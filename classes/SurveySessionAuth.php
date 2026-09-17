<?php namespace DE\RUB\SurveyAuthExternalModule;

/** Survey grants and login contexts never leave the REDCap survey session. */
trait SurveySessionAuth
{
    private $authorizedSurveyRequest;
    private const SESSION_KEY = 'redcap_survey_auth_v2';
    // Invalidate grants and login contexts issued before these security rules.
    private const POLICY_VERSION = 1;
    private const LOGIN_TTL = 600;
    private const IDLE_TTL = 1800;
    private const ABSOLUTE_TTL = 28800;

    private function surveySessionReady(): bool
    {
        // Match Surveys/index.php's entry-point naming, including its root '//'.
        // Session::getCookieName(true) normalizes that root differently on master.
        $surveyPath = parse_url(APP_PATH_SURVEY_FULL, PHP_URL_PATH);
        $name = \Session::cookie_name_survey_prefix.substr(sha1(dirname(rtrim($surveyPath, '/')).'/'), 0, 7);
        \Session::init($name);
        return session_status() === PHP_SESSION_ACTIVE && session_name() === $name;
    }

    private function &surveySession(): array
    {
        if (!isset($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = ['logins' => [], 'grants' => []];
        }
        $state =& $_SESSION[self::SESSION_KEY];
        foreach ($state['logins'] as $id => $login) {
            if ($login['expires'] <= time()) unset($state['logins'][$id]);
        }
        foreach ($state['grants'] as $id => $grant) {
            if ($grant['expires'] <= time() || $grant['last'] + self::IDLE_TTL <= time()) {
                unset($state['grants'][$id]);
            }
        }
        return $state;
    }

    private function surveyScope($projectId, string $hash, $responseId = null): array
    {
        // Resolve identity from the database, never from a posted record ID.
        $q = $this->framework->query(
            'SELECT s.project_id, s.survey_id, s.form_name, s.save_and_return, p.event_id, p.participant_id, p.participant_email
             FROM redcap_surveys s JOIN redcap_surveys_participants p ON p.survey_id=s.survey_id
             WHERE s.project_id=? AND p.hash=?', [$projectId, $hash]);
        $scope = db_fetch_assoc($q);
        if (!$scope) throw new \RuntimeException('Invalid survey context.');
        $scope['hash'] = $hash;
        $scope['record'] = null;
        $scope['response_id'] = null;
        $scope['instance'] = 1;
        $scope['first_submit_time'] = null;
        if ($scope['participant_email'] !== null || $responseId !== null) {
            $q = $this->framework->query(
                'SELECT record, response_id, instance, first_submit_time FROM redcap_surveys_response WHERE participant_id=?'.
                ($responseId !== null ? ' AND response_id=?' : ''),
                $responseId !== null ? [$scope['participant_id'], $responseId] : [$scope['participant_id']]);
            $response = db_fetch_assoc($q);
            if ($response) {
                $scope['record'] = (string)$response['record'];
                $scope['response_id'] = $response['response_id'];
                $scope['instance'] = (int)$response['instance'];
                $scope['first_submit_time'] = $response['first_submit_time'];
            } elseif ($responseId !== null) {
                throw new \RuntimeException('Invalid response context.');
            }
        }
        return $scope;
    }

    private function surveyScopeKey(array $scope, string $flow = ''): string
    {
        return hash('sha256', json_encode([
            (string)$scope['project_id'], (string)$scope['survey_id'], (string)$scope['event_id'],
            $scope['record'], (int)$scope['instance'],
            $scope['record'] === null ? [$scope['hash'], $flow] : null
        ]));
    }

    private function surveyReturnKey(array $scope): string
    {
        // Separate namespace: a return-entry grant can never authorize answers.
        return 'return:'.$this->surveyScopeKey($scope);
    }

    private function surveyReturnScope(array $source, $code): ?array
    {
        if (!is_string($code) || trim($code) === '' || strlen($code) > 15) return null;
        // REDCap displays codes in uppercase even when stored in lowercase.
        // This normalization is specific to return codes, not login passwords.
        $q = $this->framework->query(
            'SELECT p.hash, r.response_id FROM redcap_surveys_response r
             JOIN redcap_surveys_participants p ON p.participant_id=r.participant_id
             WHERE p.survey_id=? AND p.event_id=? AND UPPER(r.return_code)=?'.
            ($source['record'] !== null ? ' AND p.participant_id=?' : '').' LIMIT 2',
            $source['record'] !== null
                ? [$source['survey_id'], $source['event_id'], strtoupper(trim($code)), $source['participant_id']]
                : [$source['survey_id'], $source['event_id'], strtoupper(trim($code))]);
        $row = db_fetch_assoc($q);
        if (!$row || db_fetch_assoc($q)) return null;
        return $this->surveyScope($source['project_id'], $row['hash'], $row['response_id']);
    }

    private function surveyPolicyRevision(array $scope): string
    {
        $policy = get_object_vars($this->settings);
        // Failure counters change on every failed login and are not policy.
        unset($policy['lockoutStatus'], $policy['blobSecret'], $policy['blobHmac']);
        $dictionary = \REDCap::getDataDictionary($scope['project_id'], 'json', true, null, $scope['form_name'], false);
        return hash('sha256', self::POLICY_VERSION.':'.json_encode($policy).$dictionary);
    }

    private function surveyPath(string $url): string
    {
        // The configured path is used on the participant's current origin.
        $parts = parse_url($url);
        $path = $parts['path'] ?? '';
        if ($path === '' || $path[0] !== '/' || str_starts_with($path, '//') || preg_match('/[\\\\\r\n]/', $path)) {
            throw new \RuntimeException('Invalid survey destination.');
        }
        return $path.(isset($parts['query']) ? '?'.$parts['query'] : '');
    }

    private function surveyStop(string $message, int $status = 403, ?string $continueUrl = null): void
    {
        http_response_code($status);
        header('Cache-Control: no-store');
        print htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
        if ($continueUrl !== null) {
            print '<p><a href="'.htmlspecialchars($this->surveyPath($continueUrl), ENT_QUOTES, 'UTF-8').'">Continue this response</a></p>';
        }
        $this->exitAfterHook();
    }

    private function protectSurveyBeforeProcessing($projectId): void
    {
        if (!$projectId || !isset($_GET['s'])) return;
        try {
            if (!is_string($_GET['s']) || !$this->surveySessionReady()) {
                $this->surveyStop('A survey session is required. Please enable cookies.');
                return;
            }
            $source = $this->surveyScope($projectId, $_GET['s']);
            $scope = $source;
            $returnEntry = isset($_GET['__return']) && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET';
            $returnCode = isset($_POST['__code']);
            $validReturnCode = false;
            if ($returnCode) {
                $resolved = $this->surveyReturnScope($source, $_POST['__code']);
                if ($resolved) {
                    $scope = $resolved;
                    $validReturnCode = true;
                }
            } elseif (!empty($_POST['__response_hash__'])) {
                $postedHash = $_POST['__response_hash__'];
                if (!is_string($postedHash)) throw new \RuntimeException('Invalid response hash.');
                $responseId = \Survey::decryptResponseHash($postedHash, $source['participant_id']);
                if (!$responseId) throw new \RuntimeException('Invalid response hash.');
                $scope = $this->surveyScope($projectId, $source['hash'], $responseId);
                if ($source['record'] !== null && $this->surveyScopeKey($source) !== $this->surveyScopeKey($scope)) {
                    throw new \RuntimeException('Mismatched response.');
                }
            }
            $startOver = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_GET['__startover'], $_POST['__response_hash__']);
            if ($startOver) {
                if ($returnCode || !is_string($_POST['__response_hash__']) || $_POST['__response_hash__'] === '' ||
                    $scope['record'] === null || !$scope['response_id'] || isset($_POST['submit-action']) || !empty($_FILES)) {
                    $this->surveyStop('Invalid Start over request.', 400);
                    return;
                }
                // Core accepts a posted ID here; bind it to the validated response hash.
                $_POST['__response_id__'] = $scope['response_id'];
            }
            $this->settings = new SurveyAuthSettings($this, $projectId);
            $dictionary = json_decode(\REDCap::getDataDictionary($projectId, 'json', true, null, $scope['form_name'], false));
            if ($scope['record'] !== null) $GLOBALS['hidden_edit'] = 1;
            if (!$this->getTaggedFields($dictionary, $projectId, $scope['record'], $scope['event_id'], $scope['form_name'], $scope['instance'])) return;

            if (($returnCode || $returnEntry) && !$scope['save_and_return']) {
                $this->surveyStop('Save & Return is not enabled for this survey.');
                return;
            }

            if ($returnCode && (!$validReturnCode || isset($_POST['submit-action']) || !empty($_FILES))) {
                $this->surveyStop('Invalid return code or return request. Please go back and try again.');
                return;
            }
            $newRepeat = isset($_GET['new']) || isset($_POST['__sa_new']);
            if ($newRepeat) {
                $project = new \Project($projectId);
                if ($scope['record'] === null || !$project->isRepeatingFormOrEvent($scope['event_id'], $scope['form_name']) ||
                    $scope['first_submit_time'] !== null) {
                    $this->surveyStop('This repeat instance has already been started or is unavailable. Your submission was not saved.', 409,
                        $this->surveyPath(APP_PATH_SURVEY_FULL).'?s='.rawurlencode($scope['hash']));
                    return;
                }
                // Do not let core retarget a stale first-page submission to another
                // instance after this authorization decision. This request is exact.
                unset($_GET['new']);
            }
            // Core also resolves repeating instances from the private participant.
            if (!$this->isSurveyFileRequest()) $_GET['instance'] = $scope['instance'];
            if ($returnCode) {
                // A code request is navigation only; never let injected answers or
                // other routing flags turn it into a submission or results request.
                $_POST = ['__code' => trim($_POST['__code'])];
                $_GET = ['pid' => $projectId, 's' => $source['hash'], 'instance' => $scope['instance']];
            } elseif ($returnEntry) {
                $_GET = ['pid' => $projectId, 's' => $source['hash'], '__return' => '1', 'instance' => $scope['instance']];
            }

            $flow = $_POST['__sa_flow'] ?? $_GET['__sa_flow'] ?? '';
            if (!is_string($flow)) $flow = '';
            $state =& $this->surveySession();
            $purpose = $returnEntry && $scope['record'] === null ? 'return' : 'survey';
            $key = $purpose === 'return' ? $this->surveyReturnKey($scope) : $this->surveyScopeKey($scope, $flow);
            $grant = $state['grants'][$key] ?? null;
            $revision = $this->surveyPolicyRevision($scope);
            if (!$grant && !$returnCode && !$returnEntry) {
                $fileKey = $this->publicSurveyFileGrantKey($scope, $state['grants'], $revision);
                if ($fileKey !== null) {
                    $key = $fileKey;
                    $grant = $state['grants'][$key];
                }
            }
            if (!$grant && $returnCode && $validReturnCode) {
                $returnKey = $this->surveyReturnKey($source);
                $entryGrant = $state['grants'][$returnKey] ?? null;
                if ($entryGrant && isset($entryGrant['identity']) && hash_equals($entryGrant['revision'], $revision) && $this->surveyIdentityActive($entryGrant)) {
                    $result = $this->completeSurveyAuthentication(
                        array_merge($entryGrant['identity'], ['success' => true, 'error' => null, 'log_error' => []]),
                        $projectId, $scope['form_name'], $scope['event_id'], $scope['instance'], $scope['record']);
                    if (!$result['success']) {
                        $this->surveyStop('Authentication metadata could not be saved. Please try again.', 503);
                        return;
                    }
                    $grant = $entryGrant;
                    unset($grant['purpose'], $grant['identity']);
                    $grant['authentication_values'] = $result['authentication_values'] ?? [];
                    $grant['expires'] = $grant['issued'] + self::ABSOLUTE_TTL;
                    $state['grants'][$key] = $grant;
                    unset($state['grants'][$returnKey]);
                }
            }
            $metadataRequiresLogin = $this->settings->canwrite && $grant &&
                !is_array($grant['authentication_values'] ?? null) && ($grant['purpose'] ?? '') !== 'return';
            if ($grant && !$metadataRequiresLogin && hash_equals($grant['revision'], $revision) && $this->surveyIdentityActive($grant)) {
                $this->protectAuthenticationFields($grant);
                $state['grants'][$key]['last'] = time();
                if ($returnCode && $scope['hash'] !== $source['hash']) {
                    // Re-enter core with the participant that owns this code. Core's
                    // fallback can otherwise render a private form with a public
                    // participant's response hash. 307 retains the code in POST only.
                    header('Location: '.$this->surveyPath(APP_PATH_SURVEY_FULL).'?s='.rawurlencode($scope['hash']), true, 307);
                    $this->exitAfterHook();
                    return;
                }
                $this->authorizedSurveyRequest = ['scope' => $scope, 'key' => $key, 'flow' => $flow, 'grant' => $state['grants'][$key], 'new' => $newRepeat, 'startover' => $startOver];
                return;
            }
            unset($state['grants'][$key]);
            $id = bin2hex(random_bytes(24));
            // Only navigation is retained. Never store credentials, answers, or uploads.
            $destination = $this->surveyPath(APP_PATH_SURVEY_FULL).'?s='.rawurlencode($scope['hash']);
            $state['logins'][$id] = ['scope' => $scope, 'destination' => $destination,
                'revision' => $revision, 'purpose' => $purpose, 'return' => $returnEntry || $returnCode, 'new' => $newRepeat,
                'expires' => time() + self::LOGIN_TTL, 'csrf' => bin2hex(random_bytes(32))];
            while (count($state['logins']) > 16) array_shift($state['logins']);
            if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
                http_response_code(403);
                $this->renderSurveyLogin($id, '', $metadataRequiresLogin && isset($_GET['__startover'])
                    ? 'login.start_over' : 'login.unsaved_submission');
            } else {
                $this->renderSurveyLogin($id);
            }
            $this->exitAfterHook();
        } catch (\Throwable $e) {
            $this->surveyStop('Survey authorization could not be checked. Please contact the survey administrator.', 503);
        }
    }

    private function isSurveyFileRequest(): bool
    {
        $route = $_GET['__passthru'] ?? (defined('PAGE') ? PAGE : '');
        return is_string($route) && in_array(urldecode($route), [
            'DataEntry/file_upload.php', 'DataEntry/file_download.php',
            'DataEntry/file_delete.php', 'DataEntry/image_view.php',
            'Design/file_attachment_upload.php'
        ], true);
    }

    private function publicSurveyFileGrantKey(array $scope, array $grants, string $revision): ?string
    {
        if ($scope['record'] !== null || !$this->isSurveyFileRequest()) return null;
        // Native file URLs omit our tab's flow ID. For files only, accept a live
        // public-start grant for this exact survey/hash in the same session.
        $resource = $this->surveyScopeKey($scope);
        foreach ($grants as $key => $grant) {
            if (($grant['public_file_scope'] ?? null) === $resource &&
                hash_equals($grant['revision'], $revision) && $this->surveyIdentityActive($grant)) return $key;
        }
        return null;
    }

    private function surveyIdentityActive(array $grant): bool
    {
        if ($this->settings->useWhitelist && !in_array(strtolower($grant['username']), $this->settings->whitelist, true)) return false;
        if ($grant['method'] === 'Table') {
            $user = \User::getUserInfo($grant['username']);
            return $user && empty($user['user_suspended_time']) &&
                hash_equals($grant['account_revision'], $this->surveyAccountRevision($grant['username']));
        }
        return true;
    }

    private function surveyAccountRevision(string $username): string
    {
        $q = $this->framework->query('SELECT password, password_salt FROM redcap_auth WHERE username=?', [$username]);
        return hash('sha256', json_encode(db_fetch_assoc($q)));
    }

    private function renderSurveyLogin(string $id, string $error = '', string $errorKey = ''): void
    {
        $state =& $this->surveySession();
        $login = $state['logins'][$id];
        $escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
        // Resolve branding from the stored login scope, including on the EM endpoint.
        $loginHeading = isset($login['resource']) ? ucfirst($login['resource']['type']).' login' : 'Survey login';
        $branding = isset($login['resource']) ? ['title' => $login['resource']['title']] : (db_fetch_assoc($this->framework->query(
            'SELECT s.title, s.hide_title, e.doc_id FROM redcap_surveys s
             LEFT JOIN redcap_edocs_metadata e ON e.doc_id=s.logo AND e.project_id=s.project_id AND e.delete_date IS NULL
             WHERE s.project_id=? AND s.survey_id=?',
            [$login['scope']['project_id'], $login['scope']['survey_id']])) ?: []);
        $surveyTitle = empty($branding['hide_title']) ? strip_tags($branding['title'] ?? '') : '';
        $logoSource = '';
        if (!empty($branding['doc_id'])) {
            // Embed only the configured logo. No unauthenticated attachment route is needed.
            $file = \REDCap::getFile($branding['doc_id']);
            $image = $file ? @getimagesizefromstring($file[2]) : false;
            if ($image && in_array($image['mime'], ['image/jpeg', 'image/png', 'image/gif', 'image/bmp'], true)) {
                $logoSource = 'data:'.$image['mime'].';base64,'.base64_encode($file[2]);
            }
        }
        $csrf = $escape($login['csrf']);
        $mlmPresentation = isset($login['resource']) ? null : $this->surveyMlmLoginPresentation($login['scope'], $this->settings, $surveyTitle);
        $strings = $mlmPresentation['strings'] ?? [];
        if ($mlmPresentation !== null) {
            $loginHeading = $strings['login.heading'] ?? $loginHeading;
            $error = $errorKey !== '' ? ($strings[$errorKey] ?? $error) : $error;
            $surveyTitle = $mlmPresentation['languages'][$mlmPresentation['current']]['survey_title'] ?? $surveyTitle;
        }
        $surveyTitle = $escape($surveyTitle);
        $instructions = $strings['login.instructions'] ?? $this->settings->text;
        $usernameLabel = $strings['login.username_label'] ?? $this->settings->usernameLabel;
        $passwordLabel = $strings['login.password_label'] ?? $this->settings->passwordLabel;
        $submitLabel = $strings['login.submit_label'] ?? $this->settings->submitLabel;
        $languageLabel = $strings['login.language_label'] ?? 'Language';
        $logoAlt = $strings['login.logo_alt'] ?? 'Survey logo';
        $noJavascript = $strings['login.javascript_required'] ?? 'JavaScript is required to sign in. Please enable JavaScript and reopen this page.';
        $htmlLang = $mlmPresentation['html_lang'] ?? 'en';
        $rtl = !empty($mlmPresentation['rtl']);
        $mlmCatalogue = $mlmPresentation === null ? null : [
            'current' => $mlmPresentation['current'],
            'languages' => $mlmPresentation['languages'],
        ];
        $mlmCatalogueJson = json_encode($mlmCatalogue,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($mlmCatalogueJson === false) $mlmCatalogueJson = 'null';
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        ob_start();
        try {
            $this->framework->initializeJavascriptModuleObject();
            $moduleJavascript = ob_get_contents();
        } finally {
            ob_end_clean();
        }
        $jsObject = $this->framework->getJavascriptModuleObjectName();
        $state['logins'][$id]['framework_csrf'] = $this->framework->getCSRFToken();
        require __DIR__.'/../html/session-login.php';
    }

    private function useSessionBoundLoginCsrf(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || ($_POST['action'] ?? null) !== 'survey-login' ||
            !is_string($_POST['payload'] ?? null) || !$this->surveySessionReady()) return;
        $payload = json_decode($_POST['payload'], true);
        if (!is_array($payload) || !is_string($payload['context'] ?? null) || !is_string($payload['csrf'] ?? null) ||
            !is_string($_POST['redcap_external_module_csrf_token'] ?? null)) return;
        $state =& $this->surveySession();
        $login = $state['logins'][$payload['context']] ?? null;
        $token = $_POST['redcap_external_module_csrf_token'];
        if (!$login || !is_string($login['framework_csrf'] ?? null) ||
            !hash_equals($login['csrf'], $payload['csrf']) || !hash_equals($login['framework_csrf'], $token)) return;
        // Framework NOAUTH CSRF uses a browser-wide cookie rotated by other tabs.
        // Accept this tab's token only after checking both tokens against its live
        // server-side session context. Change only the request-local cookie view;
        // framework token and signed-verification checks still run normally.
        $_COOKIE['redcap_external_module_csrf_token'] = $token;
    }

    private function surveyLoginAjax($payload, $project_id): array
    {
        header('Cache-Control: no-store');
        if (!is_array($payload) || $project_id === null ||
            (string)$project_id !== (string)$this->framework->getProjectId()) {
            return ['success'=>false, 'error'=>'Login expired or invalid. Please reopen the resource.', 'error_key'=>'login.expired'];
        }
        try {
            return $this->processSurveyLogin($payload);
        } catch (\Throwable $e) {
            // Do not expose backend exceptions (or their credential arguments) to AJAX logs.
            return ['success'=>false, 'error'=>'Login could not be completed. Please contact the administrator.', 'error_key'=>'login.ajax_error'];
        }
    }

    // Compatibility for forms opened before the switch to the survey AJAX endpoint.
    public function surveyLogin(): void
    {
        $payload = $_POST;
        unset($_POST['username'], $_POST['password']);
        $result = $this->processSurveyLogin($payload);
        if ($result['success']) {
            header('Location: '.$result['redirect'], true, 303);
        } elseif (isset($result['csrf'])) {
            $this->renderSurveyLogin($payload['context'], $result['error'], $result['error_key'] ?? '');
        } else {
            http_response_code(403);
            print htmlspecialchars($result['error'], ENT_QUOTES, 'UTF-8');
        }
    }

    private function processSurveyLogin(array $payload): array
    {
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        if (!$this->surveySessionReady()) {
            return ['success'=>false, 'error'=>'A survey session is required. Please enable cookies.', 'error_key'=>'login.cookie_required'];
        }
        $id = $payload['context'] ?? '';
        $csrf = $payload['csrf'] ?? '';
        $state =& $this->surveySession();
        $login = is_string($id) ? ($state['logins'][$id] ?? null) : null;
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$login || !is_string($csrf) ||
            !hash_equals($login['csrf'], $csrf) || (string)$login['scope']['project_id'] !== (string)$this->framework->getProjectId()) {
            return ['success'=>false, 'error'=>'Login expired or invalid. Please reopen the survey.', 'error_key'=>'login.expired'];
        }
        if (isset($login['resource'])) {
            return $this->publicResourceLogin($id, $login, $payload['username'] ?? null, $payload['password'] ?? null);
        }
        $scope = $login['scope'];
        $this->settings = new SurveyAuthSettings($this, $scope['project_id']);
        $username = $payload['username'] ?? null;
        $password = $payload['password'] ?? null;
        unset($payload['username'], $payload['password']);
        $currentScope = $this->surveyScope($scope['project_id'], $scope['hash'], $scope['response_id']);
        if (!is_string($username) || !is_string($password) ||
            $this->surveyScopeKey($currentScope, $id) !== $this->surveyScopeKey($scope, $id) ||
            !hash_equals($login['revision'], $this->surveyPolicyRevision($scope))) {
            return ['success'=>false, 'error'=>'Login expired or invalid. Please reopen the survey.', 'error_key'=>'login.expired'];
        }
        if ($scope['record'] !== null) $GLOBALS['hidden_edit'] = 1;
        $result = $this->authenticate($username, $password, $scope['project_id'], $scope['form_name'], $scope['event_id'], $scope['instance'], $scope['record'], ($login['purpose'] ?? 'survey') !== 'return');
        unset($password);
        if (!$result['success']) {
            // Refresh session CSRF after each credential attempt.
            $state['logins'][$id]['csrf'] = bin2hex(random_bytes(32));
            $error = $result['error'] ?: $this->settings->failMsg;
            return ['success'=>false, 'error'=>$error, 'error_key'=>$this->surveyMlmErrorKey($error, $this->settings),
                'csrf'=>$state['logins'][$id]['csrf']];
        }
        $this->rotateSurveySession();
        unset($state['logins'][$id]);
        $scope['record'] = $result['record'] === null ? null : (string)$result['record'];
        $grant = ['username' => $username, 'method' => $result['method'], 'revision' => $login['revision'],
            'issued' => time(), 'last' => time(), 'expires' => time() + self::ABSOLUTE_TTL,
            'authentication_values' => $result['authentication_values'] ?? []];
        if ($grant['method'] === 'Table') $grant['account_revision'] = $this->surveyAccountRevision($username);
        $returnOnly = ($login['purpose'] ?? 'survey') === 'return';
        if ($returnOnly) {
            $grant['purpose'] = 'return';
            $grant['expires'] = time() + self::LOGIN_TTL;
            $grant['identity'] = array_intersect_key($result, array_flip(['username', 'email', 'fullname', 'method']));
        }
        if (!$returnOnly && $scope['record'] === null) $grant['public_file_scope'] = $this->surveyScopeKey($scope);
        $state['grants'][$returnOnly ? $this->surveyReturnKey($scope) : $this->surveyScopeKey($scope, $id)] = $grant;
        while (count($state['grants']) > 32) array_shift($state['grants']);
        $destination = $scope['record'] === null ? $login['destination'].'&__sa_flow='.$id : $this->surveyPath($result['targetUrl']);
        if ($returnOnly) $destination = $login['destination'];
        if (!empty($login['return'])) $destination .= '&__return=1';
        if (!empty($login['new'])) $destination .= '&new';
        return ['success'=>true, 'redirect'=>$destination];
    }

    private function rotateSurveySession(): void
    {
        $previous = session_id();
        if (session_status() !== PHP_SESSION_ACTIVE || $previous === '' ||
            !session_regenerate_id(true) || session_id() === $previous) {
            throw new \RuntimeException('Could not renew the survey session.');
        }
    }

    private function protectAuthenticationFields(array $grant): void
    {
        if (!$this->settings->canwrite) return;
        $fields = $grant['authentication_values'] ?? [];
        // These values are already persisted at login. Do not re-inject them:
        // core would reinterpret date formats and checkbox values as form input.
        // Strip both native form names and prefill/alternate field encodings.
        foreach (['_POST', '_GET', '_FILES'] as $source) {
            foreach (array_keys($GLOBALS[$source] ?? []) as $key) {
                if ($source === '_GET' && in_array($key,
                    ['s', 'hash', 'page', 'event_id', 'pid', 'pnid', 'preview', 'id', 'sq', 'instance'], true)) continue;
                $field = preg_replace('/^__chk(?:n)?__/', '', (string)$key);
                $field = explode('_RC_', $field, 2)[0];
                $field = explode('___', $field, 2)[0];
                if (array_key_exists($field, $fields)) unset($GLOBALS[$source][$key]);
            }
        }
        // Core expands this list into blank field values during required checks.
        if (is_array($_POST['empty-required-field'] ?? null)) {
            $_POST['empty-required-field'] = array_values(array_filter($_POST['empty-required-field'],
                static fn($field) => is_string($field) && !array_key_exists($field, $fields)));
        }
    }

    private function restoreAuthenticationAfterStartOver($projectId, $record, $instrument, $eventId,
        $hash, $responseId, $instance): bool
    {
        $request = $this->authorizedSurveyRequest;
        if (!$request || empty($request['startover']) || !$this->settings->canwrite) return false;
        $scope = $request['scope'];
        if ($scope['record'] === null || (string)$projectId !== (string)$scope['project_id'] ||
            (string)$record !== $scope['record'] || $instrument !== $scope['form_name'] ||
            (string)$eventId !== (string)$scope['event_id'] || $hash !== $scope['hash'] ||
            (string)$responseId !== (string)$scope['response_id'] || (int)$instance !== (int)$scope['instance']) return false;
        $values = $request['grant']['authentication_values'] ?? [];
        if (!$values) return false;
        try {
            // Core clears the response before page_top, but has already built its
            // form data. Reload after restoration to avoid rendering stale blanks.
            $current = $this->surveyScope($projectId, $hash, $responseId);
            if ($current['first_submit_time'] !== null || $this->surveyScopeKey($current) !== $this->surveyScopeKey($scope)) {
                throw new \RuntimeException('Survey reset could not be confirmed.');
            }
            $result = $this->saveSurveyAuthenticationValues($values, $projectId, $instrument, $eventId, $instance, $record);
            if (!is_array($result) || !empty($result['errors'])) throw new \RuntimeException('Metadata restoration failed.');
            $this->framework->redirectAfterHook($this->surveyPath(APP_PATH_SURVEY_FULL).'?s='.rawurlencode($hash), true);
        } catch (\Throwable $e) {
            $state =& $this->surveySession();
            unset($state['grants'][$request['key']]);
            $this->surveyStop('The survey was reset, but authentication values could not be restored. Please reopen the survey and sign in again.', 503);
        }
        return true;
    }

    public function redcap_save_record($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance = 1)
    {
        $request = $this->authorizedSurveyRequest;
        if (!$request || !$response_id) return;
        $scope = $request['scope'];
        if ((string)$project_id !== (string)$scope['project_id'] || $instrument !== $scope['form_name'] ||
            (string)$event_id !== (string)$scope['event_id'] || (int)$repeat_instance !== (int)$scope['instance'] ||
            $survey_hash !== $scope['hash'] || ($scope['record'] !== null && (string)$record !== $scope['record'])) return;
        $this->authorizedSurveyRequest['new'] = false;
        $scope['record'] = (string)$record;
        $scope['response_id'] = $response_id;
        $state =& $this->surveySession();
        $grant = $request['grant'];
        unset($grant['public_file_scope']);
        $state['grants'][$this->surveyScopeKey($scope)] = $grant;
        if ($request['scope']['record'] === null) unset($state['grants'][$request['key']]);
    }

    public function redcap_survey_complete($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance = 1)
    {
        $request = $this->authorizedSurveyRequest;
        if (!$request || (string)$project_id !== (string)$request['scope']['project_id'] ||
            $instrument !== $request['scope']['form_name'] ||
            (string)$event_id !== (string)$request['scope']['event_id'] ||
            (int)$repeat_instance !== (int)$request['scope']['instance'] ||
            $survey_hash !== $request['scope']['hash'] ||
            ($request['scope']['record'] !== null && (string)$record !== $request['scope']['record'])) return;
        $scope = $request['scope'];
        $scope['record'] = (string)$record;
        $state =& $this->surveySession();
        unset($state['grants'][$request['key']], $state['grants'][$this->surveyScopeKey($scope)]);
    }
}
