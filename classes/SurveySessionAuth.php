<?php namespace DE\RUB\SurveyAuthExternalModule;

/** Survey grants and login contexts never leave the REDCap survey session. */
trait SurveySessionAuth
{
    private $authorizedSurveyRequest;
    private const SESSION_KEY = 'redcap_survey_auth_v2';
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
        return hash('sha256', json_encode($policy).$dictionary);
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

    private function surveyLoginUrl(): string
    {
        return $this->surveyPath($this->framework->getUrl('survey-login.php', true));
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
                    $grant['expires'] = $grant['issued'] + self::ABSOLUTE_TTL;
                    $state['grants'][$key] = $grant;
                    unset($state['grants'][$returnKey]);
                }
            }
            if ($grant && hash_equals($grant['revision'], $revision) && $this->surveyIdentityActive($grant)) {
                $state['grants'][$key]['last'] = time();
                if ($returnCode && $scope['hash'] !== $source['hash']) {
                    // Re-enter core with the participant that owns this code. Core's
                    // fallback can otherwise render a private form with a public
                    // participant's response hash. 307 retains the code in POST only.
                    header('Location: '.$this->surveyPath(APP_PATH_SURVEY_FULL).'?s='.rawurlencode($scope['hash']), true, 307);
                    $this->exitAfterHook();
                    return;
                }
                $this->authorizedSurveyRequest = ['scope' => $scope, 'key' => $key, 'flow' => $flow, 'grant' => $state['grants'][$key], 'new' => $newRepeat];
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
                $this->renderSurveyLogin($id, 'Your submission was not saved. Sign in to reopen the survey. Unsaved answers are not restored automatically; use your browser Back button to recover them if available. Uploaded files may need to be selected again.');
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

    private function renderSurveyLogin(string $id, string $error = ''): void
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
        $surveyTitle = empty($branding['hide_title']) ? $escape(strip_tags($branding['title'] ?? '')) : '';
        $logoSource = '';
        if (!empty($branding['doc_id'])) {
            // Embed only the configured logo. No unauthenticated attachment route is needed.
            $file = \REDCap::getFile($branding['doc_id']);
            $image = $file ? @getimagesizefromstring($file[2]) : false;
            if ($image && in_array($image['mime'], ['image/jpeg', 'image/png', 'image/gif', 'image/bmp'], true)) {
                $logoSource = 'data:'.$image['mime'].';base64,'.base64_encode($file[2]);
            }
        }
        $action = $escape($this->surveyLoginUrl());
        // Keep the framework's CSRF protection, in addition to session-bound CSRF.
        // Reuse a valid framework cookie so opening another login tab does not
        // invalidate the first tab's double-submit token. Session CSRF is separate.
        $cookie = $_COOKIE['redcap_external_module_csrf_token'] ?? '';
        $frameworkCsrf = $escape(is_string($cookie) && preg_match('/\A[a-f0-9]{80}\z/', $cookie)
            ? $cookie : $this->framework->getCSRFToken());
        $csrf = $escape($login['csrf']);
        $instructions = $this->settings->text;
        $usernameLabel = $escape($this->settings->usernameLabel);
        $passwordLabel = $escape($this->settings->passwordLabel);
        $submitLabel = $escape($this->settings->submitLabel);
        $error = $escape($error);
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        require __DIR__.'/../html/session-login.php';
    }

    public function surveyLogin(): void
    {
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        if (!$this->surveySessionReady()) {
            http_response_code(403);
            print 'A survey session is required. Please enable cookies.';
            return;
        }
        $id = $_POST['context'] ?? '';
        $csrf = $_POST['csrf'] ?? '';
        $state =& $this->surveySession();
        $login = is_string($id) ? ($state['logins'][$id] ?? null) : null;
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$login || !is_string($csrf) ||
            !hash_equals($login['csrf'], $csrf) || (string)$login['scope']['project_id'] !== (string)$this->framework->getProjectId()) {
            http_response_code(403);
            print 'Login expired or invalid. Please reopen the survey.';
            return;
        }
        if (isset($login['resource'])) {
            $this->publicResourceLogin($id, $login);
            return;
        }
        $scope = $login['scope'];
        $this->settings = new SurveyAuthSettings($this, $scope['project_id']);
        $username = $_POST['username'] ?? null;
        $password = $_POST['password'] ?? null;
        unset($_POST['username'], $_POST['password']);
        $currentScope = $this->surveyScope($scope['project_id'], $scope['hash'], $scope['response_id']);
        if (!is_string($username) || !is_string($password) ||
            $this->surveyScopeKey($currentScope, $id) !== $this->surveyScopeKey($scope, $id) ||
            !hash_equals($login['revision'], $this->surveyPolicyRevision($scope))) {
            http_response_code(403);
            print 'Login expired or invalid. Please reopen the survey.';
            return;
        }
        if ($scope['record'] !== null) $GLOBALS['hidden_edit'] = 1;
        $result = $this->authenticate($username, $password, $scope['project_id'], $scope['form_name'], $scope['event_id'], $scope['instance'], $scope['record'], ($login['purpose'] ?? 'survey') !== 'return');
        unset($password);
        if (!$result['success']) {
            // Refresh session CSRF after each credential attempt.
            $state['logins'][$id]['csrf'] = bin2hex(random_bytes(32));
            $this->renderSurveyLogin($id, $result['error'] ?: $this->settings->failMsg);
            return;
        }
        unset($state['logins'][$id]);
        $scope['record'] = $result['record'] === null ? null : (string)$result['record'];
        $grant = ['username' => $username, 'method' => $result['method'], 'revision' => $login['revision'],
            'issued' => time(), 'last' => time(), 'expires' => time() + self::ABSOLUTE_TTL];
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
        header('Location: '.$destination, true, 303);
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
