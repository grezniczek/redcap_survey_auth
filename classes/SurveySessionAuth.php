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

    private function surveyScope($projectId, string $hash): array
    {
        // Resolve identity from the database, never from a posted record ID.
        $q = $this->framework->query(
            'SELECT s.project_id, s.survey_id, s.form_name, p.event_id, p.participant_id, p.participant_email
             FROM redcap_surveys s JOIN redcap_surveys_participants p ON p.survey_id=s.survey_id
             WHERE s.project_id=? AND p.hash=?', [$projectId, $hash]);
        $scope = db_fetch_assoc($q);
        if (!$scope) throw new \RuntimeException('Invalid survey context.');
        $scope['hash'] = $hash;
        $scope['record'] = null;
        $scope['response_id'] = null;
        $scope['instance'] = 1;
        if ($scope['participant_email'] !== null) {
            $q = $this->framework->query(
                'SELECT record, response_id, instance FROM redcap_surveys_response WHERE participant_id=?',
                [$scope['participant_id']]);
            $response = db_fetch_assoc($q);
            if ($response) {
                $scope['record'] = (string)$response['record'];
                $scope['response_id'] = $response['response_id'];
                $scope['instance'] = (int)$response['instance'];
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

    private function surveyStop(string $message, int $status = 403): void
    {
        http_response_code($status);
        header('Cache-Control: no-store');
        print htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
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
            $scope = $this->surveyScope($projectId, $_GET['s']);
            $this->settings = new SurveyAuthSettings($this, $projectId);
            $dictionary = json_decode(\REDCap::getDataDictionary($projectId, 'json', true, null, $scope['form_name'], false));
            if ($scope['record'] !== null) $GLOBALS['hidden_edit'] = 1;
            if (!$this->getTaggedFields($dictionary, $projectId, $scope['record'], $scope['event_id'], $scope['form_name'], $scope['instance'])) return;

            // These core routes can change response/instance after the early hook.
            // Keep them closed until their scope transition is implemented.
            if (isset($_GET['new']) || isset($_POST['__code']) || isset($_GET['__return']) ||
                (isset($_GET['instance']) && (int)$_GET['instance'] !== $scope['instance'])) {
                $this->surveyStop('This survey return or repeat flow is not yet supported by Survey Auth. Please contact the survey administrator.');
                return;
            }
            if (!empty($_POST['__response_hash__'])) {
                $postedHash = $_POST['__response_hash__'];
                if (!is_string($postedHash) || $scope['record'] === null ||
                    (string)\Survey::decryptResponseHash($postedHash, $scope['participant_id']) !== (string)$scope['response_id']) {
                    $this->surveyStop('The submission does not match the authorized survey response. Please reopen its private survey link.');
                    return;
                }
            }

            $flow = $_POST['__sa_flow'] ?? $_GET['__sa_flow'] ?? '';
            if (!is_string($flow)) $flow = '';
            $state =& $this->surveySession();
            $key = $this->surveyScopeKey($scope, $flow);
            $grant = $state['grants'][$key] ?? null;
            $revision = $this->surveyPolicyRevision($scope);
            if ($grant && hash_equals($grant['revision'], $revision) && $this->surveyIdentityActive($grant)) {
                $state['grants'][$key]['last'] = time();
                $this->authorizedSurveyRequest = ['scope' => $scope, 'key' => $key, 'flow' => $flow, 'grant' => $state['grants'][$key]];
                return;
            }
            unset($state['grants'][$key]);
            $id = bin2hex(random_bytes(24));
            // Only navigation is retained. Never store credentials, answers, or uploads.
            $destination = $this->surveyPath(APP_PATH_SURVEY_FULL).'?s='.rawurlencode($scope['hash']);
            $state['logins'][$id] = ['scope' => $scope, 'destination' => $destination,
                'revision' => $revision, 'expires' => time() + self::LOGIN_TTL, 'csrf' => bin2hex(random_bytes(32))];
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
        $scope = $login['scope'];
        $this->settings = new SurveyAuthSettings($this, $scope['project_id']);
        $username = $_POST['username'] ?? null;
        $password = $_POST['password'] ?? null;
        unset($_POST['username'], $_POST['password']);
        $currentScope = $this->surveyScope($scope['project_id'], $scope['hash']);
        if (!is_string($username) || !is_string($password) ||
            $this->surveyScopeKey($currentScope, $id) !== $this->surveyScopeKey($scope, $id) ||
            !hash_equals($login['revision'], $this->surveyPolicyRevision($scope))) {
            http_response_code(403);
            print 'Login expired or invalid. Please reopen the survey.';
            return;
        }
        if ($scope['record'] !== null) $GLOBALS['hidden_edit'] = 1;
        $result = $this->authenticate($username, $password, $scope['project_id'], $scope['form_name'], $scope['event_id'], $scope['instance'], $scope['record']);
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
        $state['grants'][$this->surveyScopeKey($scope, $id)] = $grant;
        while (count($state['grants']) > 32) array_shift($state['grants']);
        $destination = $scope['record'] === null ? $login['destination'].'&__sa_flow='.$id : $this->surveyPath($result['targetUrl']);
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
        $scope['record'] = (string)$record;
        $scope['response_id'] = $response_id;
        $state =& $this->surveySession();
        $state['grants'][$this->surveyScopeKey($scope)] = $request['grant'];
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
