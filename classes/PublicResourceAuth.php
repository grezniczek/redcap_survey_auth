<?php namespace DE\RUB\SurveyAuthExternalModule;

/** Session authorization for public dashboards and reports. */
trait PublicResourceAuth
{
    private function publicResource($projectId, string $type, $hash): array
    {
        if (!in_array($type, ['dashboard', 'report'], true) || !is_string($hash)) throw new \RuntimeException('Invalid resource.');
        $table = $type === 'dashboard' ? 'redcap_project_dashboards' : 'redcap_reports';
        $column = $type === 'dashboard' ? 'dash_id' : 'report_id';
        $row = db_fetch_assoc($this->framework->query(
            "SELECT $column AS id, title FROM $table WHERE project_id=? AND hash=? AND is_public=1",
            [$projectId, $hash]));
        if (!$row) throw new \RuntimeException('Resource is no longer public.');
        return ['project_id'=>(string)$projectId, 'type'=>$type, 'id'=>(string)$row['id'],
            'hash'=>$hash, 'title'=>$row['title'], 'endpoint'=>$this->get_endpoint()[1]];
    }

    private function publicResourceKey(array $resource): string
    {
        return 'public:'.hash('sha256', json_encode(array_intersect_key($resource,
            array_flip(['project_id', 'type', 'id', 'hash', 'endpoint']))));
    }

    private function loadPublicResourcePolicy(array $resource): array
    {
        $dashboard = $resource['type'] === 'dashboard';
        $this->settings = new SurveyAuthSettings($this, $resource['project_id'],
            $dashboard ? $resource['id'] : 0, $dashboard ? 0 : $resource['id']);
        $prefix = $dashboard ? 'dash_' : 'report_';
        [$options, $endpoint] = $this->get_endpoint();
        $deny = $options && $endpoint === 'external' && $this->settings->{$prefix.'denyexternal'};
        $protect = $this->settings->{$prefix.'protected'} &&
            in_array($this->settings->{$prefix.'endpoint'}, ['both', $endpoint], true);
        $policy = get_object_vars($this->settings);
        unset($policy['lockoutStatus'], $policy['blobSecret'], $policy['blobHmac']);
        return ['deny'=>$deny, 'protect'=>$protect, 'message'=>$this->settings->{$prefix.'noaccessmsg'},
            'revision'=>hash('sha256', json_encode($policy))];
    }

    private function protectPublicResource($projectId, string $type): void
    {
        try {
            $resource = $this->publicResource($projectId, $type, $_GET['__'.$type] ?? null);
            $policy = $this->loadPublicResourcePolicy($resource);
            if ($policy['deny']) {
                http_response_code(403);
                print $policy['message'];
                $this->exitAfterHook();
                return;
            }
            if (!$policy['protect']) return;
            if (!$this->surveySessionReady()) throw new \RuntimeException('Missing session.');
            header('Cache-Control: no-store');
            header('Referrer-Policy: no-referrer');
            $state =& $this->surveySession();
            $key = $this->publicResourceKey($resource);
            $grant = $state['grants'][$key] ?? null;
            if ($grant && hash_equals($grant['revision'], $policy['revision']) && $this->surveyIdentityActive($grant)) {
                $state['grants'][$key]['last'] = time();
                return;
            }
            unset($state['grants'][$key]);
            $id = bin2hex(random_bytes(24));
            $state['logins'][$id] = ['scope'=>['project_id'=>$resource['project_id']], 'resource'=>$resource,
                'revision'=>$policy['revision'], 'csrf'=>bin2hex(random_bytes(32)), 'expires'=>time()+self::LOGIN_TTL];
            while (count($state['logins']) > 16) array_shift($state['logins']);
            if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') http_response_code(403);
            $this->renderSurveyLogin($id);
            $this->exitAfterHook();
        } catch (\Throwable $e) {
            $this->surveyStop('Resource authorization could not be checked. Please contact the project administrator.', 503);
        }
    }

    private function publicResourceLogin(string $id, array $login): void
    {
        $state =& $this->surveySession();
        $stored = $login['resource'];
        $resource = $this->publicResource($stored['project_id'], $stored['type'], $stored['hash']);
        $policy = $this->loadPublicResourcePolicy($resource);
        $username = $_POST['username'] ?? null;
        $password = $_POST['password'] ?? null;
        unset($_POST['username'], $_POST['password']);
        if ($this->publicResourceKey($stored) !== $this->publicResourceKey($resource) || $policy['deny'] ||
            !$policy['protect'] || !hash_equals($login['revision'], $policy['revision']) ||
            !is_string($username) || !is_string($password)) {
            http_response_code(403);
            print 'Login expired or invalid. Please reopen the resource.';
            return;
        }
        $result = $this->authenticatePublicDashboardOrReport($username, $password, $resource['project_id'],
            'Public '.ucfirst($resource['type']).' '.$resource['id']);
        unset($password);
        if (!$result['success']) {
            $state['logins'][$id]['csrf'] = bin2hex(random_bytes(32));
            $this->renderSurveyLogin($id, $result['error'] ?: $this->settings->failMsg);
            return;
        }
        unset($state['logins'][$id]);
        $grant = ['username'=>$username, 'method'=>$result['method'], 'revision'=>$policy['revision'],
            'issued'=>time(), 'last'=>time(), 'expires'=>time()+self::ABSOLUTE_TTL];
        if ($grant['method'] === 'Table') $grant['account_revision'] = $this->surveyAccountRevision($username);
        $state['grants'][$this->publicResourceKey($resource)] = $grant;
        while (count($state['grants']) > 32) array_shift($state['grants']);
        $destination = $this->surveyPath(APP_PATH_SURVEY_FULL).'?__'.$resource['type'].'='.rawurlencode($resource['hash']);
        header('Location: '.$destination, true, 303);
    }
}
