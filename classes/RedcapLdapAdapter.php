<?php namespace DE\RUB\SurveyAuthExternalModule;

/** Runs the installed directory driver without PEAR Auth's staff-session wrapper. */
class RedcapLdapAdapter
{
    private $config;
    private $mappings;
    private $rememberSecrets;
    private $driver;
    private $attributes = [];
    private $candidateAttributes = [];
    private $hasCandidate = false;
    private $groupSearch = false;
    private $details = ['stage'=>'configuration', 'endpoint'=>null, 'warnings'=>[], 'cleanup_errors'=>[]];

    public function __construct(array $config, array $mappings, callable $rememberSecrets)
    {
        $this->config = $config;
        $this->mappings = $mappings;
        $this->rememberSecrets = $rememberSecrets;
    }

    /** Returns only mapped identity data, or null for an ordinary denial. */
    public function authenticate(string $username, string $password): ?array
    {
        // Core may strip NUL bytes before binding. Redact both forms without changing its input.
        ($this->rememberSecrets)([$username, $password, str_replace("\0", '', $password)]);
        foreach (['binddn', 'bindpw'] as $key) {
            if (is_scalar($this->config[$key] ?? null)) ($this->rememberSecrets)([(string)$this->config[$key]]);
        }
        foreach (['url', 'host'] as $key) {
            $parts = is_string($this->config[$key] ?? null) ? @parse_url($this->config[$key]) : false;
            foreach (['user', 'pass'] as $part) {
                if (isset($parts[$part])) ($this->rememberSecrets)([$parts[$part], rawurldecode($parts[$part])]);
            }
        }
        if (!extension_loaded('ldap')) throw new \RuntimeException('LDAP extension not loaded.');

        $previousHandler = set_error_handler(function ($severity, $message, $file, $line) use (&$previousHandler) {
            if (str_starts_with($message, 'ldap_')) {
                if (count($this->details['warnings']) < 20) $this->details['warnings'][] = [
                    'stage'=>$this->details['stage'], 'message'=>$message, 'file'=>$file, 'line'=>$line,
                ];
                return true;
            }
            return $previousHandler ? $previousHandler($severity, $message, $file, $line) : false;
        }, E_WARNING);
        try {
            $this->loadDriver();
            $this->driver = new \Auth_Container_LDAP($this->config);
            $this->driver->_auth_obj = $this;
            $accepted = $this->driver->fetchData($username, $password);
            if ($accepted !== true) {
                if (\PEAR::isError($accepted)) throw new \RuntimeException($accepted->getMessage(), (int)$accepted->getCode());
                $code = $this->details['ldap_errno'] ?? 0;
                if ($code !== 0 && $code !== 49) throw new \RuntimeException('REDCap LDAP operation failed.', $code);
                return null;
            }
            if (!$this->hasCandidate) throw new \RuntimeException('REDCap LDAP did not identify an authenticated candidate.');
            return $this->identity();
        } finally {
            if ($this->driver !== null) {
                $this->captureConnection();
                $this->details['configuration'] = array_intersect_key($this->driver->options, array_flip([
                    'version', 'start_tls', 'referrals', 'basedn', 'userdn', 'userscope', 'userattr',
                    'attributes', 'groupdn', 'groupscope', 'groupattr', 'memberattr', 'memberisdn', 'try_all',
                ]));
                // Older drivers do not recognize PHP LDAP connection objects during disconnect.
                if ($this->driver->conn_id !== false && $this->driver->conn_id !== null) {
                    try {
                        if (!@ldap_unbind($this->driver->conn_id)) throw new \RuntimeException('LDAP disconnect failed.');
                    } catch (\Throwable $error) {
                        $this->details['cleanup_errors'][] = ['type'=>get_class($error), 'message'=>$error->getMessage()];
                    }
                }
                $this->driver->_auth_obj = null;
                $this->driver = null;
            }
            $this->attributes = $this->candidateAttributes = [];
            restore_error_handler();
        }
    }

    private function loadDriver(): void
    {
        if (class_exists('Auth_Container_LDAP', false)) return;
        $path = APP_PATH_DOCROOT.'Libraries/PEAR/';
        $previousPath = get_include_path();
        set_include_path($path.PATH_SEPARATOR.$previousPath);
        try {
            require_once $path.'Auth.php';
            require_once $path.'Auth/Container/LDAP.php';
        } finally {
            set_include_path($previousPath);
        }
    }

    /** PEAR container callback: retain mapped attributes only, never a session or full profile. */
    public function setAuthData($name, $value, $overwrite = true): void
    {
        if (strtoupper((string)$this->driver->options['attrformat']) !== 'AUTH') {
            if ($name !== 'attributes' || !is_array($value)) return;
            $this->attributes = [];
            foreach ($value as $key=>$values) {
                if (is_string($key) && is_array($values) && array_key_exists(0, $values)) $this->retainAttribute($key, $values[0]);
            }
        } elseif ($name !== 'redcap_ldap_profile') {
            $this->retainAttribute($name, is_array($value) ? ($value[0] ?? null) : $value);
        }
    }

    private function retainAttribute($name, $value): void
    {
        if (!is_string($name) || !is_string($value)) return;
        $name = strtolower($name);
        foreach ($this->mappings as $names) {
            if (in_array($name, array_map('strtolower', $names), true)) {
                $this->attributes[$name] = trim($value);
                return;
            }
        }
    }

    /** PEAR container callback: use fixed stages and inspect handles; never forward raw debug text. */
    public function log($message, $level = 7): bool
    {
        $stages = [
            'Auth_Container_LDAP::_connect() called.'=>'connection initialization',
            'Starting TLS session'=>'StartTLS',
            'Binding with credentials'=>'service bind', 'Binding anonymously'=>'service bind',
            'Auth_Container_LDAP::_getBaseDN() called.'=>'base DN discovery',
            'Checking group membership'=>'group membership search',
        ];
        if (isset($stages[$message])) $this->details['stage'] = $stages[$message];
        if ($message === 'Checking group membership') $this->groupSearch = true;
        if (str_starts_with($message, 'Switching to LDAP version ')) $this->details['stage'] = 'protocol version';
        if (str_starts_with($message, 'Searching with ')) $this->details['stage'] = $this->groupSearch ? 'group membership search' : 'user search';
        if (str_starts_with($message, 'Bind as ')) {
            ($this->rememberSecrets)([substr($message, strlen('Bind as '))]);
            $this->details['stage'] = 'user bind';
            $this->candidateAttributes = $this->attributes;
            $this->attributes = [];
            $this->hasCandidate = true;
        }
        if (in_array($message, ['Bind failed', 'Could not start TLS session', 'NOT authenticated!',
            'User not found', 'Auth_Container_LDAP::_disconnect() called.'], true)) $this->captureConnection();
        return true;
    }

    private function captureConnection(): void
    {
        if ($this->driver->conn_id === null || $this->driver->conn_id === false) return;
        $parts = @parse_url((string)($this->driver->options['url'] ?? ''));
        if (isset($parts['scheme'], $parts['host'])) $this->details['endpoint'] = $parts['scheme'].'://'.$parts['host'].
            (isset($parts['port']) ? ':'.$parts['port'] : '');
        try {
            $diagnostic = null;
            @ldap_get_option($this->driver->conn_id, LDAP_OPT_DIAGNOSTIC_MESSAGE, $diagnostic);
            $this->details['ldap_errno'] = @ldap_errno($this->driver->conn_id);
            $this->details['ldap_error'] = @ldap_error($this->driver->conn_id);
            $this->details['ldap_diagnostic'] = $diagnostic;
        } catch (\Throwable $ignored) {
            // A newer core driver may already have closed the handle. Keep the earlier snapshot.
        }
    }

    private function identity(): array
    {
        $data = array_fill_keys(['email', 'fullname', 'firstname', 'lastname'], '');
        foreach ($this->mappings as $key=>$names) {
            foreach ($names as $name) {
                if (array_key_exists(strtolower($name), $this->candidateAttributes)) {
                    $data[$key] = $this->candidateAttributes[strtolower($name)];
                    break;
                }
            }
        }
        return ['fullname'=>$data['fullname'] !== '' ? $data['fullname'] : trim($data['firstname'].' '.$data['lastname']),
            'email'=>strtolower($data['email'])];
    }

    public function diagnostics(): array { return $this->details; }
}
