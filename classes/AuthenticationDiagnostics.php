<?php namespace DE\RUB\SurveyAuthExternalModule;

/** Technical diagnostics never include request payloads, connection credentials, or trace arguments. */
trait AuthenticationDiagnostics
{
    private $diagnosticSecrets = [];

    private function rememberDiagnosticSecrets(array $values): void
    {
        foreach ($values as $value) {
            if (is_string($value) && $value !== '') {
                foreach ([$value, rawurlencode($value), urlencode($value),
                    substr(json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE), 1, -1),
                    $this->quoteFilterString($value)] as $encoded) {
                    $this->diagnosticSecrets[$encoded] = '[REDACTED]';
                }
            }
        }
    }

    private function redactDiagnostic(string $text): string
    {
        $configs = $GLOBALS['ldapdsn'] ?? [];
        if (is_array($configs) && isset($configs['url'])) $configs = [$configs];
        $otherConfigs = $this->settings->otherLDAPConfigs ?? [];
        foreach (array_merge(is_array($configs) ? $configs : [], is_array($otherConfigs) ? $otherConfigs : []) as $config) {
            if (!is_array($config)) continue;
            foreach ($config as $key => $value) {
                if (preg_match('/binddn|bindpw|password|passwd|credential|secret|token/i', (string)$key)) {
                    $this->rememberDiagnosticSecrets(is_array($value) ? $value : [$value]);
                }
            }
            $parts = @parse_url((string)($config['url'] ?? ''));
            foreach (['user', 'pass'] as $key) {
                if (isset($parts[$key])) $this->rememberDiagnosticSecrets([rawurldecode($parts[$key]), $parts[$key]]);
            }
        }
        $this->rememberDiagnosticSecrets([$this->settings->blobSecret ?? null, $this->settings->blobHmac ?? null]);
        $custom = $this->settings->customCredentials ?? [];
        if (!is_array($custom)) $custom = [];
        $this->rememberDiagnosticSecrets(array_merge(array_keys($custom), array_values($custom)));
        // strtr uses longest matches first and does not reprocess replacement text.
        return strtr($text, $this->diagnosticSecrets);
    }

    private function technicalException(\Throwable $error): string
    {
        $errors = [];
        do {
            $trace = [];
            foreach ($error->getTrace() as $frame) {
                $trace[] = array_intersect_key($frame, array_flip(['file', 'line', 'class', 'type', 'function']));
            }
            $errors[] = ['type'=>get_class($error), 'code'=>$error->getCode(), 'message'=>$error->getMessage(),
                'file'=>$error->getFile(), 'line'=>$error->getLine(), 'trace'=>$trace];
            $error = $error->getPrevious();
        } while ($error !== null);
        return $this->redactDiagnostic(json_encode($errors, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR));
    }

    private function logTechnicalError(string $stage, string $details, $projectId = null): void
    {
        $details = $this->redactDiagnostic($details);
        try {
            $this->framework->log('Survey Auth technical error', [
                'stage'=>$stage, 'details'=>$details, 'project_id'=>$projectId,
            ]);
        } catch (\Throwable $loggingError) {
            // A database/logging failure must not replace the participant's generic error.
            error_log('Survey Auth technical error (module logging failed: '.get_class($loggingError).'): '.$details);
        }
    }

    private function logAuthenticationErrors(array &$result, string $stage, $projectId): void
    {
        foreach ($result['log_error'] as &$detail) {
            $detail = $this->redactDiagnostic((string)$detail);
            $this->logTechnicalError($stage, $detail, $projectId);
        }
    }
}
