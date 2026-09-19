<?php
// Standalone regression tests: php tests/security-regressions.php
// No REDCap bootstrap, installation credentials, database, or live requests.
namespace ExternalModules {
    class AbstractExternalModule {
        public $exited = false;
        public $framework;
        public function exitAfterHook() { $this->exited = true; }
    }
}

namespace {
    function filter_tags($value) {
        $value = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', (string)$value);
        return preg_replace('/\s+on[a-z]+\s*=\s*(["\']).*?\1/is', ' removed=""', $value);
    }
    class REDCap {
        public static $testFile = false;
        public static $fileReads = [];
        public static function getFile($id) { self::$fileReads[] = $id; return self::$testFile; }
        public static function getRecordIdField() { return 'record_id'; }
    }
    class Form {
        public static function replaceIfActionTag($annotation, ...$context) {
            // Synthetic evaluator output; this does not test REDCap's @IF parser.
            return $annotation === 'conditional-fixture' ? '@SURVEY-AUTH' : $annotation;
        }
        public static function getValueInParenthesesActionTag($annotation, $tag) {
            return preg_match('/'.preg_quote($tag, '/').'\(([^)]*)\)/', $annotation, $match) ? $match[1] : '';
        }
    }
    require_once dirname(__DIR__).'/SurveyAuthExternalModule.php';
    define('PAGE', 'surveys/index.php');

    function check($condition, $description) {
        if (!$condition) throw new \RuntimeException($description);
    }

    $module = new \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule();
    $method = new \ReflectionMethod($module, 'getTaggedFields');
    $cases = [
        '@SURVEY-AUTH' => 1,
        '@SURVEY-AUTH @HIDDEN-SURVEY' => 1,
        ' @SURVEY-AUTH' => 1,
        "@HIDDEN-SURVEY\n@SURVEY-AUTH" => 1,
        '@SURVEY-AUTH(success=1)' => 1,
        'conditional-fixture' => 1,
        '' => 0,
        '@SURVEY-AUTH-OTHER' => 0,
        '@SURVEY-AUTHENTICATION' => 0,
        '@SURVEY-AUTH_other' => 0,
        'prefix@SURVEY-AUTH' => 0,
    ];
    $cases['@SURVEY-AUTH(success)'] = 1;
    set_error_handler(static function($severity, $message, $file, $line) {
        throw new \ErrorException($message, 0, $severity, $file, $line);
    });
    try {
        foreach ($cases as $annotation => $expected) {
            $dictionary = [(object)['field_name' => 'auth', 'field_annotation' => $annotation]];
            $fields = $method->invoke($module, $dictionary, 1, null, 2, 'survey', 1);
            check(count($fields) === $expected, 'Tag detection: '.$annotation);
            if ($annotation === '@SURVEY-AUTH(success=1)') {
                check($fields[0]->successValue === '1', 'Parameterized tag retains its settings');
            } elseif ($annotation === '@SURVEY-AUTH(success)') {
                check($fields[0]->successField === null, 'Malformed action-tag parameters are ignored without warnings');
            }
        }
    } finally {
        restore_error_handler();
    }

    $credentialModule = new class extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule {
        public $systemSettingReads = [];
        public function getSystemSetting($key) {
            $this->systemSettingReads[] = $key;
            return $key === 'surveyauth_lockouttime' ? '0' : '';
        }
        public function getProjectSetting($key) {
            return match ($key) {
                'surveyauth_lockoutcount' => '0',
                'surveyauth_usecustom' => '1',
                'surveyauth_custom' => " user :secret:part\r\nblank:\n:password\n:\nvalid:0",
                default => '',
            };
        }
    };
    $credentialSettings = new \DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings($credentialModule, 1);
    check(!in_array('surveyauth_lockouts', $credentialModule->systemSettingReads, true),
        'Settings initialization does not eagerly load the legacy installation-wide lockout JSON');
    check($credentialSettings->customCredentials === ['user'=>'secret:part', 'valid'=>'0'],
        'Credential parsing rejects empty identities/secrets and preserves exact nonempty passwords');
    (new \ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class, 'settings'))
        ->setValue($credentialModule, $credentialSettings);
    foreach ([['', 'password', false], ['blank', '', false], [' user ', 'secret:part', true], ['valid', '0', true]] as [$user, $password, $expected]) {
        $result = ['success'=>false];
        (new \ReflectionMethod($credentialModule, 'authenticateCustom'))->invokeArgs($credentialModule, [$user, $password, &$result]);
        check($result['success'] === $expected, 'Custom authentication rejects blank credentials and normalizes usernames');
    }

    $config = json_decode(file_get_contents(dirname(__DIR__).'/config.json'), true, 512, JSON_THROW_ON_ERROR);
    $projectSettings = array_column($config['project-settings'], null, 'key');
    check(!empty($projectSettings['surveyauth_useotherldap']['super-users-only']) &&
        !empty($projectSettings['surveyauth_otherldap']['super-users-only']),
        'Other LDAP activation and connection secrets are restricted to superusers');

    foreach (['GET', 'POST'] as $verb) {
        foreach ([['__dashboard' => 'dashboard', '__report' => '1'],
                  ['__report' => '1', '__dashboard' => 'dashboard'],
                  ['__dashboard' => [], '__report' => []]] as $selectors) {
            $_SERVER['REQUEST_METHOD'] = $verb;
            $_GET = $selectors;
            $module->exited = false;
            http_response_code(200);
            ob_start();
            $module->redcap_every_page_before_render(1);
            ob_end_clean();
            check(http_response_code() === 400 && $module->exited, 'Conflicting selectors must terminate '.$verb);
        }
    }
    $_GET = [];
    $module->exited = false;
    $module->redcap_every_page_before_render(1);
    check(!$module->exited, 'Ordinary survey dispatch is unchanged in this preparatory patch');
    echo "Passed tag detection and conflicting-selector regressions.\n";
}
