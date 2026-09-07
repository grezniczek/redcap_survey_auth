<?php
// Standalone regression tests: php tests/security-regressions.php
// No REDCap bootstrap, installation credentials, database, or live requests.
namespace ExternalModules {
    class AbstractExternalModule {
        public $exited = false;
        public function exitAfterHook() { $this->exited = true; }
    }
}

namespace {
    class REDCap {
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
    foreach ($cases as $annotation => $expected) {
        $dictionary = [(object)['field_name' => 'auth', 'field_annotation' => $annotation]];
        $fields = $method->invoke($module, $dictionary, 1, null, 2, 'survey', 1);
        check(count($fields) === $expected, 'Tag detection: '.$annotation);
        if ($annotation === '@SURVEY-AUTH(success=1)') {
            check($fields[0]->successValue === '1', 'Parameterized tag retains its settings');
        }
    }

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
