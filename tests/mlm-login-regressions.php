<?php
// Standalone MLM companion regression tests: no REDCap installation required.
namespace ExternalModules {
    class AbstractExternalModule { public $framework; }
}

namespace REDCap {
    class Context {
        public $languageId;
        public function __construct($languageId = null) { $this->languageId = $languageId; }
        public static function Builder() { return new ContextBuilder(); }
    }
    class ContextBuilder {
        private $languageId;
        public function is_survey() { return $this; }
        public function project_id($value) { return $this; }
        public function survey_id($value) { return $this; }
        public function event_id($value) { return $this; }
        public function instrument($value) { return $this; }
        public function record($value) { return $this; }
        public function response_id($value) { return $this; }
        public function instance($value) { return $this; }
        public function lang_id($value) { $this->languageId = $value; return $this; }
        public function Build() { return new Context($this->languageId); }
    }
}

namespace MultiLanguageManagement {
    class MultiLanguage {
        public static $settings = [];
        public static $current = 'de-DE';
        public static function isActive($projectId) { return true; }
        public static function getProjectSettings($projectId) { return self::$settings; }
        public static function sortLanguages($languages, $subset = null) { return $subset ?? array_keys($languages); }
        public static function formatLangIdForHtmlTag($languageId) { return strtolower(explode('-', $languageId)[0]); }
        public static function getCurrentLanguage($context) { return self::$current; }
        public static function getUITranslation($context, $key) {
            return [
                'de-DE' => ['survey_22'=>'Zurückkehrend?', 'survey_118'=>'Rückkehrcode', 'survey_24'=>'Setzen Sie die Umfrage mit Ihrem Rückkehrcode fort.'],
                'en-US' => ['survey_22'=>'Returning?', 'survey_118'=>'Return Code', 'survey_24'=>'Continue the survey with your return code.'],
            ][$context->languageId][$key] ?? '';
        }
        public static function getDDTranslation($context, $type, $form) {
            if ($type === 'survey-logo_alt_text') {
                return ['de-DE'=>'Logo der Studie', 'en-US'=>'Study logo'][$context->languageId] ?? '';
            }
            return ['de-DE'=>'Studienumfrage', 'en-US'=>'Study survey'][$context->languageId] ?? '';
        }
    }
}

namespace {
    function isnumber($value) { return is_numeric($value); }
    function filter_tags($value) {
        $value = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', (string)$value);
        return preg_replace('/\s+on[a-z]+\s*=\s*(["\']).*?\1/is', ' removed=""', $value);
    }
    function check($value, $message) { if (!$value) throw new \RuntimeException($message); }
    function invoke($module, $method, ...$args) { return (new \ReflectionMethod($module, $method))->invoke($module, ...$args); }

    class Project {
        public function __construct($projectId) {}
        public function getMetadata() { return ['auth' => ['misc'=>'@SURVEY-AUTH']]; }
        public function getForms() { return ['survey' => ['survey_id'=>2, 'fields'=>['auth'=>[]]]]; }
    }

    require dirname(__DIR__).'/SurveyAuthExternalModule.php';

    class MlmFixture extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule {
        public function getSystemSetting($key) { return $key === 'surveyauth_lockouttime' ? '0' : ''; }
        public function getProjectSetting($key) { return ''; }
    }

    $module = new MlmFixture();
    $framework = new class {
        public $stored = '';
        public function getProjectSetting($key, $projectId = null) { return $this->stored; }
    };
    $module->framework = $framework;
    $settings = new \DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings($module, 1);
    \MultiLanguageManagement\MultiLanguage::$settings = [
        'fallbackLang' => 'en-US',
        'langs' => [
            'de-DE' => ['active'=>true, 'display'=>'Deutsch', 'htmlLang'=>'de', 'rtl'=>false,
                'dd'=>['survey-active'=>['survey'=>true]]],
            'en-US' => ['active'=>true, 'display'=>'English', 'htmlLang'=>'en', 'rtl'=>false,
                'dd'=>['survey-active'=>['survey'=>true]]],
            'fr-FR' => ['active'=>true, 'display'=>'Français', 'htmlLang'=>'fr', 'rtl'=>false,
                'dd'=>['survey-active'=>['survey'=>false]]],
        ],
    ];
    $items = invoke($module, 'surveyMlmLoginItems', $settings);
    check(!isset($items['login.language_label'], $items['login.logo_alt']),
        'The obsolete selector and logo-alt strings are not exposed for translation.');
    check(isset($items['login.return_code_invalid']) && !$items['login.return_code_invalid']['html'] &&
        !isset($items['login.returning_heading'], $items['login.return_code_label'], $items['login.return_code_help']),
        'Only the Survey Auth return-code error is module-owned translation content.');
    $framework->stored = json_encode(['version'=>1, 'languages'=>[
        'de-DE' => [
            'login.heading' => ['value'=>'Anmelden', 'source_hash'=>hash('sha256', $items['login.heading']['value'])],
            'login.username_label' => ['value'=>'Benutzername', 'source_hash'=>hash('sha256', $items['login.username_label']['value'])],
            'login.instructions' => ['value'=>'<em>Bitte anmelden</em><script>alert(1)</script><img src="x" onerror="alert(2)">',
                'source_hash'=>hash('sha256', $items['login.instructions']['value'])],
            'not-an-item' => ['value'=>'ignored', 'source_hash'=>str_repeat('0', 64)],
        ],
        'en-US' => [
            'login.password_label' => ['value'=>'Pass phrase', 'source_hash'=>hash('sha256', $items['login.password_label']['value'])],
            'login.submit_label' => ['value'=>'bad hash', 'source_hash'=>'not-a-hash'],
        ],
    ]]);
    $scope = ['project_id'=>1, 'survey_id'=>2, 'event_id'=>3, 'form_name'=>'survey', 'record'=>null, 'response_id'=>null, 'instance'=>1];
    $presentation = invoke($module, 'surveyMlmLoginPresentation', $scope, $settings, 'Reference survey');
    check($presentation['enabled'] && $presentation['current'] === 'de-DE', 'Current MLM survey language selects the login catalogue.');
    check(array_keys($presentation['languages']) === ['de-DE', 'en-US'], 'Only languages active for the protected survey are offered.');
    check($presentation['strings']['login.heading'] === 'Anmelden' &&
        $presentation['strings']['login.username_label'] === 'Benutzername', 'Saved language-specific login strings are used.');
    check(str_contains($presentation['strings']['login.instructions'], '<em>Bitte anmelden</em>') &&
        !str_contains($presentation['strings']['login.instructions'], '<script') &&
        !str_contains($presentation['strings']['login.instructions'], 'onerror'),
        'HTML-capable MLM strings retain REDCap-supported formatting but remove active markup.');
    check($presentation['languages']['de-DE']['survey_title'] === 'Studienumfrage' &&
        $presentation['languages']['en-US']['survey_title'] === 'Study survey', 'MLM survey titles join the login language catalogue.');
    check($presentation['languages']['de-DE']['survey_logo_alt'] === 'Logo der Studie' &&
        $presentation['languages']['en-US']['survey_logo_alt'] === 'Study logo',
        'MLM custom-logo alternative text joins the login language catalogue.');
    check($presentation['languages']['de-DE']['core_strings']['survey_22'] === 'Zurückkehrend?' &&
        $presentation['languages']['en-US']['core_strings']['survey_118'] === 'Return Code' &&
        $presentation['core_strings']['survey_22'] === 'Zurückkehrend?',
        'Returning UI strings use MLM core-language translations, not module-owned overrides.');
    check($presentation['strings']['login.password_label'] === 'Pass phrase', 'Missing strings use the configured MLM fallback language.');
    check($presentation['strings']['login.submit_label'] === $items['login.submit_label']['value'], 'Invalid translation entries fail closed to the reference string.');

    // The project-level translation catalogue may legitimately exceed the old
    // 512 KiB reader limit while staying within the bounded 2 MiB setting.
    $large = [];
    for ($i = 0; $i < 24; $i++) {
        $large['lang-'.$i]['login.instructions'] = [
            'value'=>str_repeat(chr(65 + ($i % 26)), 24000),
            'source_hash'=>str_repeat('a', 64),
        ];
    }
    $framework->stored = json_encode(['version'=>1, 'languages'=>$large], JSON_THROW_ON_ERROR);
    check(strlen($framework->stored) > 524288 && strlen($framework->stored) < 2097152,
        'The large-catalogue fixture exercises the expanded bound.');
    check(count(invoke($module, 'surveyMlmReadTranslations', 1, ['login.instructions'=>true])) === 24,
        'Valid MLM catalogues between 512 KiB and 2 MiB remain readable.');
    check(invoke($module, 'surveyMlmEncodeTranslations', $large) === $framework->stored,
        'The writer accepts catalogues within the same bound as the reader.');
    try {
        invoke($module, 'surveyMlmEncodeTranslations', [
            'oversized'=>['login.instructions'=>['value'=>str_repeat('x', 2097152), 'source_hash'=>str_repeat('a', 64)]],
        ]);
        throw new \LogicException('Oversized MLM catalogue accepted.');
    } catch (\LengthException $expected) {
    }

    \MultiLanguageManagement\MultiLanguage::$settings['langs']['de-DE']['dd']['survey-active']['survey'] = false;
    \MultiLanguageManagement\MultiLanguage::$settings['langs']['en-US']['dd']['survey-active']['survey'] = false;
    $presentation = invoke($module, 'surveyMlmLoginPresentation', $scope, $settings);
    check(!$presentation['enabled'] && $presentation['strings']['login.heading'] === 'Survey login',
        'No active MLM language on this survey leaves the original login page unchanged.');
    check(invoke($module, 'surveyMlmTranslationEditorAvailable', 1),
        'The editor remains available when a protected survey has not activated an otherwise active project language.');
    \MultiLanguageManagement\MultiLanguage::$settings['langs']['de-DE']['active'] = false;
    \MultiLanguageManagement\MultiLanguage::$settings['langs']['en-US']['active'] = false;
    \MultiLanguageManagement\MultiLanguage::$settings['langs']['fr-FR']['active'] = false;
    check(!invoke($module, 'surveyMlmTranslationEditorAvailable', 1),
        'The editor remains hidden when MLM has no active project language.');
    $editor = file_get_contents(dirname(__DIR__).'/classes/SurveyAuthMlm.php');
    check(str_contains($editor, "APP_PATH_CSS.'multilanguage-setup.css'") &&
        str_contains($editor, 'surveyauth-mlm-editor-sticky') &&
        strpos($editor, 'Save translations') < strpos($editor, 'data-bs-toggle="tab"') &&
        str_contains($editor, 'class="form-control form-control-sm textarea-autosize" rows="1"'),
        'The translation editor keeps its MLM-style navigation and compact autosizing fields available while scrolling.');
    echo "Passed MLM Survey Auth language eligibility, fallback, and storage validation regressions.\n";
}
