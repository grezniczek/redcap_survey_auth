<?php
namespace ExternalModules {
    class AbstractExternalModule {
        public $framework;
        public $PREFIX = 'redcap_survey_auth';
        public $exited = false;
        public function exitAfterHook() { $this->exited = true; }
    }
}
namespace {
ob_start();
session_save_path(sys_get_temp_dir());
function filter_tags($value) {
    $value = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', (string)$value);
    return preg_replace('/\s+on[a-z]+\s*=\s*(["\']).*?\1/is', ' removed=""', $value);
}
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
define('PAGE', 'surveys/index.php');
define('APP_PATH_SURVEY_FULL', 'https://survey.example/surveys/');
class Session {
    const cookie_name_survey_prefix = 'survey';
    static function init($name) { if (session_status() !== PHP_SESSION_ACTIVE) { session_name($name); session_start(); } }
}
class REDCap {
    public static $dictionary=[['field_name'=>'auth','field_annotation'=>'@SURVEY-AUTH(success=1)']];
    public static $dictionaryJson=null;
    static function getDataDictionary(...$args) { return self::$dictionaryJson ?? json_encode(self::$dictionary); }
    static function getRecordIdField(){return 'record_id';}
}
class Form {
    static function replaceIfActionTag($tag,...$args){return $tag;}
    static function getValueInParenthesesActionTag($tag,$name){
        return preg_match('/'.preg_quote($name, '/').'\\(([^)]*)\\)/', $tag, $matches) ? $matches[1] : '';
    }
}
class Survey { static function decryptResponseHash($hash,$participant){return $hash==='valid-response-hash'?9:null;} }
class Project {
    public static $testForms=[];
    public static $testSurveys=[];
    public static $testMetadata=[];
    public $forms=[];
    public $surveys=[];
    public $metadata=[];
    public function __construct($projectId) {
        $this->forms=self::$testForms;
        $this->surveys=self::$testSurveys;
        $this->metadata=self::$testMetadata;
    }
    public function isRepeatingFormOrEvent($eventId,$formName){return false;}
}
function parseEnum($choices) {
    $result=[];
    foreach (preg_split('/\\R/', (string)$choices) as $choice) {
        [$value,$label]=array_pad(explode(',', $choice, 2), 2, null);
        if ($label !== null) $result[trim($value)]=trim($label);
    }
    return $result;
}
function isnumber($value) { return is_numeric($value); }
function db_fetch_assoc($q) { if (!$q->valid()) return null; $r=$q->current(); $q->next(); return $r; }
function check($value, $message) { if (!$value) throw new \RuntimeException($message); }
function invoke($module, $method, ...$args) { return (new \ReflectionMethod($module,$method))->invoke($module,...$args); }
function ajax($action,$payload,$pid) { global $module; return $module->redcap_module_ajax(...array_pad([$action,$payload,$pid],14,null)); }
class LoginFixture extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule {
    public $attempts=0;
    public $settingsReads=0;
    public $throw=false;
    public $allowWriting=false;
    public function getSystemSetting($key) { $this->settingsReads++; return $key==='surveyauth_lockouttime' ? '0' : ''; }
    public function getProjectSetting($key) { return str_contains($key, '_protected_') || ($key==='surveyauth_canwrite' && $this->allowWriting) ? '1' : ''; }
    public function authenticate($username,$password,$project_id,$instrument,$event_id,$repeat_instance,$record,$writeAuthenticationData=true) {
        $this->attempts++;
        if ($this->throw) throw new \RuntimeException('synthetic backend secret');
        return ['success'=>$username==='fixture' && $password==='correct', 'error'=>'Denied', 'record'=>null, 'method'=>'Custom',
            'authentication_values'=>['auth'=>'1','auth_user'=>$username]];
    }
    public function authenticatePublicDashboardOrReport($username,$password,$project_id,$page) {
        return $this->authenticate($username,$password,$project_id,null,null,null,null);
    }
}
$module=new LoginFixture();
$module->framework=new class {
    public function getProjectId() { return 1; }
    public function initializeJavascriptModuleObject(){}
    public function getJavascriptModuleObjectName(){return 'window.fixture';}
    public function getCSRFToken(){return str_repeat('a',80);}
    public function loadREDCapJS(){}
    public function loadBootstrap(){}
    public function query($sql,$params) {
        if (str_contains($sql,'redcap_surveys s')) return new \ArrayIterator([[
            'project_id'=>1,'survey_id'=>2,'form_name'=>'survey','save_and_return'=>1,'event_id'=>3,
            'participant_id'=>4,'participant_email'=>$params[1]==='private'?'':null,
        ]]);
        if (str_contains($sql,'FROM redcap_surveys_response')) return new \ArrayIterator([[
            'record'=>'existing','response_id'=>9,'instance'=>1,'first_submit_time'=>'2026-09-01 12:34:56',
        ]]);
        return new \ArrayIterator([['id'=>'7','title'=>'Fixture']]);
    }
};
$_SERVER=['REQUEST_METHOD'=>'POST','SERVER_NAME'=>'survey.example','SERVER_PORT'=>'443',
    'HTTP_HOST'=>'untrusted.example','HTTPS'=>'on','REQUEST_URI'=>'/surveys/'];
$GLOBALS['redcap_base_url']='https://survey.example/';
$GLOBALS['redcap_survey_base_url']='https://survey.example/';
invoke($module,'surveySessionReady');
function loginContext($type='survey') {
    global $module;
    $_SESSION['redcap_survey_auth_v2']=['logins'=>[], 'grants'=>[]];
    if ($type==='survey') {
        $scope=invoke($module,'surveyScope',1,'public');
        (new \ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue($module,new \DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings($module,1));
        $login=['scope'=>$scope,'revision'=>invoke($module,'surveyPolicyRevision',$scope),'destination'=>'/surveys/?s=public'];
    } else {
        $r=invoke($module,'publicResource',1,$type,'resource-hash');
        $policy=invoke($module,'loadPublicResourcePolicy',$r);
        $login=['scope'=>['project_id'=>1],'resource'=>$r,'revision'=>$policy['revision']];
    }
    $_SESSION['redcap_survey_auth_v2']['logins']['context']=$login+['csrf'=>'csrf','expires'=>time()+600];
    return ['context'=>'context','csrf'=>'csrf','username'=>'fixture','password'=>'correct'];
}
foreach (['survey','dashboard','report'] as $type) {
    $payload=loginContext($type);
    $before=$module->attempts;
    foreach ([['context'=>'missing'],['csrf'=>'wrong'],['csrf'=>[]],['context'=>[]]] as $change) {
        $r=ajax('survey-login',array_replace($payload,$change),1);
        check(!$r['success'] && $module->attempts===$before, 'Invalid context/CSRF cannot reach authentication');
    }
    check(!ajax('survey-login',$payload,2)['success'], 'Verified project must match');
    check(ajax('unknown',$payload,1)===null, 'Only registered login action is accepted');
    check(!ajax('survey-login','malformed',1)['success'], 'Malformed payload is rejected');
    $r=ajax('survey-login',array_replace($payload,['password'=>'wrong']),1);
    check(!$r['success'] && isset($r['csrf']) && $r['csrf']!=='csrf', 'Failure returns refreshed session CSRF');
    check(!$_SESSION['redcap_survey_auth_v2']['grants'], 'Failure does not grant access');
    $payload['csrf']=$r['csrf'];
    $r=ajax('survey-login',$payload,1);
    check($r['success'] && str_starts_with($r['redirect'],'/surveys/?'), 'Successful AJAX login returns a survey redirect');
    check(count($_SESSION['redcap_survey_auth_v2']['grants'])===1 && !$_SESSION['redcap_survey_auth_v2']['logins'], 'Success consumes context and stores one grant');
    if ($type==='survey') check(current($_SESSION['redcap_survey_auth_v2']['grants'])['authentication_values']===['auth'=>'1','auth_user'=>'fixture'],
        'Survey grant retains only the metadata values returned by authentication');
    check(!ajax('survey-login',$payload,1)['success'], 'Consumed login cannot be replayed');
}
$payload=loginContext();
$module->throw=true;
$r=ajax('survey-login',$payload,1);
check(!$r['success'] && !str_contains(json_encode($r),'synthetic backend secret'), 'Backend exception details do not escape to framework logs');
$module->throw=false;
$_SESSION['redcap_survey_auth_v2']['logins']['context']['expires']=time()-1;
check(!ajax('survey-login',$payload,1)['success'], 'Expired login is rejected');
$_GET=['s'=>'public','__passthru'=>'ExternalModules','prefix'=>'redcap_survey_auth','ajax'=>'1'];
$module->exited=false;
$module->redcap_every_page_before_render(1);
check(!$module->exited, 'Own framework AJAX request reaches verified dispatch instead of rendering another login');
$_GET['prefix']='another_module';
$before=$module->settingsReads;
ob_start();
$module->redcap_every_page_before_render(1);
ob_end_clean();
check($module->settingsReads>$before, 'Another module does not inherit the login dispatch exception');
$_GET=['s'=>'private','__startover'=>'1'];
$_POST=['__response_hash__'=>'valid-response-hash','__response_id__'=>999];
$module->redcap_every_page_before_render(1);
check($_POST['__response_id__']===9,'Start over binds the core reset ID to the validated response hash');
foreach ([['__response_hash__'=>''],['__response_hash__'=>[]],['submit-action'=>'next']] as $invalid) {
    $module->exited=false;
    $_POST=array_replace(['__response_hash__'=>'valid-response-hash'],$invalid);
    ob_start();$module->redcap_every_page_before_render(1);ob_end_clean();
    check($module->exited && http_response_code()===400,'Malformed or mixed Start over submissions are blocked');
}
REDCap::$dictionary=[['field_name'=>'auth','field_annotation'=>'@SURVEY-AUTH(success=1)']];
$module->allowWriting=true;
$scope=invoke($module,'surveyScope',1,'private');
(new \ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue(
    $module,new \DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings($module,1));
$key=invoke($module,'surveyScopeKey',$scope);
$oldGrant=['username'=>'fixture','method'=>'Custom','revision'=>invoke($module,'surveyPolicyRevision',$scope),
    'last'=>time(),'expires'=>time()+600];
foreach ([$oldGrant, $oldGrant+['authentication_values'=>['auth'=>'1']]] as $grant) {
    $_SESSION=['redcap_survey_auth_v2'=>['logins'=>[],'grants'=>[$key=>$grant]]];
    $_GET=['s'=>'private','__startover'=>'1'];$_POST=['__response_hash__'=>'valid-response-hash'];$module->exited=false;
    ob_start();$module->redcap_every_page_before_render(1);$html=ob_get_clean();
    if (isset($grant['authentication_values'])) {
        check(!$module->exited,'Grant with authentication values allows the authorized reset to proceed');
    } else {
        check($module->exited && str_contains($html,'Sign in again before starting over'),'Older grant requests authentication before allowing core to erase values');
    }
}
foreach (['[]', '{invalid-json', '[{}]'] as $invalidDictionary) {
    REDCap::$dictionaryJson = $invalidDictionary;
    $_SERVER['REQUEST_METHOD']='GET';$_GET=['s'=>'public'];$_POST=[];$module->exited=false;
    http_response_code(200);ob_start();$module->redcap_every_page_before_render(1);$body=ob_get_clean();
    check($module->exited && http_response_code()===503 && str_contains($body,'authorization could not be checked'),
        'Empty or malformed survey metadata fails closed');
}
REDCap::$dictionaryJson=null;
REDCap::$dictionary=[['field_name'=>'ordinary','field_annotation'=>'']];
$_SERVER['REQUEST_METHOD']='GET';$_GET=['s'=>'public'];$_POST=[];$module->exited=false;
$module->redcap_every_page_before_render(1);
check(!$module->exited,'A successfully loaded dictionary without the action tag remains unprotected');
REDCap::$dictionary=[['field_name'=>'auth','field_annotation'=>'@SURVEY-AUTH(success=1)']];
session_destroy();
echo "Passed AJAX login errors, retries, grants, replay, resources, and hook routing regressions.\n";
ob_end_flush();
}
