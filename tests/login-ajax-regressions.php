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
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
define('PAGE', 'surveys/index.php');
define('APP_PATH_SURVEY_FULL', 'https://survey.example/surveys/');
class Session {
    const cookie_name_survey_prefix = 'survey';
    static function init($name) { if (session_status() !== PHP_SESSION_ACTIVE) { session_name($name); session_start(); } }
}
class REDCap { static function getDataDictionary(...$args) { return '[]'; } }
function isnumber($value) { return is_numeric($value); }
function db_fetch_assoc($q) { if (!$q->valid()) return null; $r=$q->current(); $q->next(); return $r; }
function check($value, $message) { if (!$value) throw new \RuntimeException($message); }
function invoke($module, $method, ...$args) { return (new \ReflectionMethod($module,$method))->invoke($module,...$args); }
function ajax($action,$payload,$pid) { global $module; return $module->redcap_module_ajax(...array_pad([$action,$payload,$pid],14,null)); }
class LoginFixture extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule {
    public $attempts=0;
    public $settingsReads=0;
    public $throw=false;
    public function getSystemSetting($key) { $this->settingsReads++; return $key==='surveyauth_lockouttime' ? '0' : ''; }
    public function getProjectSetting($key) { return str_contains($key, '_protected_') ? '1' : ''; }
    public function authenticate($username,$password,$project_id,$instrument,$event_id,$repeat_instance,$record,$writeAuthenticationData=true) {
        $this->attempts++;
        if ($this->throw) throw new \RuntimeException('synthetic backend secret');
        return ['success'=>$username==='fixture' && $password==='correct', 'error'=>'Denied', 'record'=>null, 'method'=>'Custom'];
    }
    public function authenticatePublicDashboardOrReport($username,$password,$project_id,$page) {
        return $this->authenticate($username,$password,$project_id,null,null,null,null);
    }
}
$module=new LoginFixture();
$module->framework=new class {
    public function getProjectId() { return 1; }
    public function query($sql,$params) {
        if (str_contains($sql,'redcap_surveys s')) return new \ArrayIterator([[
            'project_id'=>1,'survey_id'=>2,'form_name'=>'survey','save_and_return'=>1,'event_id'=>3,
            'participant_id'=>4,'participant_email'=>null,
        ]]);
        return new \ArrayIterator([['id'=>'7','title'=>'Fixture']]);
    }
};
$_SERVER=['REQUEST_METHOD'=>'POST','HTTP_HOST'=>'survey.example','HTTPS'=>'on','REQUEST_URI'=>'/surveys/'];
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
session_destroy();
echo "Passed AJAX login errors, retries, grants, replay, resources, and hook routing regressions.\n";
ob_end_flush();
}
