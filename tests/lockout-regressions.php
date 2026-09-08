<?php
namespace DE\RUB\SurveyAuthExternalModule {
    // Deterministic clock for the module's lockout helpers; no sleeps or live settings.
    function time() { return $GLOBALS['lockout_test_now'] ?? \time(); }
}
namespace {
require __DIR__.'/session-regressions.php';
$module=new class extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule {
    public $writes=[];
    public $PREFIX='fixture';
    public function setSystemSetting($key,$value) { $this->writes[]=[$key,$value]; }
};
if (!defined('MYSQLI_STORE_RESULT')) define('MYSQLI_STORE_RESULT', 0);
function db_query($sql,$params=[],$connection=null,$mode=null,$primary=false) {
    global $settings;
    check($primary,'Lockout queries must use the primary connection');
    if (str_contains($sql,'GET_LOCK')) return new ArrayIterator([['acquired'=>1]]);
    if (str_contains($sql,'RELEASE_LOCK')) return new ArrayIterator([]);
    return new ArrayIterator([['value'=>json_encode($settings->lockoutStatus)]]);
}
$module->PREFIX='fixture';
$module->framework=new class($module) {
    public function __construct(private $module) {}
    public function prefixSettingKey($key) { return $key; }
    public function setSystemSetting($key,$value) { $this->module->setSystemSetting($key,$value); }
};
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->lockouttime=5;
$settings->lockoutMsg='Locked';$settings->failMsg='Denied';$settings->errorMsg='Error';
$settings->useCustom=true;$settings->customCredentials=['user'=>'correct'];
$settings->useWhitelist=false;$settings->useTable=false;$settings->useLDAP=false;$settings->useOtherLDAP=false;
$settings->log='none';
(new ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue($module,$settings);
$_SERVER['REMOTE_ADDR']='192.0.2.1';
$ip=$_SERVER['REMOTE_ADDR'];
foreach ([1,2,3,5] as $threshold) {
    $GLOBALS['lockout_test_now']=1000;
    $settings->lockoutCount=$threshold;
    $settings->lockoutStatus=['192.0.2.2'=>['n'=>1,'ts'=>1000]];
    $module->writes=[];
    for($i=1;$i<=$threshold;$i++) {
        $result=$module->authenticatePublicDashboardOrReport('user','wrong',1,'Test');
        check(!$result['success'] && $settings->lockoutStatus[$ip]['n']===$i,'Each failed authentication counts once');
    }
    $before=$settings->lockoutStatus;$writes=count($module->writes);
    foreach([1000,1100,1299] as $now) {
        $GLOBALS['lockout_test_now']=$now;
        $result=$module->authenticatePublicDashboardOrReport('user','correct',1,'Test');
        check(!$result['success'] && $result['error']==='Locked',"Threshold $threshold blocks until expiry");
        $survey=$module->authenticate('user','correct',1,'survey',3,1,null);
        check(!$survey['success'] && $survey['error']==='Locked','Survey authentication uses the same lockout boundary');
        check($settings->lockoutStatus===$before && count($module->writes)===$writes,'Blocked attempts neither write nor extend the deadline');
    }
    $GLOBALS['lockout_test_now']=1300;
    check(callPrivate($module,'checkLockoutStatus',$ip)===0,'Lockout expires exactly at its deadline');
    check($settings->lockoutStatus===$before && count($module->writes)===$writes,'Expiry check is read-only');
    $result=$module->authenticatePublicDashboardOrReport('user','correct',1,'Test');
    check($result['success'] && !isset($settings->lockoutStatus[$ip]),"Threshold $threshold permits login after expiry and clears old failures");
    check(isset($settings->lockoutStatus['192.0.2.2']),'Clearing one IP preserves the other IP');
    $settings->lockoutStatus[$ip]=['n'=>$threshold,'ts'=>1000];
    $result=$module->authenticatePublicDashboardOrReport('user','wrong',1,'Test');
    check(!$result['success'] && $settings->lockoutStatus[$ip]===['n'=>1,'ts'=>1300],'A failure after expiry starts a fresh count');
}
foreach ([[0,5],[3,0],[3,0.0]] as [$count,$minutes]) {
    $settings->lockoutCount=$count;$settings->lockouttime=$minutes;
    $settings->lockoutStatus=[$ip=>['n'=>99,'ts'=>1300]];$module->writes=[];
    check(callPrivate($module,'checkLockoutStatus',$ip)===0,'Disabled lockout ignores old failures');
    callPrivate($module,'updateLockoutStatus',$ip);
    check(!$module->writes,'Disabled lockout records no failures');
}
echo "Passed lockout threshold, deadline, reset, and disabled-mode regressions.\n";
}
