<?php
namespace DE\RUB\SurveyAuthExternalModule {
    function time() { return $GLOBALS['concurrency_now'] ?? \time(); }
}
namespace {
ob_start();
require __DIR__.'/session-regressions.php';
if (!defined('MYSQLI_STORE_RESULT')) define('MYSQLI_STORE_RESULT',0);
$GLOBALS['concurrency_now']=1000;
$storage=[];$held=[];$history=[];$storageFailure=false;
function db_query($sql,$params=[],$connection=null,$mode=null,$primary=false) {
    global $storage,$held,$history;
    check($primary,'All admission/storage operations use the primary connection');
    $lock=$params[0]??'';
    if (str_contains($sql,'GET_LOCK')) {
        $acquired=!isset($held[$lock]);
        $history[]=['acquire',$lock,$acquired];
        if($acquired)$held[$lock]=true;
        return new ArrayIterator([['acquired'=>$acquired?1:0]]);
    }
    if (str_contains($sql,'RELEASE_LOCK')) {
        check(isset($held[$lock]),'Only a held lock is released');
        unset($held[$lock]);$history[]=['release',$lock];
        return new ArrayIterator([]);
    }
    $key=$params[1];
    return new ArrayIterator(array_key_exists($key,$storage)?[['value'=>$storage[$key]]]:[]);
}
$module=new class extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule {public $PREFIX='fixture';};
$module->framework=new class {
    public function prefixSettingKey($key){return $key;}
    public function setSystemSetting($key,$value){
        global $storage,$held,$storageFailure;
        $bucket=substr($key,-1);
        check(isset($held[':fixture:lockouts:'.$bucket]),'Counter writes hold their bucket lock');
        if($storageFailure)throw new RuntimeException('synthetic storage failure');
        $storage[$key]=$value;
    }
};
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->useTable=true;$settings->useWhitelist=false;$settings->lockoutCount=1;$settings->lockouttime=5;
$settings->log='none';$settings->failMsg='Denied';$settings->lockoutMsg='Locked';$settings->errorMsg='Error';
(new ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue($module,$settings);
function concurrencyBucket($ip){global $module;return callPrivate($module,'lockoutBucketForIp',$ip);}
function concurrencyKey($ip){global $module;return callPrivate($module,'lockoutBucketSettingKey',concurrencyBucket($ip));}
function concurrencyData($ip){global $storage;return json_decode($storage[concurrencyKey($ip)]??'[]',true);}
class User {static function getUserInfo($u){return ['user_suspended_time'=>null,'user_email'=>'','user_firstname'=>'','user_lastname'=>''];}}
class Authentication {
    static $checks=[], $during=null, $throw=false;
    static function verifyTableUsernamePassword($u,$p){
        global $held;
        $ip=$_SERVER['REMOTE_ADDR'];
        check(isset($held[':fixture:authentication:'.$ip]),'Password verification holds its per-IP admission lock');
        check(!array_filter(array_keys($held),fn($key)=>str_starts_with($key,':fixture:lockouts:')),
            'Slow backends never hold a bucket storage lock');
        self::$checks[]=$ip;
        $callback=self::$during;self::$during=null;
        if($callback)$callback();
        if(self::$throw)throw new Error('synthetic backend failure');
        return $p==='correct';
    }
}
function attempt($ip,$password='wrong',$survey=false){
    global $module;
    $previous=$_SERVER['REMOTE_ADDR']??null;$_SERVER['REMOTE_ADDR']=$ip;
    try {return $survey ? $module->authenticate('fixture',$password,1,'survey',3,1,null)
        : $module->authenticatePublicDashboardOrReport('fixture',$password,1,'fixture');}
    finally {$_SERVER['REMOTE_ADDR']=$previous;}
}
Authentication::$during=function(){
    // A second connection/request overlaps while the first is verifying its password.
    $r=attempt('192.0.2.1','wrong',true);
    check(!$r['success'] && $r['error']==='Error','An overlapping same-IP survey request cannot enter the backend');
    check(count(Authentication::$checks)===1,'Only the first same-IP password is verified');
    attempt('192.0.2.2');
    check(count(Authentication::$checks)===2,'Another IP is not blocked by this backend');
};
attempt('192.0.2.1');
check(!$held && concurrencyData('192.0.2.1')['192.0.2.1']['n']===1 && concurrencyData('192.0.2.2')['192.0.2.2']['n']===1,
    'Overlapping requests preserve counters in separate buckets and release every lock');
$r=attempt('192.0.2.1','correct');
check(!$r['success'] && $r['error']==='Locked' && count(Authentication::$checks)===2,'Queued/later request observes the recorded failure');
$before=$storage;$GLOBALS['concurrency_now']=1299;attempt('192.0.2.1');
check($before===$storage && !$held,'Blocked attempt neither extends the deadline nor leaks a lock');
$GLOBALS['concurrency_now']=1300;
$r=attempt('192.0.2.1','correct');
check($r['success'] && !isset(concurrencyData('192.0.2.1')['192.0.2.1']) &&
    isset(concurrencyData('192.0.2.2')['192.0.2.2']) && !$held,
    'Expiry allows success and leaves another bucket for lazy pruning');
Authentication::$throw=true;
try {attempt('192.0.2.3');} catch(Error $expected) {}
check(!$held,'Unexpected backend errors release the per-IP lock');Authentication::$throw=false;
$storageFailure=true;$r=attempt('192.0.2.4');
check(!$r['success'] && !$held,'Counter-write failure fails authentication and releases both locks');
$storageFailure=false;
$held[':fixture:lockouts:'.concurrencyBucket('192.0.2.5')]=true;
$r=attempt('192.0.2.5');
check(!$r['success'] && array_keys($held)===[':fixture:lockouts:'.concurrencyBucket('192.0.2.5')],
    'A bucket-lock timeout releases only this request’s admission lock');
$held=[];
echo "Passed concurrent authentication admission, per-IP isolation, expiry, success, and lock-failure regressions.\n";
ob_end_flush();
}
