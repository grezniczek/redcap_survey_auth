<?php
require __DIR__.'/session-regressions.php';
if (!defined('MYSQLI_STORE_RESULT')) define('MYSQLI_STORE_RESULT',0);
$storage=[];$events=[];$acquire=true;$failWrite=false;
function db_query($sql,$params=[],$connection=null,$mode=null,$primary=false) {
    global $storage,$events,$acquire;
    check($primary,'Lockout queries use primary connection');
    if(str_contains($sql,'GET_LOCK')) {$events[]='lock';return new ArrayIterator([['acquired'=>$acquire?1:0]]);}
    if(str_contains($sql,'RELEASE_LOCK')) {$events[]='release';return new ArrayIterator([]);}
    $events[]='read';return new ArrayIterator([['value'=>json_encode($storage)]]);
}
$module=new class extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule { public $PREFIX='fixture'; };
$module->framework=new class {
    public function prefixSettingKey($key) { return $key; }
    public function setSystemSetting($key,$value) {
        global $storage,$events,$failWrite;
        $events[]='write';if($failWrite)throw new RuntimeException('simulated write failure');
        $storage=json_decode($value,true);
    }
};
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->lockoutCount=3;$settings->lockouttime=5;
(new ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue($module,$settings);
foreach (['192.0.2.1','192.0.2.2','192.0.2.1'] as $ip) {
    $settings->lockoutStatus=[]; // Request was initialized before other requests wrote.
    $events=[];callPrivate($module,'updateLockoutStatus',$ip);
    check($events[0]==='lock' && end($events)==='release' && array_search('read',$events)<array_search('write',$events),'Latest snapshot read and written within lock');
}
check($storage['192.0.2.1']['n']===2 && $storage['192.0.2.2']['n']===1,'Stale request snapshots lose neither same-IP increments nor other IPs');
$settings->lockoutStatus=[];callPrivate($module,'clearLockoutStatus','192.0.2.1');
check(!isset($storage['192.0.2.1']) && $storage['192.0.2.2']['n']===1,'Successful login clears only its IP using fresh storage');
$storage['198.51.100.1']=['n'=>7,'ts'=>time()-301];
$storage['malformed']=['n'=>0,'ts'=>'not-a-time'];
$settings->lockoutStatus=[];callPrivate($module,'updateLockoutStatus','192.0.2.3');
check(!isset($storage['198.51.100.1'],$storage['malformed']) && $storage['192.0.2.3']['n']===1,
    'Mutations prune expired and malformed lockout entries before persisting.');
$events=[];$acquire=false;$before=$storage;
try {callPrivate($module,'updateLockoutStatus','192.0.2.2');throw new LogicException('Timeout accepted');}
catch(RuntimeException $expected) {}
check($storage===$before && $events===['lock'],'Lock timeout never reads or writes unprotected data');
$events=[];$acquire=true;$failWrite=true;
try {callPrivate($module,'updateLockoutStatus','192.0.2.2');throw new LogicException('Write failure accepted');}
catch(RuntimeException $expected) {}
check($storage===$before && end($events)==='release','Write failure propagates and always releases lock');
$failWrite=false;
$moduleClass=new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class);
$limit=$moduleClass->getReflectionConstant('LOCKOUT_MAX_ENTRIES')->getValue();
check($limit===10000 && $moduleClass->getReflectionConstant('LOCKOUT_MAX_BYTES')->getValue()===2097152,
    'Lockout storage has explicit entry and byte bounds.');
$storage=[];$now=time();
for($i=0;$i<$limit;$i++) $storage['198.18.'.intdiv($i,256).'.'.($i%256)]=['n'=>1,'ts'=>$now];
$events=[];
try {callPrivate($module,'updateLockoutStatus','203.0.113.9');throw new LogicException('Entry cap accepted');}
catch(RuntimeException $expected) {}
check(count($storage)===$limit && !isset($storage['203.0.113.9']) && end($events)==='release' && !in_array('write',$events,true),
    'A new address cannot grow lockout storage beyond its entry cap.');
$storage['203.0.113.10']=['n'=>1,'ts'=>$now];
try {callPrivate($module,'checkLockoutStatus','198.18.0.0');throw new LogicException('Oversized entry set accepted');}
catch(RuntimeException $expected) {}
$storage=['oversized-'.str_repeat('x',2097152)=>['n'=>1,'ts'=>$now]];
try {callPrivate($module,'checkLockoutStatus','192.0.2.1');throw new LogicException('Oversized JSON accepted');}
catch(RuntimeException $expected) {}
echo "Passed lockout storage freshness, isolation, pruning, timeout, and capacity regressions.\n";
