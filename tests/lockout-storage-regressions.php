<?php
require __DIR__.'/session-regressions.php';
if (!defined('MYSQLI_STORE_RESULT')) define('MYSQLI_STORE_RESULT',0);
$storage=[];$events=[];$acquire=true;$failWrite=false;
function db_query($sql,$params=[],$connection=null,$mode=null,$primary=false) {
    global $storage,$events,$acquire;
    check($primary,'Lockout queries use primary connection');
    if(str_contains($sql,'GET_LOCK')) {$events[]='lock:'.$params[0];return new ArrayIterator([['acquired'=>$acquire?1:0]]);}
    if(str_contains($sql,'RELEASE_LOCK')) {$events[]='release:'.$params[0];return new ArrayIterator([]);}
    $key=$params[1];$events[]='read:'.$key;
    return new ArrayIterator(array_key_exists($key,$storage)?[['value'=>$storage[$key]]]:[]);
}
$module=new class extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule { public $PREFIX='fixture'; };
$module->framework=new class {
    public function prefixSettingKey($key) { return $key; }
    public function setSystemSetting($key,$value) {
        global $storage,$events,$failWrite;
        $events[]='write:'.$key;if($failWrite)throw new RuntimeException('simulated write failure');
        $storage[$key]=$value;
    }
};
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->lockoutCount=3;$settings->lockouttime=5;$settings->lockoutStatus=[];
(new ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue($module,$settings);
function bucketFor($module,$ip){return callPrivate($module,'lockoutBucketForIp',$ip);}
function bucketKeyFor($module,$ip){return callPrivate($module,'lockoutBucketSettingKey',bucketFor($module,$ip));}
function bucketData($module,$ip){global $storage;return json_decode($storage[bucketKeyFor($module,$ip)]??'[]',true);}
function findBucketIp($module,$bucket,$start,$exclude=[]){
    for($i=$start;$i<1000000;$i++){
        $ip=long2ip(0x0a000000+$i);
        if(!in_array($ip,$exclude,true)&&bucketFor($module,$ip)===$bucket)return $ip;
    }
    throw new RuntimeException('Could not find bucket fixture IP');
}
$ip='192.0.2.1';$bucket=bucketFor($module,$ip);
$same=findBucketIp($module,$bucket,1,[$ip]);
$other=findBucketIp($module,dechex((hexdec($bucket)+1)%16),1,[$ip,$same]);
foreach ([$ip,$other,$same,$ip] as $address) {
    $settings->lockoutStatus=[]; // Request was initialized before other requests wrote.
    $events=[];callPrivate($module,'updateLockoutStatus',$address);
    $key=bucketKeyFor($module,$address);
    check(str_starts_with($events[0],'lock::fixture:lockouts:') && end($events)==='release::fixture:lockouts:'.bucketFor($module,$address) &&
        array_search('read:'.$key,$events)<array_search('write:'.$key,$events),'Latest bucket snapshot is read and written within its lock');
}
$sameBucket=bucketData($module,$ip);$otherBucket=bucketData($module,$other);
check($sameBucket[$ip]['n']===2 && $sameBucket[$same]['n']===1 && $otherBucket[$other]['n']===1,
    'Updates retain same-bucket counters and isolate other buckets');
$settings->lockoutStatus=[];callPrivate($module,'clearLockoutStatus',$ip);
$sameBucket=bucketData($module,$ip);
check(!isset($sameBucket[$ip]) && $sameBucket[$same]['n']===1 && bucketData($module,$other)[$other]['n']===1,
    'Successful login clears only its IP without rewriting another bucket');
$expired=findBucketIp($module,$bucket,1000,[$ip,$same,$other]);
$sameBucket[$expired]=['n'=>7,'ts'=>time()-301];
$sameBucket['malformed']=['n'=>0,'ts'=>'not-a-time'];
$storage[bucketKeyFor($module,$same)]=json_encode($sameBucket);
$settings->lockoutStatus=[];callPrivate($module,'updateLockoutStatus',$same);
$sameBucket=bucketData($module,$same);
check(!isset($sameBucket[$expired],$sameBucket['malformed']) && $sameBucket[$same]['n']===2,
    'A bucket mutation prunes its expired and malformed entries before persisting');
$events=[];$acquire=false;$before=$storage;
try {callPrivate($module,'updateLockoutStatus',$same);throw new LogicException('Timeout accepted');}
catch(RuntimeException $expected) {}
check($storage===$before && count($events)===1 && str_starts_with($events[0],'lock::fixture:lockouts:'),
    'Bucket-lock timeout never reads or writes unprotected data');
$events=[];$acquire=true;$failWrite=true;
try {callPrivate($module,'updateLockoutStatus',$same);throw new LogicException('Write failure accepted');}
catch(RuntimeException $expected) {}
check($storage===$before && str_starts_with(end($events),'release::fixture:lockouts:'),'Write failure propagates and always releases its bucket lock');
$failWrite=false;
$moduleClass=new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class);
$limit=$moduleClass->getReflectionConstant('LOCKOUT_BUCKET_MAX_ENTRIES')->getValue();
$byteLimit=$moduleClass->getReflectionConstant('LOCKOUT_BUCKET_MAX_BYTES')->getValue();
check($moduleClass->getReflectionConstant('LOCKOUT_BUCKET_COUNT')->getValue()===16 && $limit===1024 && $byteLimit===262144,
    'Lockout storage has 16 explicitly bounded buckets');
$full=[];$used=[];$candidate=1;
while(count($full)<$limit){
    $address=findBucketIp($module,$bucket,$candidate,$used);$used[]=$address;$candidate=ip2long($address)-0x0a000000+1;
    $full[$address]=['n'=>1,'ts'=>time()];
}
$key=bucketKeyFor($module,$ip);$storage[$key]=json_encode($full);$extra=findBucketIp($module,$bucket,$candidate,$used);$events=[];
try {callPrivate($module,'updateLockoutStatus',$extra);throw new LogicException('Entry cap accepted');}
catch(RuntimeException $expected) {}
check(count(json_decode($storage[$key],true))===$limit && !in_array('write:'.$key,$events,true) && str_starts_with(end($events),'release:'),
    'A new address cannot grow one bucket beyond its entry cap');
$full[$extra]=['n'=>1,'ts'=>time()];$storage[$key]=json_encode($full);
try {callPrivate($module,'checkLockoutStatus',$ip);throw new LogicException('Oversized entry set accepted');}
catch(RuntimeException $expected) {}
$storage[$key]=str_repeat('x',$byteLimit+1);
try {callPrivate($module,'checkLockoutStatus',$ip);throw new LogicException('Oversized JSON accepted');}
catch(RuntimeException $expected) {}
echo "Passed lockout bucket freshness, isolation, pruning, timeout, and capacity regressions.\n";
