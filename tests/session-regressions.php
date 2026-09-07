<?php
// No REDCap bootstrap, database, web server, or installation credentials.
ob_start();
require __DIR__.'/security-regressions.php';

function callPrivate($module, $method, ...$args) {
    return (new ReflectionMethod($module, $method))->invoke($module, ...$args);
}
function setPrivate($module, $property, $value) {
    (new ReflectionProperty($module, $property))->setValue($module, $value);
}

$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->failMsg='denied';
$settings->customCredentials=['user'=>'0e12345'];
setPrivate($module,'settings',$settings);
foreach (['0e99999'=>false, '0e12345'=>true] as $password=>$expected) {
    $result=['success'=>false];
    (new ReflectionMethod($module,'authenticateCustom'))->invokeArgs($module,['user',$password,&$result]);
    check($result['success']===$expected,'Passwords must match exactly');
}
check($module->authenticate([],[],1,'survey',2,1,null)['success']===false,'Malformed credentials rejected');

$scope=['project_id'=>1,'survey_id'=>2,'event_id'=>3,'form_name'=>'survey','hash'=>'public','record'=>null,'instance'=>1];
$keyA=callPrivate($module,'surveyScopeKey',$scope,'flow-a');
$keyB=callPrivate($module,'surveyScopeKey',$scope,'flow-b');
check($keyA!==$keyB,'Two public starts must have separate grants');
$private=$scope; $private['record']='12';
$privateKey=callPrivate($module,'surveyScopeKey',$private);
foreach (['record'=>'13','event_id'=>4,'instance'=>2,'survey_id'=>5,'project_id'=>6] as $field=>$value) {
    $other=$private; $other[$field]=$value;
    check(callPrivate($module,'surveyScopeKey',$other)!==$privateKey,'Grant isolates '.$field);
}

$grant=['username'=>'user','method'=>'Custom','revision'=>'revision','issued'=>time(),'last'=>time(),'expires'=>time()+100];
$_SESSION=['redcap_survey_auth_v2'=>['logins'=>['expired'=>['expires'=>time()-1]],'grants'=>[
    'absolute-expired'=>array_replace($grant,['expires'=>time()-1]),
    'idle-expired'=>array_replace($grant,['last'=>time()-1801]),
    $keyA=>$grant,$keyB=>$grant,
]]];
callPrivate($module,'surveySession');
$state=$_SESSION['redcap_survey_auth_v2'];
check(!$state['logins'] && count($state['grants'])===2,'Expired logins and idle/absolute grants are removed');

setPrivate($module,'authorizedSurveyRequest',['scope'=>$scope,'key'=>$keyA,'flow'=>'flow-a','grant'=>$grant]);
$module->redcap_save_record(1,'12','survey',99,null,'public',100,1);
check(!isset($_SESSION['redcap_survey_auth_v2']['grants'][$privateKey]),'Unrelated save cannot establish continuation');
$module->redcap_save_record(1,'12','survey',3,null,'public',100,1);
$state=$_SESSION['redcap_survey_auth_v2'];
check(isset($state['grants'][$privateKey],$state['grants'][$keyB]) && !isset($state['grants'][$keyA]),'Save consumes only its own public grant and binds continuation');
$module->redcap_survey_complete(1,'12','survey',99,null,'public',100,1);
check(isset($_SESSION['redcap_survey_auth_v2']['grants'][$privateKey]),'Unrelated completion leaves grant intact');
$module->redcap_survey_complete(1,'12','survey',3,null,'public',100,1);
$state=$_SESSION['redcap_survey_auth_v2'];
check(!isset($state['grants'][$privateKey]) && isset($state['grants'][$keyB]),'Completion closes only its own response grant');

check(callPrivate($module,'surveyPath','https://internal.example/redcap/surveys/?s=example')==='/redcap/surveys/?s=example','Destination retains path on participant origin');
foreach (['https://example.test//evil.test/path', "https://example.test/\\evil.test/path"] as $url) {
    try { callPrivate($module,'surveyPath',$url); throw new LogicException('Unsafe destination accepted'); }
    catch (RuntimeException $expected) {}
}
echo "Passed survey grant scope, lifecycle, password, and destination regressions.\n";
ob_end_flush();
