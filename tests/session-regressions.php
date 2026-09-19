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
check(callPrivate($module,'surveyReturnKey',$scope)!==callPrivate($module,'surveyScopeKey',$scope,'return'),
    'A client-supplied flow cannot select a return-only grant');
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

// Exercise the real return-code lookup with queued database results. The SQL
// and its parameters are captured; no installation or credentials are loaded.
class SurveyAuthQueryFixture {
    public $results = [];
    public $queries = [];
    public function query($sql, $params) {
        $this->queries[] = [$sql, $params];
        return new ArrayIterator(array_shift($this->results) ?? []);
    }
}
function db_fetch_assoc($cursor) {
    if (!$cursor->valid()) return null;
    $row=$cursor->current(); $cursor->next(); return $row;
}
$fixture = new SurveyAuthQueryFixture();
$module->framework = $fixture;
foreach ([null, [], '', str_repeat('a',16)] as $code) {
    check(callPrivate($module,'surveyReturnScope',$scope,$code)===null,'Malformed return code is rejected');
}
check(!$fixture->queries,'Malformed return codes never reach the database');
$fixture->results = [[['hash'=>'private','response_id'=>42]],
    [['project_id'=>1,'survey_id'=>2,'form_name'=>'survey','save_and_return'=>1,'event_id'=>3,'participant_id'=>7,'participant_email'=>'']],
    [['record'=>'12','response_id'=>42,'instance'=>2,'first_submit_time'=>'2026-01-01 10:00:00']]];
$returned=callPrivate($module,'surveyReturnScope',$scope,' validcode ');
check($returned['record']==='12' && $returned['instance']===2 && $returned['hash']==='private',
    'Return scope comes from the matching response and participant');
check($fixture->queries[0][1]===[2,3,'VALIDCODE'],'Code lookup is case-normalized and limited to this survey and event');
check($fixture->queries[2][1]===[7,42],'Resolved response must belong to the selected participant');
$fixture->results = [[['hash'=>'one','response_id'=>1],['hash'=>'two','response_id'=>2]]];
check(callPrivate($module,'surveyReturnScope',$scope,'DUPLICATE')===null,'Ambiguous return code fails closed');
$fixture->results = [[]]; $private['participant_id']=7;
callPrivate($module,'surveyReturnScope',$private,'VALIDCODE');
$last=end($fixture->queries);
check($last[1]===[2,3,'VALIDCODE',7] && str_contains($last[0],'AND p.participant_id=?'),
    'A private link cannot return into another participant');
$fixture->results = [[['project_id'=>1,'survey_id'=>2,'form_name'=>'survey','save_and_return'=>1,'event_id'=>3,'participant_id'=>8,'participant_email'=>null]],
    [['record'=>'12','response_id'=>43,'instance'=>1,'first_submit_time'=>'2026-01-01 10:00:00']]];
$publicResponse=callPrivate($module,'surveyScope',1,'public',43);
check($publicResponse['record']==='12' && $publicResponse['response_id']===43,
    'A verified public response hash can resolve its continuation');

check(callPrivate($module,'surveyPath','https://internal.example/redcap/surveys/?s=example')==='/redcap/surveys/?s=example','Destination retains path on participant origin');
foreach (['https://example.test//evil.test/path', "https://example.test/\\evil.test/path"] as $url) {
    try { callPrivate($module,'surveyPath',$url); throw new LogicException('Unsafe destination accepted'); }
    catch (RuntimeException $expected) {}
}
echo "Passed survey grant scope, lifecycle, return-code, password, and destination regressions.\n";
ob_end_flush();
