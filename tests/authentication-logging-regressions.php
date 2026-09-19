<?php
// Exercise authentication and its native logging API without a database or credentials.
namespace ExternalModules { class AbstractExternalModule { public $PREFIX='fixture'; public $framework; } }
namespace {
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
class REDCap {
    public static $logs=[];
    public static function logEvent(...$args) { self::$logs[]=$args; }
    public static function getDataDictionary(...$args) { return json_encode([['field_name'=>'auth','field_annotation'=>'@SURVEY-AUTH']]); }
    public static function getRecordIdField() { return 'record_id'; }
    public static function getSurveyLink(...$args) { return 'https://example.test/surveys/?s=fixture'; }
}
class Form {
    public static function replaceIfActionTag($annotation,...$args) { return $annotation; }
    public static function getValueInParenthesesActionTag(...$args) { return ''; }
}
function check($ok,$message) { if(!$ok)throw new RuntimeException($message); }
$module=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule();
$module->framework=new class { public function prefixSettingKey($key) { return $key; } };
if(!defined('MYSQLI_STORE_RESULT'))define('MYSQLI_STORE_RESULT',0);
function db_query($sql,...$args) { return new ArrayIterator(str_contains($sql,'GET_LOCK') ? [['acquired'=>1]] : []); }
function db_fetch_assoc($rows) { if(!$rows->valid())return null; $row=$rows->current();$rows->next();return $row; }
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->lockoutCount=0;$settings->canwrite=false;$settings->useWhitelist=false;
$settings->useCustom=true;$settings->useTable=false;$settings->useLDAP=false;$settings->useOtherLDAP=false;
$settings->failMsg='Denied';$settings->errorMsg='Error';
$username="Audit User\nforged line";$password='PASSWORD_MUST_NOT_APPEAR_43f1';
$settings->customCredentials=[strtolower($username)=>$password];
(new ReflectionProperty($module,'settings'))->setValue($module,$settings);
$_SERVER['REMOTE_ADDR']='192.0.2.7';$GLOBALS['project_id']=999;
foreach(['none','fail','success','all'] as $mode) {
 $settings->log=$mode;
 foreach([false,true] as $success) {
  REDCap::$logs=[];
  $result=$module->authenticate($username,$success?$password:'WRONG_PASSWORD_MUST_NOT_APPEAR',87,'example_survey',123,2,'record-1');
  check($result['success']===$success,'Authentication outcome must remain unchanged');
  $expected=$mode==='all' || ($mode==='success' && $success) || ($mode==='fail' && !$success);
  check(count(REDCap::$logs)===($expected?1:0),'Configured logging mode must control event creation');
  if(!$expected)continue;
  [$description,$details,$sql,$record,$event,$project]=REDCap::$logs[0];
  check($description==='Survey Auth EM' && $record==='record-1' && $event===123 && $project===87,'Log must use the authenticated scope, not the global project');
  check(str_contains($details,'Submitted username: '.json_encode($username)),'Submitted identity must be recorded even with writing disabled');
  check(!str_contains($details,"\nforged line"),'Username cannot inject a new log line');
  check(str_contains($details,'Survey: "example_survey"; instance: 2'),'Survey and repeat instance must be identifiable');
  check(str_contains($details,$success?'Successful authentication via Custom':'Failed or denied login attempt'),'Outcome must distinguish verified and failed identities');
  check(!str_contains(json_encode(REDCap::$logs),'PASSWORD_MUST_NOT_APPEAR'),'Neither submitted password may enter the log');
 }
}
$settings->log='all';$settings->useWhitelist=true;$settings->whitelist=['someone-else'];REDCap::$logs=[];
$result=$module->authenticate($username,$password,87,'example_survey',123,1,null);
check(!$result['success'] && count(REDCap::$logs)===1 && REDCap::$logs[0][3]===null,'Denied public-survey attempt logs without a record');
echo "Passed authentication logging modes, identity, scope, and password exclusion regressions.\n";
}
