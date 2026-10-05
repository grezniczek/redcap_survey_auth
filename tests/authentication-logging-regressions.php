<?php
// Exercise authentication and its native logging API without a database or credentials.
namespace ExternalModules { class AbstractExternalModule { public $PREFIX='fixture'; public $framework; } }
namespace {
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
class User {
    public static $error;
    public static function getUserInfo($username) { throw self::$error; }
}
class REDCap {
    public static $logs=[];
    public static function logEvent(...$args) { self::$logs[]=$args; }
    public static function getDataDictionary(...$args) { return json_encode([['field_name'=>'auth','field_annotation'=>'@SURVEY-AUTH']]); }
    public static function getRecordIdField() { return 'record_id'; }
    public static function getSurveyLink(...$args) { return 'https://example.test/surveys/?s=fixture'; }
}
class Logging {
    public static $logs=[];
    public static function logEvent(...$args) { self::$logs[]=$args; }
}
class Form {
    public static function replaceIfActionTag($annotation,...$args) { return $annotation; }
    public static function getValueInParenthesesActionTag(...$args) { return ''; }
}
function check($ok,$message) { if(!$ok)throw new RuntimeException($message); }
$module=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule();
$module->framework=new class {
    public $logs=[];
    public $failLogging=false;
    public function prefixSettingKey($key) { return $key; }
    public function log($message,$parameters) {
        if ($this->failLogging) throw new RuntimeException('synthetic logging outage');
        $this->logs[]=[$message,$parameters];
    }
};
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
// Prefixes count UTF-8 characters and remain quoted; short usernames are shown in full.
$mask=new ReflectionMethod($module,'maskedUsernameForLog');
foreach ([''=>'','a'=>'a','ab'=>'ab','abc'=>'abc',
 'abcd'=>'abc[REDACTED]','rezniczek'=>'rez[REDACTED]','ÄÖÜx'=>'ÄÖÜ[REDACTED]',
 "a\nbc"=>"a\nb[REDACTED]",'"abc'=>'"ab[REDACTED]',"\xffabc"=>'[REDACTED]'] as $input=>$expected) {
 $actual=$mask->invoke($module,$input);
 check($actual===json_encode($expected,JSON_INVALID_UTF8_SUBSTITUTE),
   'Username hints show short values, mask longer values, and quote Unicode safely');
 check(!str_contains($actual,"\n"),'Username hints cannot inject log lines');
}
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
  check(str_contains($details,'Submitted username: "Aud[REDACTED]"'),'Only the three-character hint is logged, including successful logins');
  check(!str_contains(json_encode(REDCap::$logs),substr(json_encode($username),1,-1)),
    'Submitted username must not appear in any project log argument');
  check(!str_contains($details,"\nforged line"),'Username cannot inject a new log line');
  check(str_contains($details,'Survey: "example_survey"; instance: 2'),'Survey and repeat instance must be identifiable');
  check(str_contains($details,$success?'Successful authentication via Custom':'Failed or denied login attempt'),'Outcome must distinguish verified and failed identities');
  check(!str_contains(json_encode(REDCap::$logs),'PASSWORD_MUST_NOT_APPEAR'),'Neither submitted password may enter the log');
 }
}
// Public dashboards/reports also used the submitted value as the log's user argument.
foreach (['none','fail','success','all'] as $mode) {
 $settings->log=$mode;
 foreach (['Public Dashboard 7','Public Report 8'] as $title) {
  foreach ([false,true] as $success) {
   Logging::$logs=[];
   $result=$module->authenticatePublicDashboardOrReport($username,
     $success?$password:'WRONG_PASSWORD_MUST_NOT_APPEAR',87,$title);
   $expected=$mode==='all' || ($mode==='success' && $success) || ($mode==='fail' && !$success);
   check($result['success']===$success && count(Logging::$logs)===($expected?1:0),
     'Public-resource authentication and logging modes remain unchanged');
   if (!$expected) continue;
   check(Logging::$logs[0][7]==='( "Aud[REDACTED]" )' && Logging::$logs[0][8]===87,
     'Public-resource log actor is redacted and retains the correct project');
   $serialized=json_encode(Logging::$logs);
   check(!str_contains($serialized,substr(json_encode($username),1,-1)) &&
     !str_contains($serialized,'PASSWORD_MUST_NOT_APPEAR'),
     'Neither username nor password appears in any public-resource log argument');
   check(str_contains(Logging::$logs[0][4],$title), 'Resource identity remains available for troubleshooting');
  }
 }
}
$settings->log='all';$settings->useWhitelist=true;$settings->whitelist=['someone-else'];REDCap::$logs=[];
$result=$module->authenticate($username,$password,87,'example_survey',123,1,null);
check(!$result['success'] && count(REDCap::$logs)===1 && REDCap::$logs[0][3]===null,'Denied public-survey attempt logs without a record');
// Technical errors bypass attempt filters and exclude secrets even in nested exceptions.
$settings->useWhitelist=false;$settings->useCustom=false;$settings->useTable=true;
$bindPassword='BIND_SECRET_95a';$bindDn='cn=service-secret,dc=test';
$GLOBALS['ldapdsn']=['url'=>'ldap://fixture','binddn'=>$bindDn,'bindpw'=>$bindPassword];
$settings->otherLDAPConfigs=[['url'=>'ldap://uri-account:uri-password@fixture']];
$inner=new RuntimeException('Failure containing '.$password.' '.$bindPassword.' '.$bindDn.' uri-password', 72);
User::$error=new TypeError('Outer failure '.$username.' uri-account',0,$inner);
foreach (['none','fail','success','all'] as $mode) {
 $settings->log=$mode;REDCap::$logs=[];$module->framework->logs=[];
 $result=$module->authenticate($username,$password,87,'example_survey',123,2,'record-1');
 check(!$result['success'] && $result['error']==='Error','Technical failures retain the generic participant message');
 check(count($module->framework->logs)===1,'Technical failures always produce a module log entry');
 [$message,$parameters]=$module->framework->logs[0];
 check($message==='Survey Auth technical error' && $parameters['project_id']===87,'Module log uses the correct project');
 $details=$parameters['details'];
 check(str_contains($details,'TypeError') && str_contains($details,'RuntimeException') && str_contains($details,'72') && str_contains($details,'trace'),
   'Chained exception types, codes, locations, and trace metadata are retained');
 foreach ([$username,$password,$bindPassword,$bindDn,'uri-account','uri-password'] as $secret) {
  check(!str_contains($details,$secret),'Credentials must be absent from module diagnostics');
 }
 check(!str_contains($details,'"args"') && !str_contains($details,'"object"'),'Trace arguments and objects must never be logged');
 check(!str_contains(json_encode(REDCap::$logs),$password) && !str_contains(json_encode(REDCap::$logs),$bindPassword),
   'Project diagnostics must also redact passwords');
}
// Logging outages retain sanitized diagnostics without replacing the generic response.
$logFile=tempnam(sys_get_temp_dir(),'survey-auth-log-');
$previousErrorLog=ini_set('error_log',$logFile);
try {
 $module->framework->failLogging=true;
 (new ReflectionMethod($module,'logTechnicalError'))->invoke($module,'fixture failure',
     'Diagnostic '.$password.' '.$bindPassword,87);
 $fallback=file_get_contents($logFile);
 check(str_contains($fallback,'module logging failed') && str_contains($fallback,'Diagnostic'),
     'A module logging outage falls back to the PHP error log');
 check(!str_contains($fallback,$password) && !str_contains($fallback,$bindPassword),
     'Fallback diagnostics exclude credentials');
} finally {
 ini_set('error_log',$previousErrorLog);unlink($logFile);
 $module->framework->failLogging=false;
}
$config=json_decode(file_get_contents(dirname(__DIR__).'/config.json'),true,512,JSON_THROW_ON_ERROR);
check($config['enable-no-auth-logging']===true,'Framework permits logging on anonymous login pages');
echo "Passed technical diagnostics, credential redaction, and authentication logging modes, identity, scope, and password exclusion regressions.\n";
}
