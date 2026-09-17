<?php
// Render -> save -> reopen round trips, with in-memory settings and staff-rights fixtures.
ob_start();
require __DIR__.'/session-regressions.php';
define('USERID','editor');
function isnumber($value) { return is_numeric($value); }
function starts_with($text,$prefix) { return str_starts_with($text,$prefix); }
class UserRights {
    public static function getPrivileges($pid,$user) { return [$pid=>[$user=>['reports'=>1,'role_id'=>null,'group_id'=>null]]]; }
}
class DataExport {
    public static function validateReportId($pid,$id) { return $pid===1 && $id==2; }
    public static function getReportsEditAccess(...$args) { return [2]; }
}
class ProjectDashboards {
    public function getDashboards($pid,$id) { return ['is_public'=>'1']; }
}
$module=new class extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule {
    public $saved=[];
    public function getSystemSetting($key) { return ''; }
    public function getProjectSetting($key) { return (string)($this->saved[$key] ?? ''); }
    public function setProjectSetting($key,$value) { $this->saved[$key]=$value; }
    public function escape($value) { return htmlspecialchars($value,ENT_QUOTES); }
    public function initializeJavascriptModuleObject() {}
};
$module->framework=new class {
    public function getJavascriptModuleObjectName() { return 'fixture'; }
    public function query($sql,$params) { return new ArrayIterator([['id'=>2,'title'=>'Fixture']]); }
};
$GLOBALS['redcap_base_url']='https://dev-redcap/';
$GLOBALS['redcap_survey_base_url']='https://dev-surveys/';
$_SERVER['REQUEST_SCHEME']='https';
$_SERVER['REQUEST_URI']='/surveys/';
function setRequestEndpoint($authority,$scheme,$spoofedHost='attacker.invalid') {
    $parts=parse_url($scheme.'://'.$authority);
    $_SERVER['SERVER_NAME']=$parts['host'];
    $_SERVER['SERVER_PORT']=(string)($parts['port'] ?? ($scheme==='https'?443:80));
    $_SERVER['HTTP_HOST']=$spoofedHost;
    $_SERVER['REQUEST_SCHEME']=$scheme;
}
function selectedEndpoint($module,$type) {
    $_GET=['report_id'=>2,'dash_id'=>2];
    ob_start();callPrivate($module,'add_'.$type.'_settings',1);$html=ob_get_clean();
    preg_match_all("/type='radio' value='([^']+)' checked/",$html,$matches);
    check(count($matches[1])===1,'Exactly one endpoint is selected');
    return $matches[1][0];
}
foreach(['dashboard'=>'dash','report'=>'report'] as $type=>$prefix) {
 foreach(['both','internal','external'] as $endpoint) {
    $module->saved=["surveyauth_{$prefix}_endpoint_2"=>$endpoint,"surveyauth_{$prefix}_protected_2"=>'1'];
    $selected=selectedEndpoint($module,$type);
    check($selected===$endpoint,"$type displays saved $endpoint endpoint");
    if($type==='dashboard') callPrivate($module,'save_dashboard_settings',2,['is_public'=>'on','survey_auth_protected'=>'on','surveyauth_dash_endpoint'=>$selected]);
    else callPrivate($module,'save_report_settings',1,['report_id'=>2,'report_protected'=>true,'report_denyexternal'=>false,'report_endpoint'=>$selected]);
    check(selectedEndpoint($module,$type)===$endpoint,"$type save and reopen retains $endpoint");
    foreach(['internal'=>'dev-redcap','external'=>'dev-surveys'] as $side=>$host) {
        setRequestEndpoint($host,'https',$side==='internal'?'dev-surveys':'dev-redcap');
        $policy=callPrivate($module,'loadPublicResourcePolicy',['project_id'=>1,'type'=>$type,'id'=>2]);
        check((bool)$policy['protect']===($endpoint==='both' || $endpoint===$side),"$type protects intended $side origin after save");
    }
 }
}
$beforeInvalidReportId = $module->saved;
foreach ([null, '', '2.0', '-2', '2e0', [], 2.0] as $reportId) {
    $result = callPrivate($module, 'save_report_settings', 1, [
        'report_id' => $reportId,
        'report_protected' => true,
        'report_denyexternal' => true,
        'report_endpoint' => 'external',
    ]);
    check($result === 0 && $module->saved === $beforeInvalidReportId,
        'Report settings reject malformed report IDs before permissions or writes');
}
echo "Passed dashboard/report endpoint render, save, and policy round trips.\n";

// Classify each request by its complete configured origin and base directory.
$cases = [
 ['https://example.test/staff/', 'https://example.test/public/', 'example.test', '/staff/surveys/', 'https', 'internal'],
 ['https://example.test/staff/', 'https://example.test/public/', 'example.test', '/public/surveys/?__dashboard=x', 'https', 'external'],
 ['https://example.test/', 'https://example.test/public/', 'example.test', '/public/surveys/', 'https', 'external'],
 ['https://example.test/staff/', 'https://example.test/', 'example.test', '/staff/surveys/', 'https', 'internal'],
 ['https://example.test/', 'https://example.test/public/', 'example.test', '/publicity/surveys/', 'https', 'internal'],
 ['https://EXAMPLE.test:443/staff/', 'https://example.test/public/', 'example.TEST', '/staff/surveys/', 'https', 'internal'],
 ['https://example.test/', 'https://example.test:8443/', 'example.test:8443', '/surveys/', 'https', 'external'],
 ['http://example.test/', 'https://example.test/', 'example.test', '/surveys/', 'https', 'external'],
 ['http://example.test/', '', 'example.test:80', '/surveys/', 'http', 'internal'],
 ['https://example.test/', 'https://example.test/public/', 'example.test', '/public', 'https', 'external'],
 ['https://example.test/', 'https://example.test/public/', 'example.test', '/public%2Fsurveys/', 'https', 'external'],
 ['https://example.test/', 'https://example.test/public/', 'example.test', '/staff/../public/surveys/', 'https', 'external'],
 ['https://example.test/', 'https://example.test/public/', 'example.test', '/surveys/?next=/public/', 'https', 'internal'],
];
foreach ($cases as [$internal, $external, $host, $uri, $scheme, $expected]) {
 $GLOBALS['redcap_base_url']=$internal; $GLOBALS['redcap_survey_base_url']=$external;
 setRequestEndpoint($host,$scheme,'spoofed.example'); $_SERVER['REQUEST_URI']=$uri;
 check(callPrivate($module,'get_endpoint')[1]===$expected,'URL components select '.$expected.' for '.$host.$uri);
 foreach (['dashboard'=>'dash', 'report'=>'report'] as $type=>$prefix) {
  foreach (['internal','external','both'] as $selection) {
   $module->saved=["surveyauth_{$prefix}_protected_2"=>'1', "surveyauth_{$prefix}_endpoint_2"=>$selection];
   $policy=callPrivate($module,'loadPublicResourcePolicy',['project_id'=>1,'type'=>$type,'id'=>2]);
   check((bool)$policy['protect']===($selection==='both' || $selection===$expected),"$type applies $selection protection on the matched endpoint");
  }
  $module->saved["surveyauth_{$prefix}_denyexternal_2"]='1';
  $policy=callPrivate($module,'loadPublicResourcePolicy',['project_id'=>1,'type'=>$type,'id'=>2]);
  check((bool)$policy['deny']===($external!=='' && $expected==='external'),"$type denies external access only on the configured external endpoint");
 }
}
$GLOBALS['redcap_base_url']='https://example.test/staff/';
$GLOBALS['redcap_survey_base_url']='https://example.test/public/';
foreach ([['example.test','/staff-other/surveys/'], ['example.test','/unconfigured/'],
 ['example','/staff/surveys/'], ['example.test.evil','/staff/surveys/'],
 ['example.test:8443','/staff/surveys/']] as [$host,$uri]) {
 setRequestEndpoint($host,'https','example.test'); $_SERVER['REQUEST_URI']=$uri;
 $rejected=false;
 try { callPrivate($module,'get_endpoint'); } catch (RuntimeException $e) { $rejected=true; }
 check($rejected,'Unmatched endpoint cannot inherit a potentially unprotected policy');
}
// A client-controlled Host header must not select the internal policy.
$GLOBALS['redcap_base_url']='https://internal.example/';
$GLOBALS['redcap_survey_base_url']='https://external.example/';
setRequestEndpoint('external.example','https','internal.example');
$_SERVER['REQUEST_URI']='/surveys/?__dashboard=fixture';
check(callPrivate($module,'get_endpoint')[1]==='external','HTTP Host spoofing cannot change the trusted endpoint');
$previousScheme=$_SERVER['REQUEST_SCHEME'];$_SERVER['REQUEST_SCHEME']=[];$rejected=false;
try { callPrivate($module,'get_endpoint'); } catch (RuntimeException $e) { $rejected=true; }
$_SERVER['REQUEST_SCHEME']=$previousScheme;
check($rejected,'Malformed request scheme fails closed without URL coercion');

// Access-denied messages are project content, not executable markup.
$module->saved=[
    'surveyauth_dash_protected_2'=>'1',
    'surveyauth_dash_endpoint_2'=>'both',
    'surveyauth_dash_denyexternal_2'=>'1',
    'surveyauth_dash_noaccessmsg'=>'<img src=x onerror="alert(1)">Denied & unsafe',
];
$_GET=['__dashboard'=>'fixture'];
$_SERVER['REQUEST_METHOD']='GET';
$module->exited=false;
ob_start();callPrivate($module,'protectPublicResource',1,'dashboard');$denial=ob_get_clean();
check($module->exited && http_response_code()===403 &&
    str_contains($denial,'&lt;img') && str_contains($denial,'Denied &amp; unsafe') && !str_contains($denial,'<img'),
    'Public-resource denial messages render as escaped text.');
echo "Passed endpoint path, origin, access-policy, and unmatched-request regressions.\n";
ob_end_flush();
