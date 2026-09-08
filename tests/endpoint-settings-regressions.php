<?php
// Render -> save -> reopen round trips, with in-memory settings and staff-rights fixtures.
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
$module->framework=new class { public function getJavascriptModuleObjectName() { return 'fixture'; } };
$GLOBALS['redcap_base_url']='https://dev-redcap/';
$GLOBALS['redcap_survey_base_url']='https://dev-surveys/';
$_SERVER['REQUEST_SCHEME']='https';
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
        $_SERVER['HTTP_HOST']=$host;
        $policy=callPrivate($module,'loadPublicResourcePolicy',['project_id'=>1,'type'=>$type,'id'=>2]);
        check((bool)$policy['protect']===($endpoint==='both' || $endpoint===$side),"$type protects intended $side origin after save");
    }
 }
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
 $_SERVER['HTTP_HOST']=$host; $_SERVER['REQUEST_URI']=$uri; $_SERVER['REQUEST_SCHEME']=$scheme;
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
 $_SERVER['HTTP_HOST']=$host; $_SERVER['REQUEST_URI']=$uri; $_SERVER['REQUEST_SCHEME']='https';
 $rejected=false;
 try { callPrivate($module,'get_endpoint'); } catch (RuntimeException $e) { $rejected=true; }
 check($rejected,'Unmatched endpoint cannot inherit a potentially unprotected policy');
}
echo "Passed endpoint path, origin, access-policy, and unmatched-request regressions.\n";
