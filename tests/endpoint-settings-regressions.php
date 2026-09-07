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
