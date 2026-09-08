<?php
// Exercise actual metadata completion and tag parsing; REDCap storage is simulated.
namespace ExternalModules { class AbstractExternalModule {} }
namespace {
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
class REDCap {
    public static $field='auth', $tag='@SURVEY-AUTH(success=1)', $response, $writes=[], $links=[];
    public static function getDataDictionary(...$args) { return json_encode([
        ['field_name'=>'record_id','field_annotation'=>self::$field==='record_id'?self::$tag:''],
        ['field_name'=>'auth','field_annotation'=>self::$field==='auth'?self::$tag:'']]); }
    public static function getRecordIdField(){return 'record_id';}
    public static function saveData(...$args){self::$writes[]=$args;return self::$response;}
    public static function getSurveyLink(...$args){self::$links[]=$args;return 'https://example.test/surveys/?s=private';}
}
class Form {
    public static function replaceIfActionTag($tag,...$args){return $tag;}
    public static function getValueInParenthesesActionTag($tag,$name){return preg_match('/@SURVEY-AUTH\(([^)]*)\)/',$tag,$m)?$m[1]:'';}
}
class Project {
    public static $repeat='none';
    public function __construct($pid){}
    public function isRepeatingEvent($event){return self::$repeat==='event';}
    public function isRepeatingForm($event,$form){return self::$repeat==='form';}
}
class Survey {
    public static function getSurveyId($instrument){return 2;}
    public static function getSurveyHash($survey,$event){return 'public';}
}
define('APP_PATH_SURVEY_FULL','https://example.test/surveys/');
function check($ok,$message){if(!$ok)throw new RuntimeException($message);}
$module=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule();
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->canwrite=true;$settings->errorMsg='Metadata failure';
(new ReflectionProperty($module,'settings'))->setValue($module,$settings);
function complete($record,$response,$write=true){
    global $module;
    REDCap::$writes=REDCap::$links=[];REDCap::$response=$response;
    return (new ReflectionMethod($module,'completeSurveyAuthentication'))->invoke($module,
        ['success'=>true,'error'=>null,'log_error'=>[],'username'=>'fixture'],87,'survey',123,2,$record,$write);
}
foreach([null,'existing'] as $record){
    foreach([false,null,['errors'=>['fixture validation error']],['errors'=>['fixture error'],'ids'=>['NEW'=>'42']]] as $response){
        $r=complete($record,$response);
        check(!$r['success'] && $r['error']==='Metadata failure' && !empty($r['log_error']),'Save failure must reject completion and report a safe error');
        check(count(REDCap::$writes)===1 && !REDCap::$links && !isset($r['targetUrl']),'Failed save must not generate a redirect');
    }
}
foreach([['errors'=>[]],['errors'=>[],'ids'=>[]],['errors'=>[],'ids'=>['NEW'=>null]]] as $response){
    $r=complete(null,$response);
    check(!$r['success'] && !isset($r['targetUrl']) && !REDCap::$links,'Missing new record ID must fail closed');
}
foreach(['none','event','form'] as $repeat){
    Project::$repeat=$repeat;
    foreach([null,'existing'] as $record){
        $r=complete($record,['errors'=>[],'ids'=>['NEW'=>'42']]);
        $savedRecord=$record??'NEW';$values=['auth'=>'1'];
        $expected=$repeat==='none'?[$savedRecord=>[123=>$values]]:
            [$savedRecord=>['repeat_instances'=>[123=>[$repeat==='event'?'':'survey'=>[2=>$values]]]]];
        check($r['success'] && count(REDCap::$writes)===1,'Success-only tag must save once without other mappings');
        check(REDCap::$writes[0][0]===87 && REDCap::$writes[0][2]===$expected,'Metadata targets only the intended record, event, instrument and repeat instance');
        check($r['record']===($record??'42') && REDCap::$links[0][0]===($record??'42'),'New records use the confirmed returned ID; existing records retain their ID');
    }
}
Project::$repeat='none';
foreach([false,true] as $allow){
    $settings->canwrite=$allow;
    $r=complete('existing',false,false);
    check($r['success'] && !REDCap::$writes,'Return-entry authentication defers metadata even if writing is allowed');
}
$settings->canwrite=false;$r=complete(null,false);
check($r['success'] && $r['record']===null && !REDCap::$writes,'Allow writing disabled does not create a record');
$settings->canwrite=true;REDCap::$field='record_id';$r=complete('existing',false);
check($r['success'] && !REDCap::$writes,'Success assignment cannot overwrite the record ID');
REDCap::$field='auth';REDCap::$tag='@SURVEY-AUTH';$r=complete('existing',false);
check($r['success'] && !REDCap::$writes,'Bare tag requires no metadata write');
echo "Passed metadata-save failures, success-only writes, response scope, and writing controls.\n";
}
