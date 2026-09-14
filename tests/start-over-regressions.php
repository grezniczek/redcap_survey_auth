<?php
// Exercise post-reset restoration with actual module methods and synthetic storage.
ob_start();
require __DIR__.'/metadata-write-regressions.php';
function db_fetch_assoc($q){if(!$q->valid())return null;$row=$q->current();$q->next();return $row;}
$module->framework=new class {
    public $redirects=[], $firstSubmit=null;
    public function query($sql,$params){
        if(str_contains($sql,'JOIN redcap_surveys_participants'))return new ArrayIterator([[
            'project_id'=>87,'survey_id'=>2,'event_id'=>123,'form_name'=>'survey','save_and_return'=>1,
            'participant_id'=>7,'participant_email'=>'',
        ]]);
        check($params===[7,9], 'Reset verification queries only the authorized participant and response');
        return new ArrayIterator([['record'=>'existing','response_id'=>9,'instance'=>2,'first_submit_time'=>$this->firstSubmit]]);
    }
    public function redirectAfterHook($url,$js){check($js,'Reset reload must work after headers are output');$this->redirects[]=$url;}
};
$scope=['project_id'=>87,'survey_id'=>2,'event_id'=>123,'form_name'=>'survey','hash'=>'private',
    'record'=>'existing','response_id'=>9,'instance'=>2];
$values=['auth'=>'1','auth_user'=>'fixture','auth_email'=>'fixture@example.test','auth_fullname'=>'Fixture User','auth_time'=>'2026-09-01 12:34:56'];
$grant=['authentication_values'=>$values,'expires'=>time()+600,'last'=>time()];
$request=['scope'=>$scope,'key'=>'grant','grant'=>$grant,'startover'=>true];
$property=new ReflectionProperty($module,'authorizedSurveyRequest');
function resetFixture($request,$result=['errors'=>[]]){
    global $module,$property,$settings;
    $property->setValue($module,$request);$settings->canwrite=true;
    $module->exited=false;$module->framework->redirects=[];$module->framework->firstSubmit=null;
    REDCap::$writes=[];REDCap::$response=$result;
    $_SESSION=['redcap_survey_auth_v2'=>['logins'=>[],'grants'=>['grant'=>$request['grant']??[]]]];
}
function restore($args=[]){
    global $module;
    ob_start();
    $module->redcap_survey_page_top(...array_replace([87,'existing','survey',123,null,'private',9,2],$args));
    return ob_get_clean();
}
foreach(['none','event','form'] as $repeat){
    Project::$repeat=$repeat;resetFixture($request);restore();
    $expected=$repeat==='none'?['existing'=>[123=>$values]]:
        ['existing'=>['repeat_instances'=>[123=>[$repeat==='event'?'':'survey'=>[2=>$values]]]]];
    check(count(REDCap::$writes)===1 && REDCap::$writes[0][2]===$expected,'Restore only original authentication values in the authorized record/event/instance');
    check(REDCap::$writes[0][16]===false,'Restoration never creates a new record');
    check($module->framework->redirects===['/surveys/?s=private'],'Reload omits Start over to prevent another reset and displays restored values');
}
foreach([null,array_replace($request,['startover'=>false]),array_replace($request,['grant'=>['authentication_values'=>[]]])] as $other){
    resetFixture($other);restore();check(!REDCap::$writes && !$module->framework->redirects,'No restoration without an authorized reset and values');
}
foreach([[0=>88],[1=>'another'],[2=>'other_form'],[3=>124],[5=>'other_hash'],[6=>10],[7=>3]] as $different){
    resetFixture($request);restore($different);check(!REDCap::$writes,'Mismatched hook scope cannot restore values');
}
resetFixture($request);$settings->canwrite=false;restore();check(!REDCap::$writes,'Allow writing off prevents restoration');
foreach([false,null,['errors'=>['synthetic save failure']]] as $response){
    resetFixture($request,$response);$html=restore();
    check(!$module->framework->redirects && $module->exited && !$_SESSION['redcap_survey_auth_v2']['grants'], 'Failed restoration stops rendering and revokes access');
    check(str_contains($html,'could not be restored'),'Failure explains that values were not restored');
}
resetFixture($request);$module->framework->firstSubmit='2026-09-01 12:34:56';restore();
check(!REDCap::$writes && $module->exited,'Restoration requires confirmation that core reset response status');
echo "Passed Start over metadata restoration, scope, write controls, reload, and failure regressions.\n";
ob_end_flush();
