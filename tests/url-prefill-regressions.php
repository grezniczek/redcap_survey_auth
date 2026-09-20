<?php
ob_start();
require __DIR__.'/login-ajax-regressions.php';
ob_end_clean();

\REDCap::$dictionary=[
    ['field_name'=>'record_id','field_annotation'=>''],
    ['field_name'=>'auth','field_annotation'=>'@SURVEY-AUTH(success=1,username=auth_user)'],
    ['field_name'=>'auth_user','field_annotation'=>''],
    ['field_name'=>'prefill_text','field_annotation'=>''],
    ['field_name'=>'prefill_check','field_annotation'=>''],
    ['field_name'=>'prefill_calc','field_annotation'=>''],
    ['field_name'=>'later_text','field_annotation'=>''],
];
\Project::$testForms=['survey'=>['fields'=>array_fill_keys([
    'record_id','auth','auth_user','prefill_text','prefill_check','prefill_calc','later_text','survey_complete'
], '')]];
\Project::$testSurveys=[2=>['question_by_section'=>true]];
\Project::$testMetadata=[
    'auth'=>['element_type'=>'text','element_preceding_header'=>'','element_enum'=>''],
    'auth_user'=>['element_type'=>'text','element_preceding_header'=>'','element_enum'=>''],
    'prefill_text'=>['element_type'=>'text','element_preceding_header'=>'','element_enum'=>''],
    'prefill_check'=>['element_type'=>'checkbox','element_preceding_header'=>'','element_enum'=>"1, One\n2, Two"],
    'prefill_calc'=>['element_type'=>'calc','element_preceding_header'=>'','element_enum'=>''],
    'later_text'=>['element_type'=>'text','element_preceding_header'=>'Second page','element_enum'=>''],
];
$module->allowWriting=true;
$settings=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings($module,1);
(new ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue($module,$settings);
$scope=invoke($module,'surveyScope',1,'public');
$dictionary=invoke($module,'getSurveyDataDictionary',1,'survey');
$taggedFields=invoke($module,'getTaggedFields',$dictionary,1,null,3,'survey',1);
$_SERVER['REQUEST_METHOD']='GET';
$_GET=['s'=>'public','auth'=>'forged','auth_user'=>'forged','prefill_text'=>'Jane Doe',
    'prefill_check___1'=>'1','prefill_check___9'=>'1','prefill_calc'=>'4','later_text'=>'later',
    '__page__'=>'1','unknown'=>'ignored','array_value'=>['ignored']];
$prefill=invoke($module,'surveyLoginPrefill',$scope,$taggedFields);
check($prefill===['prefill_text'=>'Jane Doe','prefill_check___1'=>'1'],
    'Only allowlisted first-page fields and valid checkbox options survive login');
check(invoke($module,'appendSurveyLoginPrefill','/surveys/?s=public&__sa_flow=context',$prefill)
    ==='/surveys/?s=public&__sa_flow=context&prefill_text=Jane%20Doe&prefill_check___1=1',
    'Prefill values are RFC3986-encoded when rebuilding the survey URL');
$_GET=['s'=>'public','prefill_text'=>'Jane Doe','__return'=>'1'];
check(invoke($module,'surveyLoginPrefill',$scope,$taggedFields)===[], 'Save & Return requests do not retain URL prefill');
$_GET=['s'=>'public','prefill_text'=>'Jane Doe','__startover'=>'1'];
check(invoke($module,'surveyLoginPrefill',$scope,$taggedFields)===[], 'Start over requests do not retain URL prefill');
$_GET=['s'=>'public','prefill_text'=>'Jane Doe'];
$_SERVER['REQUEST_METHOD']='POST';
check(invoke($module,'surveyLoginPrefill',$scope,$taggedFields)===[], 'POST data is never retained as URL prefill');
$_SERVER['REQUEST_METHOD']='GET';
$scope['first_submit_time']='2026-09-19 10:00:00';
check(invoke($module,'surveyLoginPrefill',$scope,$taggedFields)===[], 'Started responses do not retain URL prefill');

invoke($module,'surveySessionReady');
$payload=loginContext();
$_SESSION['redcap_survey_auth_v2']['logins']['context']['prefill']=$prefill;
$_SERVER['REQUEST_METHOD']='POST';
$login=$_SESSION['redcap_survey_auth_v2']['logins']['context'];
$currentScope=invoke($module,'surveyScope',1,'public');
check(invoke($module,'surveyScopeKey',$login['scope'],'context')===invoke($module,'surveyScopeKey',$currentScope,'context') &&
    hash_equals($login['revision'],invoke($module,'surveyPolicyRevision',$login['scope'])), 'Synthetic prefill login context remains valid');
$result=ajax('survey-login',$payload,1);
check($result['success'] && $result['redirect']==='/surveys/?s=public&__sa_flow=context&prefill_text=Jane%20Doe&prefill_check___1=1',
    'Successful login redirects with the session-bound prefill payload only');
echo "Passed URL prefill allowlist, authentication-field exclusion, and redirect regressions.\n";
