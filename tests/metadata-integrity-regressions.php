<?php
ob_start();
require __DIR__.'/login-ajax-regressions.php';
invoke($module,'surveySessionReady');
$module->allowWriting=true;
REDCap::$dictionary=[['field_name'=>'auth','field_annotation'=>'@SURVEY-AUTH(success=1) @READONLY-SURVEY']];
$scope=invoke($module,'surveyScope',1,'private');
(new ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue(
    $module,new \DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings($module,1));
$key=invoke($module,'surveyScopeKey',$scope);
$values=['auth'=>'1','auth_user'=>'fixture','auth_time'=>'2026-09-14 14:15:16','auth_check'=>['1'=>'1','2'=>'0']];
$grant=['username'=>'fixture','method'=>'Custom','revision'=>invoke($module,'surveyPolicyRevision',$scope),
    'last'=>time(),'expires'=>time()+600,'authentication_values'=>$values];
foreach (['next','previous','submit'] as $action) {
    $_SESSION=['redcap_survey_auth_v2'=>['logins'=>[],'grants'=>[$key=>$grant]]];
    $_GET=['s'=>'private','auth_user'=>'prefill-forgery','auth_check___1'=>'1'];
    $_POST=['__response_hash__'=>'valid-response-hash','submit-action'=>$action,'auth'=>'0',
        'auth_user'=>['forged'],'auth_time'=>'01/01/1900','__chk__auth_check_RC_1'=>'',
        '__chkn__auth_check'=>'on','auth_check___2'=>'1','auth_user____I2'=>'forged-repeat',
        'empty-required-field'=>['auth','auth_check','answer'], 'answer'=>'real answer'];
    $_FILES=['auth_user'=>['tmp_name'=>'synthetic'],'answer_file'=>['tmp_name'=>'synthetic']];
    $_SERVER['REQUEST_METHOD']='POST';$module->exited=false;
    $module->redcap_every_page_before_render(1);
    check(!$module->exited,'Authorized '.$action.' continues');
    check($_POST===['__response_hash__'=>'valid-response-hash','submit-action'=>$action,
        'empty-required-field'=>['answer'],'answer'=>'real answer'],
        'Scalar, array, date, checkbox, repeat-encoded and implicit blank metadata cannot reach core processing');
    check($_GET===['s'=>'private','instance'=>1] && array_keys($_FILES)===['answer_file'],
        'Metadata prefill/upload inputs are removed while routing and answer uploads survive');
    check($_SESSION['redcap_survey_auth_v2']['grants'][$key]['authentication_values']===$values,
        'Original values remain unchanged, including timestamp and checkbox structure');
}
$_GET=['s'=>'private'];$_POST=['submit-action'=>'next','answer'=>'omitted metadata'];$_FILES=[];
$module->redcap_every_page_before_render(1);
check($_POST===['submit-action'=>'next','answer'=>'omitted metadata'],'Omitted metadata is not injected or cleared');
$module->allowWriting=false;
$_POST=['submit-action'=>'next','auth'=>'participant value'];
$settings=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings($module,1);
(new ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->setValue($module,$settings);
invoke($module,'protectAuthenticationFields',$grant);
check($_POST['auth']==='participant value','Writing-disabled requests are unchanged');
$module->allowWriting=true;
$_SESSION['redcap_survey_auth_v2']['grants'][$key]=$grant;
unset($_SESSION['redcap_survey_auth_v2']['grants'][$key]['authentication_values']);
$module->exited=false;ob_start();$module->redcap_every_page_before_render(1);ob_end_clean();
check($module->exited && empty($_SESSION['redcap_survey_auth_v2']['grants']),
    'Old grants without a snapshot require authentication before ordinary saves as well as Start over');
// The filter is called only from the survey gate; staff writes never call it.
$_GET=[];$_POST=['auth'=>'staff correction'];$module->exited=false;
$module->redcap_every_page_before_render(1);
check($_POST['auth']==='staff correction' && !$module->exited,'Non-survey requests are unchanged');
session_destroy();
echo "Passed authentication metadata tampering, checkbox, blanking, prefill, omission, and old-grant regressions.\n";
ob_end_flush();
