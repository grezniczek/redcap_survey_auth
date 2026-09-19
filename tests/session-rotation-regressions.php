<?php
namespace DE\RUB\SurveyAuthExternalModule {
    function session_regenerate_id($deleteOld) {
        if (($GLOBALS['rotation_failure'] ?? '') === 'false') return false;
        if (($GLOBALS['rotation_failure'] ?? '') === 'unchanged') return true;
        return \session_regenerate_id($deleteOld);
    }
}
namespace {
ob_start();
require __DIR__.'/login-ajax-regressions.php';
$module->allowWriting=false;
foreach (['survey','dashboard','report'] as $type) {
    invoke($module,'surveySessionReady');
    $payload=loginContext($type);
    $_SESSION['core_survey_marker']='preserved';
    $_SESSION['redcap_survey_auth_v2']['logins']['other']=$_SESSION['redcap_survey_auth_v2']['logins']['context'];
    $old=session_id();
    // Persist a real anonymous session, then resume it as a request would.
    session_write_close(); session_id($old); invoke($module,'surveySessionReady');
    $_SERVER['REQUEST_METHOD']='POST';
    $result=ajax('survey-login',$payload,1);
    $renewed=session_id();
    check($result['success'] && $renewed!==$old,'Successful '.$type.' authentication rotates the ID');
    check($_SESSION['core_survey_marker']==='preserved' && isset($_SESSION['redcap_survey_auth_v2']['logins']['other']),
        'Core state and other pending login contexts survive rotation');
    session_write_close();
    check(!is_file(session_save_path().'/sess_'.$old),'Old session storage is removed');
    session_id($old); invoke($module,'surveySessionReady');
    check(empty($_SESSION['redcap_survey_auth_v2']['grants']),'Replaying the pre-login cookie has no authorization');
    session_destroy(); session_id($renewed); invoke($module,'surveySessionReady');
    check(count($_SESSION['redcap_survey_auth_v2']['grants'])===1,'New cookie resumes the authenticated grant');
    $other=array_replace($payload,['context'=>'other']);
    check(ajax('survey-login',$other,1)['success'],'Another pre-opened login context still authenticates after rotation');
    session_destroy();
}
foreach (['false','unchanged'] as $failure) {
    $GLOBALS['rotation_failure']=$failure;
    foreach (['survey','dashboard','report'] as $type) {
        invoke($module,'surveySessionReady');$payload=loginContext($type);
        $result=ajax('survey-login',$payload,1);
        check(!$result['success'] && !isset($result['redirect']) && !$_SESSION['redcap_survey_auth_v2']['grants'],
            'Failed or ineffective rotation cannot grant access for '.$type);
        session_destroy();
    }
}
unset($GLOBALS['rotation_failure']);
foreach (['survey','dashboard','report'] as $type) {
    invoke($module,'surveySessionReady');$payload=loginContext($type);
    $settings=(new \ReflectionProperty(\DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule::class,'settings'))->getValue($module);
    $legacyPolicy=get_object_vars($settings);
    unset($legacyPolicy['lockoutStatus'],$legacyPolicy['blobSecret'],$legacyPolicy['blobHmac']);
    // Frozen pre-upgrade revision format, which had no policy-version prefix.
    $legacyRevision=hash('sha256',json_encode($legacyPolicy).($type==='survey'?REDCap::getDataDictionary():''));
    $login=$_SESSION['redcap_survey_auth_v2']['logins']['context'];
    check($login['revision']!==$legacyRevision,'Security upgrade changes the policy revision for '.$type);
    $_SESSION['redcap_survey_auth_v2']['logins']['context']['revision']=$legacyRevision;
    check(!ajax('survey-login',$payload,1)['success'],'Pre-upgrade login context must be reopened');
    $key=$type==='survey'?invoke($module,'surveyScopeKey',$login['scope'],'old-flow'):
        invoke($module,'publicResourceKey',$login['resource']);
    $_SESSION['redcap_survey_auth_v2']['grants'][$key]=['username'=>'fixture','method'=>'Custom',
        'revision'=>$legacyRevision,'last'=>time(),'expires'=>time()+600];
    $_GET=$type==='survey'?['s'=>'public','__sa_flow'=>'old-flow']:['__'.$type=>'resource-hash'];
    $_POST=[];$_SERVER['REQUEST_METHOD']='GET';$module->exited=false;
    ob_start();$module->redcap_every_page_before_render(1);ob_end_clean();
    check($module->exited && !isset($_SESSION['redcap_survey_auth_v2']['grants'][$key]),
        'Pre-upgrade authorization requires reauthentication for '.$type);
    $_SERVER['REQUEST_METHOD']='POST';session_destroy();
}
echo "Passed session rotation, old-cookie rejection, retained contexts, and rotation-failure regressions.\n";
ob_end_flush();
}
