<?php
ob_start();
require __DIR__.'/login-ajax-regressions.php';
invoke($module,'surveySessionReady');
$tabA=['scope'=>['project_id'=>1], 'csrf'=>'session-csrf-a', 'framework_csrf'=>str_repeat('a',80), 'expires'=>time()+600];
$tabB=['scope'=>['project_id'=>1], 'csrf'=>'session-csrf-b', 'framework_csrf'=>str_repeat('b',80), 'expires'=>time()+600];
function tabCsrf($context, $csrf, $token, $logins, $action='survey-login') {
    global $module;
    $_SESSION=['redcap_survey_auth_v2'=>['logins'=>$logins, 'grants'=>[]]];
    $_COOKIE['redcap_external_module_csrf_token']=str_repeat('c',80);
    $_SERVER['REQUEST_METHOD']='POST';
    $_POST=['action'=>$action,'payload'=>json_encode(['context'=>$context,'csrf'=>$csrf]),'redcap_external_module_csrf_token'=>$token];
    invoke($module,'useSessionBoundLoginCsrf');
    return $_COOKIE['redcap_external_module_csrf_token'];
}
foreach (['a'=>$tabA,'b'=>$tabB] as $id=>$tab) {
    check(tabCsrf($id,$tab['csrf'],$tab['framework_csrf'],['a'=>$tabA,'b'=>$tabB])===$tab['framework_csrf'],
        'Either login tab can use its own framework token after another page rotates the shared cookie');
}
foreach ([
    ['a','wrong',$tabA['framework_csrf'],['a'=>$tabA]],
    ['a',$tabA['csrf'],$tabB['framework_csrf'],['a'=>$tabA,'b'=>$tabB]],
    ['missing',$tabA['csrf'],$tabA['framework_csrf'],['a'=>$tabA]],
    ['a',$tabA['csrf'],$tabA['framework_csrf'],[]],
    ['a',$tabA['csrf'],$tabA['framework_csrf'],['a'=>array_replace($tabA,['expires'=>time()-1])]],
    [[], $tabA['csrf'],$tabA['framework_csrf'],['a'=>$tabA]],
    ['a',[], $tabA['framework_csrf'],['a'=>$tabA]],
    ['a',$tabA['csrf'],[],['a'=>$tabA]],
] as $case) {
    check(tabCsrf(...$case)===str_repeat('c',80),'Invalid, expired, consumed, or foreign-session context cannot replace the request cookie');
}
check(tabCsrf('a',$tabA['csrf'],$tabA['framework_csrf'],['a'=>$tabA],'save-report-settings')===str_repeat('c',80),
    'Session-token adaptation applies only to login');
session_destroy();
echo "Passed per-tab login token binding, invalid tokens, expiry, and session-isolation regressions.\n";
ob_end_flush();
