<?php
// File access requires SurveyAuth; file ownership and storage remain REDCap's responsibility.
require __DIR__.'/session-regressions.php';
$scope=['project_id'=>1,'survey_id'=>2,'event_id'=>3,'form_name'=>'survey','hash'=>'public','record'=>null,'instance'=>1];
$settings->useWhitelist=false;
$grant=['username'=>'user','method'=>'Custom','revision'=>'policy','last'=>time(),'expires'=>time()+600,
    'public_file_scope'=>callPrivate($module,'surveyScopeKey',$scope)];
$grants=['tab-a'=>$grant];
foreach (['DataEntry/file_upload.php','DataEntry/file_download.php','DataEntry/file_delete.php','DataEntry/image_view.php','Design/file_attachment_upload.php'] as $route) {
    $_GET=['__passthru'=>urlencode($route)];
    check(callPrivate($module,'publicSurveyFileGrantKey',$scope,$grants,'policy')==='tab-a','Native file request can use this public survey grant: '.$route);
}
$_GET=[];
check(callPrivate($module,'publicSurveyFileGrantKey',$scope,$grants,'policy')===null,'Answer submissions cannot use file grant fallback');
$_GET=['__passthru'=>'DataEntry/file_upload.php'];
foreach (['project_id'=>9,'survey_id'=>9,'event_id'=>9,'hash'=>'other','record'=>'12','instance'=>2] as $key=>$value) {
    check(callPrivate($module,'publicSurveyFileGrantKey',array_replace($scope,[$key=>$value]),$grants,'policy')===null,'Grant cannot cross '.$key);
}
check(callPrivate($module,'publicSurveyFileGrantKey',$scope,$grants,'changed-policy')===null,'Changed policy rejects file fallback');
$returnGrant=$grant; unset($returnGrant['public_file_scope']); $returnGrant['purpose']='return';
check(callPrivate($module,'publicSurveyFileGrantKey',$scope,['return'=>$returnGrant],'policy')===null,'Return-entry login cannot authorize file requests');
$_SESSION['redcap_survey_auth_v2']=['logins'=>[], 'grants'=>['expired'=>array_replace($grant,['last'=>time()-1801])]];
$pruned=callPrivate($module,'surveySession');
check(callPrivate($module,'publicSurveyFileGrantKey',$scope,$pruned['grants'],'policy')===null,'Expired session grants cannot authorize files');
$settings->useWhitelist=true; $settings->whitelist=[];
check(callPrivate($module,'publicSurveyFileGrantKey',$scope,$grants,'policy')===null,'Revoked identity cannot authorize files');
$settings->useWhitelist=false;
$_SESSION['redcap_survey_auth_v2']['grants']=['tab-a'=>$grant];
setPrivate($module,'authorizedSurveyRequest',['scope'=>$scope,'key'=>'tab-a','flow'=>'a','grant'=>$grant]);
$module->redcap_save_record(1,'12','survey',3,null,'public',100,1);
$bound=$_SESSION['redcap_survey_auth_v2']['grants'];
check(count($bound)===1 && !isset(array_values($bound)[0]['public_file_scope']),'Saving consumes public file access and retains only the private grant');
echo "Passed native file authorization regressions.\n";
