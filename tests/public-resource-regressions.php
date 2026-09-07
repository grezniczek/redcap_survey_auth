<?php
require __DIR__.'/session-regressions.php';
$r=['project_id'=>'1','type'=>'dashboard','id'=>'2','hash'=>'public-hash','title'=>'Title','endpoint'=>'external'];
$key=callPrivate($module,'publicResourceKey',$r);
foreach(['project_id'=>'9','type'=>'report','id'=>'9','hash'=>'other','endpoint'=>'internal'] as $field=>$value) {
 check(callPrivate($module,'publicResourceKey',array_replace($r,[$field=>$value]))!==$key,'Resource grant isolates '.$field);
}
check(str_starts_with($key,'public:'),'Public resources cannot collide with survey grants');
check(callPrivate($module,'publicResourceKey',array_replace($r,['title'=>'Renamed']))===$key,'Display title is not an authorization identifier');
// A legacy daily flag never enters the new grant store.
$_SESSION=['SurveyAuth-'.date('Y-m-d').'-Dashboard-2'=>true];
$state=callPrivate($module,'surveySession');
check($state['grants']===[],'Legacy daily flags confer no authorization');
$grant=['username'=>'user','method'=>'Custom','revision'=>'policy','last'=>time(),'expires'=>time()+600];
$_SESSION['redcap_survey_auth_v2']['grants']=[$key=>array_replace($grant,['expires'=>time()-1])];
$state=callPrivate($module,'surveySession');
check(!$state['grants'],'Absolute expiry removes public resource grants');
check(!method_exists($module,'toSecureBlob') && !method_exists($module,'fromSecureBlob'),'Unauthenticated-IV blob implementation removed');
echo "Passed public resource key, migration, and expiry regressions.\n";
