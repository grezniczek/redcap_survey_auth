<?php
// Real PHP LDAP extension and disposable OpenLDAP; see fixtures/ldap-live/README.md.
namespace ExternalModules { class AbstractExternalModule { public $framework; } }
namespace {
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
$module=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule();
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->fallbackToTableUserInfo=false;
$settings->ldapMappings=['fullname'=>[], 'firstname'=>['givenname'], 'lastname'=>['sn'], 'email'=>['mail']];
(new ReflectionProperty($module,'settings'))->setValue($module,$settings);
$base=['url'=>'ldap://127.0.0.1:1389','port'=>1389,'version'=>3,'start_tls'=>true,'referrals'=>false,
 'binddn'=>'cn=admin,dc=test','bindpw'=>'fixture-admin','basedn'=>'dc=test','userattr'=>'uid',
 'userfilter'=>'(objectClass=inetOrgPerson)','attributes'=>[]];
$failures=0;
function check($ok,$label){global $failures;echo ($ok?'PASS ':'FAIL ').$label."\n";if(!$ok)$failures++;}
function attempt($user,$password='fixture-password',$changes=[]){
 global $module,$base;
 $result=['success'=>false,'log_error'=>[]];
 (new ReflectionMethod($module,'doLDAPauth'))->invokeArgs($module,[$user,$password,array_replace($base,$changes),&$result]);
 return $result;
}
$r=attempt('alice');check($r['success'] && $r['email']==='alice@example.test','StartTLS login and email mapping');
check($r['fullname']==='Alice Directory','LDAP attribute names match case-insensitively');
check(!attempt('alice','wrong')['success'],'Incorrect password denied');
check(!attempt('alice','')['success'],'Empty password denied');
check(attempt('alice','fixture-password',['group'=>'allowed'])['success'],'Group member accepted');
check(!attempt('jörg','fixture-password',['group'=>'allowed'])['success'],'Non-member denied');
check(attempt('jörg')['success'],'UTF-8 username authenticates without double encoding');
check(attempt('star*user')['success'],'Literal filter metacharacter authenticates');
check(!attempt('*')['success'],'Wildcard username cannot select another entry');
check(!attempt('alice','fixture-password',['bindpw'=>'wrong'])['success'],'Failed service bind denied');
$settings->fallbackToTableUserInfo=true;
$module->framework=new class {
 public $calls=0;
 public function query($sql,$params){
  $this->calls++;
  return new class { public function fetch_assoc(){return ['user_email'=>'fallback@example.test','user_firstname'=>'Fallback','user_lastname'=>'Name'];} };
 }
};
$r=attempt('star*user');check($r['success'] && $r['email']==='fallback@example.test' && $r['fullname']==='Star','Fallback fills only missing attributes');
$before=$module->framework->calls;attempt('star*user','wrong');check($module->framework->calls===$before,'Failed bind does not read fallback identity');
exit($failures?1:0);
}
