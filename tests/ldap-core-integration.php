<?php
// Unmodified tagged REDCap sources + disposable OpenLDAP. See fixtures/ldap-live/README.md.
namespace ExternalModules { class AbstractExternalModule { public $framework; } }
namespace {
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
define('APP_PATH_DOCROOT', rtrim($argv[1], '/').'/');
define('APP_PATH_WEBTOOLS', __DIR__.'/fixtures/');
require APP_PATH_DOCROOT.'helpers.php';
class Session { static function init() { throw new RuntimeException('Staff session initialization attempted'); } }
class FakeLDAP { public static $redcapConfigs=[]; }
function check($ok,$label) { if (!$ok) throw new RuntimeException($label); echo 'PASS '.$label."\n"; }
$module=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule();
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->fallbackToTableUserInfo=false;
$settings->ldapMappings=['fullname'=>['cn'],'email'=>['mail'],'firstname'=>['givenname'],'lastname'=>['sn']];
(new ReflectionProperty($module,'settings'))->setValue($module,$settings);
$base=['url'=>'ldap://127.0.0.1','port'=>636,'version'=>3,'start_tls'=>true,'referrals'=>false,
    'binddn'=>'cn=admin,dc=test','bindpw'=>'fixture-admin','basedn'=>'dc=test','userattr'=>'uid',
    'userfilter'=>'(objectClass=inetOrgPerson)','attributes'=>[]];
$module->framework=new class {
    public $queries=[];
    function query($sql,$params) {
        $this->queries[]=$params;
        return new class { function fetch_assoc() { return ['user_email'=>'fallback@example.test','user_firstname'=>'Fallback','user_lastname'=>'Name']; } };
    }
};
$_SESSION=['survey'=>'unchanged']; $_POST=['sentinel'=>'post']; $_COOKIE=['sentinel'=>'cookie'];
$state=[$_SESSION,$_POST,$_COOKIE];
$includePath=get_include_path();
function attempt($username='alice',$password='fixture-password',$changes=[]) {
    global $module,$base;
    $config=array_replace($base,$changes);
    if (array_key_exists('version',$changes) && $changes['version']===null) unset($config['version']);
    FakeLDAP::$redcapConfigs=$config;
    $result=['success'=>false,'log_error'=>[]];
    (new ReflectionMethod($module,'authenticateLDAP'))->invokeArgs($module,[$username,$password,&$result]);
    return $result;
}
if (($argv[2] ?? '')==='untrusted') {
    $r=attempt();
    check(!$r['success'] && count($r['log_error'])===1,'Untrusted certificate rejects authentication');
    $details=json_decode(substr($r['log_error'][0],strlen('REDCap LDAP error: ')),true,512,JSON_THROW_ON_ERROR);
    check($details['stage']==='StartTLS' && !empty($details['warnings']),'TLS failure retains stage and native warnings');
    check(!str_contains(json_encode($r),'fixture-admin') && !str_contains(json_encode($r),'fixture-password'),
        'TLS diagnostics exclude credentials');
    exit;
}
$r=attempt();
check($r['success'] && $r['method']==='LDAP' && $r['fullname']==='Alice Directory' && $r['email']==='alice@example.test',
    'Core driver ignores separate port and maps accepted identity');
check(!str_contains(json_encode($r),'userPassword') && !str_contains(json_encode($r),'fixture-password'),'Raw LDAP password attributes are discarded');
check(attempt('alice','fixture-password',['host'=>'ldap://127.0.0.1:1389','url'=>'ldap://127.0.0.1:9'])['success'],
    'Core host precedence is preserved');
check(attempt('alice','fixture-password',['url'=>'ldap://127.0.0.1:1389','port'=>636])['success'],'Explicit URL port is preserved');
check(attempt('alice','fixture-password',['url'=>'ldaps://127.0.0.1','port'=>389,'start_tls'=>false])['success'],'LDAPS uses core scheme default');
foreach (['AUTH','LDAP'] as $format) {
    $r=attempt('alice','fixture-password',['attrformat'=>$format]);
    check($r['success'] && $r['email']==='alice@example.test' && $r['fullname']==='Alice Directory','Accepted identity from '.$format.' attribute format');
}
foreach ([['alice','wrong'],['alice',''],['*','fixture-password'],['alice',"fixture-\0password"],["ali\0ce",'fixture-password']] as [$user,$password]) {
    $r=attempt($user,$password);
    check(!$r['success'] && !$r['log_error'] && !isset($r['email']),'Invalid credentials denied without technical errors or identity');
}
check(attempt('jörg')['success'],'UTF-8 username authenticates');
check(attempt('star*user')['success'],'Literal filter metacharacter authenticates');
$r=attempt('Retry User','fixture-password',['userattr'=>'cn','try_all'=>true]);
check(!$r['success'] && !$r['log_error'] && !isset($r['email']),'Core try_all limitation and denied-candidate isolation are preserved');
check(attempt('retry-second')['success'],'The later matching entry has independently valid credentials');
check(attempt('alice','fixture-password',['group'=>'allowed'])['success'],'Group member accepted');
$r=attempt('jörg','fixture-password',['group'=>'allowed']);
check(!$r['success'] && !$r['log_error'] && !isset($r['email']),'Group denial discards staged identity');
foreach ([null,2,'2','invalid'] as $version) {
    $r=attempt('alice','fixture-password',['version'=>$version]);
    $details=json_decode(substr($r['log_error'][0],strlen('REDCap LDAP error: ')),true,512,JSON_THROW_ON_ERROR);
    check(!$r['success'] && $details['stage']==='configuration' && $details['endpoint']===null,
        'Incompatible or omitted StartTLS protocol rejected before connection');
}
$r=attempt('alice','fixture-password',['bindpw'=>'wrong']);
check(!$r['success'] && count($r['log_error'])===1 && str_contains($r['log_error'][0],'service bind'),
    'PEAR service-bind error is technical failure, never truthy success');
check(!str_contains($r['log_error'][0],'fixture-password') && !str_contains($r['log_error'][0],'cn=admin,dc=test'),
    'Service-bind diagnostics redact submitted password and bind identity');
$r=attempt('alice','fixture-password',['userfilter'=>'(']);
check(!$r['success'] && str_contains(join('',$r['log_error']),'user search'),'Failed search is logged as a technical error');
$modern=version_compare(basename(rtrim($argv[1],'/')),'17.5.6','>=');
$r=attempt('alice','fixture-password',['basedn'=>'']);
check($r['success']===$modern,'Base DN discovery retains installed-driver behavior');
$settings->fallbackToTableUserInfo=true;
$module->framework->queries=[];
attempt('alice','wrong');
check(!$module->framework->queries,'Failed password never queries table attributes');
$r=attempt('alice','fixture-password',['attributes'=>['sn']]);
check($r['success'] && $r['fullname']==='Directory' && $r['email']==='fallback@example.test' &&
    $module->framework->queries===[['alice']],'Fallback fills missing attributes only after acceptance');
$settings->fallbackToTableUserInfo=false;
FakeLDAP::$redcapConfigs=[array_replace($base,['group'=>'not-allowed']),$base,array_replace($base,['url'=>'ldap://127.0.0.1:9'])];
$r=['success'=>false,'log_error'=>[]];
(new ReflectionMethod($module,'authenticateLDAP'))->invokeArgs($module,['alice','fixture-password',&$r]);
check($r['success'] && !$r['log_error'] && $r['email']==='alice@example.test','Directory order, denial isolation, and first accepted directory are preserved');
check([$_SESSION,$_POST,$_COOKIE]===$state,'No staff session, POST, or cookie side effects');
check(get_include_path()===$includePath,'Core dependency loading restores the include path');
echo 'Passed installed-core LDAP adapter integration for '.basename($argv[1]).".\n";
}
