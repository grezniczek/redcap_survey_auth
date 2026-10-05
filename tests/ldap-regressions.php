<?php
// Run with php -n tests/ldap-regressions.php: fake LDAP transport, no network or credentials.
namespace DE\RUB\SurveyAuthExternalModule {
    function extension_loaded($name) { return $name === 'ldap' || \extension_loaded($name); }
}
namespace {
if (extension_loaded('ldap')) throw new RuntimeException('Run this isolated transport test with php -n.');
require __DIR__.'/session-regressions.php';
define('APP_PATH_WEBTOOLS',__DIR__.'/fixtures/');
define('LDAP_OPT_DIAGNOSTIC_MESSAGE',50);
define('LDAP_OPT_PROTOCOL_VERSION',17); define('LDAP_OPT_REFERRALS',8);
class FakeLDAP {
    public static $servers=[], $redcapConfigs=[], $calls=[], $results=[], $closed=[];
    public static $errno=49, $diagnostic='directory diagnostic';
    public static $tableSuccess=false, $transport=[], $optionSuccess=true, $tlsSuccess=true;
    public static function reset() { self::$calls=self::$results=self::$closed=self::$transport=[]; }
    public static function result($entries) { $r=(object)['entries'=>$entries,'freed'=>false];self::$results[]=$r;return $r; }
}
function ldap_connect($url) { FakeLDAP::$calls[]=$url;return (object)['url'=>$url]; }
function ldap_set_option($ldap,$option,$value) { FakeLDAP::$transport[]=['option',$option,$value]; return FakeLDAP::$optionSuccess; }
function ldap_start_tls($ldap) {
    FakeLDAP::$transport[]=['tls'];
    if (!FakeLDAP::$tlsSuccess) {
        // Simulate the native E_WARNING callback, including credentials in a diagnostic.
        $handler=set_error_handler(static fn()=>false);restore_error_handler();
        $handler(E_WARNING,'ldap_start_tls(): Certificate verification failed for user with correct',__FILE__,__LINE__);
    }
    return FakeLDAP::$tlsSuccess;
}
function ldap_get_option($ldap,$option,&$value) { $value=FakeLDAP::$diagnostic; return true; }
function ldap_errno($ldap) { return FakeLDAP::$errno; }
function ldap_error($ldap) { return FakeLDAP::$errno===49 ? 'Invalid credentials' : 'Cannot contact LDAP server'; }
function ldap_bind($ldap,$dn=null,$password=null) {
    FakeLDAP::$transport[]=['bind'];
    if (!empty(FakeLDAP::$servers[$ldap->url]['service_failure'])) return false;
    if ($dn==='cn=private-service,dc=test') return true;
    if ($dn===null) return true;
    return $password==='correct' && in_array($dn,FakeLDAP::$servers[$ldap->url]['accept']??[],true);
}
function ldap_search($ldap,$base,$filter,$attributes) {
    $s=FakeLDAP::$servers[$ldap->url];
    if (!empty($s[str_contains($filter,'cn=allowed') ? 'group_failure' : 'search_failure'])) return false;
    return FakeLDAP::result(str_contains($filter,'cn=allowed') ? ($s['group']??[]) : $s['entries']);
}
function ldap_list(...$args) { return ldap_search(...$args); }
function ldap_read($ldap,$dn,$filter,$attributes) { return FakeLDAP::result(FakeLDAP::$servers[$ldap->url]['read']??[]); }
function ldap_count_entries($ldap,$r) { check(!$r->freed,'LDAP result remains live'); return count($r->entries); }
function ldap_first_entry($ldap,$r) { check(!$r->freed,'No access after free');return $r->entries ? (object)['r'=>$r,'i'=>0] : false; }
function ldap_next_entry($ldap,$e) { check(!$e->r->freed,'Failed bind must not advance a freed result');return isset($e->r->entries[$e->i+1]) ? (object)['r'=>$e->r,'i'=>$e->i+1] : false; }
function ldap_get_dn($ldap,$e) { return $e->r->entries[$e->i]['dn']; }
function ldap_get_attributes($ldap,$e) { return $e->r->entries[$e->i]['attrs']??[]; }
function ldap_free_result($r) { check(!$r->freed,'Results freed only once');$r->freed=true;return true; }
function ldap_unbind($ldap) { check(!in_array($ldap,FakeLDAP::$closed,true),'Connection closed only once');FakeLDAP::$closed[]=$ldap;return true; }
class User {
    public static function getUserInfo($user) { return ['user_suspended_time'=>null,'user_email'=>'table@example.test','user_firstname'=>'Table','user_lastname'=>'User']; }
}
class Authentication {
    public static function verifyTableUsernamePassword($user,$password) { FakeLDAP::$calls[]='Table'; return FakeLDAP::$tableSuccess; }
}
function config($host,$group='') { return ['url'=>'ldap://'.$host,'host'=>$host,'port'=>389,'basedn'=>'dc=test','group'=>$group]; }
function entry($dn,$name='',$email='') { return ['dn'=>$dn,'attrs'=>['cn'=>['count'=>1,0=>$name],'mail'=>['count'=>1,0=>$email]]]; }
function runBackends() {
    global $module;
    FakeLDAP::reset();$r=['success'=>false,'log_error'=>[]];
    (new ReflectionMethod($module,'authenticateBackends'))->invokeArgs($module,['user','correct',&$r]);
    foreach(FakeLDAP::$results as $handle) check($handle->freed,'All LDAP results are released');
    check(count(FakeLDAP::$closed)===count(array_filter(FakeLDAP::$calls,fn($v)=>$v!=='Table')),'All connections are closed');
    return $r;
}
$settings->useCustom=true;$settings->useTable=true;$settings->useOtherLDAP=true;$settings->useLDAP=true;
$settings->customCredentials=['user'=>'correct'];$settings->fallbackToTableUserInfo=false;
$settings->ldapMappings=['fullname'=>['cn'],'email'=>['mail'],'firstname'=>[],'lastname'=>[]];
$settings->otherLDAPConfigs=[config('other')];FakeLDAP::$redcapConfigs=[config('redcap')];
FakeLDAP::$servers=['ldap://other:389'=>['entries'=>[entry('other','Other','other@example.test')],'accept'=>['other']],
    'ldap://redcap:389'=>['entries'=>[entry('redcap','REDCap','redcap@example.test')],'accept'=>['redcap']]];
$ldapConnectionUri = new ReflectionMethod($module, 'ldapConnectionUri');
check($ldapConnectionUri->invoke($module, config('other')) === 'ldap://other:389',
    'Configured LDAP port is encoded in the one-argument connection URI');
check($ldapConnectionUri->invoke($module, array_replace(config('other'), ['url'=>'ldaps://other:636'])) === 'ldaps://other:636',
    'An explicit LDAP URI port remains authoritative');
check($ldapConnectionUri->invoke($module, array_replace(config('other'), ['url'=>'ldaps://other/dc=test?uid?sub','port'=>1636])) === 'ldaps://other:1636/dc=test?uid?sub',
    'LDAP URI path and query survive port encoding');
$r=runBackends();check($r['method']==='Custom' && !FakeLDAP::$calls,'Custom succeeds before any other backend');
$settings->customCredentials=[];FakeLDAP::$tableSuccess=true;
$r=runBackends();check($r['method']==='Table' && FakeLDAP::$calls===['Table'],'Table precedes both LDAP sources');
FakeLDAP::$tableSuccess=false;
$r=runBackends();check(str_starts_with($r['method'],'Other LDAP') && $r['email']==='other@example.test' && FakeLDAP::$calls===['Table','ldap://other:389'],'Other LDAP wins before REDCap LDAP');
FakeLDAP::$servers['ldap://other:389']['accept']=[];
$r=runBackends();check($r['method']==='LDAP' && $r['email']==='redcap@example.test' && FakeLDAP::$calls===['Table','ldap://other:389','ldap://redcap:389'],'Failed Other LDAP falls through to REDCap');
$settings->useTable=$settings->useOtherLDAP=false;
FakeLDAP::$redcapConfigs=[config('bad'),config('good'),config('late')];
FakeLDAP::$servers['ldap://bad:389']=['entries'=>[entry('bad','Wrong','wrong@example.test')],'accept'=>[]];
FakeLDAP::$servers['ldap://good:389']=['entries'=>[entry('good')],'accept'=>['good']];
$r=runBackends();check($r['success'] && $r['fullname']==='' && $r['email']==='' && FakeLDAP::$calls===['ldap://bad:389','ldap://good:389'],'Rejected directory attributes cannot leak and first accepted directory stops iteration');
FakeLDAP::$redcapConfigs=[config('multi')];
FakeLDAP::$servers['ldap://multi:389']=['entries'=>[entry('bad','Wrong','wrong@example.test'),entry('good')],'accept'=>['good'],
    'read'=>[entry('unrelated','Unrelated','unrelated@example.test'),entry('good','Accepted','accepted@example.test')]];
$r=runBackends();check($r['success'] && $r['fullname']==='Accepted' && $r['email']==='accepted@example.test','Failed entry can advance safely; user-bound attributes must match the accepted DN');
FakeLDAP::$redcapConfigs=[config('multi','allowed')];
$r=runBackends();check(!$r['success'] && !isset($r['email']),'Group rejection publishes no identity and releases group results');
$settings->fallbackToTableUserInfo=true;
$module->framework=new class {
    public $queries=[];
    public function query($sql,$params) {
        $this->queries[]=$params;
        return new class { public function fetch_assoc() { return ['user_email'=>'fallback@example.test','user_firstname'=>'Fallback','user_lastname'=>'User']; } };
    }
};
FakeLDAP::$redcapConfigs=[config('bad')];
$r=runBackends();check(!$r['success'] && !$module->framework->queries,'Table attributes are not queried for a failed LDAP bind');
FakeLDAP::$redcapConfigs=[config('good')];
$r=runBackends();check($r['success'] && $r['fullname']==='Fallback User' && $r['email']==='fallback@example.test' && $module->framework->queries===[['user']],'Fallback uses the authenticated username and fills missing attributes');
$settings->fallbackToTableUserInfo=false;
$r=['success'=>true,'email'=>'stale','fullname'=>'stale','log_error'=>[]];FakeLDAP::reset();
(new ReflectionMethod($module,'doLDAPauth'))->invokeArgs($module,['user','',config('multi'),&$r]);
check(!$r['success'] && $r['email']===null && $r['fullname']===null && !FakeLDAP::$calls,'Empty passwords cannot bind anonymously or preserve prior success');
// Requested encryption must be negotiated before either service or user bind.
foreach ([[], ['version'=>3], ['version'=>'3']] as $version) {
    FakeLDAP::reset();$r=['success'=>false,'log_error'=>[]];
    $cfg=array_replace(config('good'),['start_tls'=>true],$version);
    (new ReflectionMethod($module,'doLDAPauth'))->invokeArgs($module,['user','correct',$cfg,&$r]);
    check($r['success'],'Valid StartTLS configuration authenticates, including an omitted protocol version');
    check(FakeLDAP::$transport[0]===['option',LDAP_OPT_PROTOCOL_VERSION,3] && FakeLDAP::$transport[1]===['tls'] && FakeLDAP::$transport[2]===['option',LDAP_OPT_REFERRALS,true],
        'Protocol 3 and TLS precede binds');
}
foreach ([['version'=>2], ['version'=>'invalid'], ['start_tls'=>'false'], ['version'=>3,'option_failure'=>true], ['version'=>3,'tls_failure'=>true]] as $changes) {
    FakeLDAP::reset();$r=['success'=>false,'log_error'=>[]];
    FakeLDAP::$optionSuccess=empty($changes['option_failure']);FakeLDAP::$tlsSuccess=empty($changes['tls_failure']);
    $cfg=array_replace(config('good'),['start_tls'=>true],$changes);
    (new ReflectionMethod($module,'doLDAPauth'))->invokeArgs($module,['user','correct',$cfg,&$r]);
    check(!$r['success'] && !empty($r['log_error']) && !in_array(['bind'],FakeLDAP::$transport,true),
        'Invalid protocol, TLS configuration, option failure or failed TLS never sends bind credentials');
}
FakeLDAP::$optionSuccess=FakeLDAP::$tlsSuccess=true;
// LDAP diagnostics distinguish operational errors from rejected credentials.
$module->framework=new class {
 public $logs=[];
 public function log($message,$parameters) { $this->logs[]=[$message,$parameters]; }
};
FakeLDAP::$errno=-1;
$bindSecret='BIND_PASSWORD_DO_NOT_LOG';$bindDn='cn=private-service,dc=test';
FakeLDAP::$diagnostic='TLS/connection failure for user with correct '.$bindSecret.' '.$bindDn;
foreach (['StartTLS','service bind','user search','user bind','group membership search'] as $stage) {
 FakeLDAP::reset();FakeLDAP::$tlsSuccess=$stage!=='StartTLS';
 FakeLDAP::$servers['ldap://diagnostics.test:389']=['entries'=>[entry('good')],
  'accept'=>$stage==='user bind' ? [$bindDn] : ['good',$bindDn],
  'service_failure'=>$stage==='service bind', 'search_failure'=>$stage==='user search',
  'group_failure'=>$stage==='group membership search'];
 $cfg=array_replace(config('diagnostics.test',$stage==='group membership search'?'allowed':''),
  ['start_tls'=>$stage==='StartTLS','binddn'=>$bindDn,'bindpw'=>$bindSecret]);
 $r=['success'=>false,'log_error'=>[]];
 (new ReflectionMethod($module,'doLDAPauth'))->invokeArgs($module,['user','correct',$cfg,&$r]);
 check(!$r['success'] && count($r['log_error'])===1,'Each operational failure returns technical diagnostics');
 $detail=$r['log_error'][0];
 // The supplied username is also a substring of two stage labels; compare the redacted label.
 $expectedStage=callPrivate($module,'redactDiagnostic',$stage);
 $parsed=json_decode(substr($detail,strlen('LDAP error: ')),true,512,JSON_THROW_ON_ERROR);
 check($parsed['stage']===$expectedStage && $parsed['endpoint']==='ldap://diagnostics.test:389' &&
  $parsed['ldap_errno']===-1 && str_contains($parsed['ldap_diagnostic'],'TLS/connection failure'),
  'LDAP diagnostics identify stage, effective endpoint, code, and server diagnostic');
 if ($stage==='StartTLS') check(str_contains($parsed['warnings'][0]['message'],'Certificate verification failed') &&
  !str_contains($parsed['warnings'][0]['message'],'correct'),'LDAP warnings are captured and redacted');
 foreach (['correct',$bindSecret,$bindDn] as $secret) {
  check(!str_contains($detail,$secret),'LDAP diagnostics exclude submitted and configured credentials');
 }
 (new ReflectionMethod($module,'logAuthenticationErrors'))->invokeArgs($module,[&$r,'survey authentication',87]);
 check(end($module->framework->logs)[1]['project_id']===87,'LDAP failures reach project-scoped module logs');
 foreach(FakeLDAP::$results as $handle) check($handle->freed,'Failed operations release results');
 check(count(FakeLDAP::$closed)===1,'Failed operations close the connection');
}
FakeLDAP::$tlsSuccess=true;FakeLDAP::$errno=49;
FakeLDAP::$servers['ldap://diagnostics.test:389']=['entries'=>[entry('good')],'accept'=>[]];
$r=['success'=>false,'log_error'=>[]];
(new ReflectionMethod($module,'doLDAPauth'))->invokeArgs($module,['user','wrong',config('diagnostics.test'),&$r]);
check(!$r['success'] && !$r['log_error'],'Invalid credentials remain a normal denial');
echo "Passed LDAP diagnostics, credential exclusion, backend precedence, LDAP isolation, group denial, and handle-lifetime regressions.\n";
}
