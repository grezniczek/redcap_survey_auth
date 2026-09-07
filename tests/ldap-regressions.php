<?php
// Run with php -n tests/ldap-regressions.php: fake LDAP transport, no network or credentials.
namespace DE\RUB\SurveyAuthExternalModule {
    function extension_loaded($name) { return $name === 'ldap' || \extension_loaded($name); }
}
namespace {
if (extension_loaded('ldap')) throw new RuntimeException('Run this isolated transport test with php -n.');
require __DIR__.'/session-regressions.php';
define('APP_PATH_WEBTOOLS',__DIR__.'/fixtures/');
define('LDAP_OPT_PROTOCOL_VERSION',17); define('LDAP_OPT_REFERRALS',8);
class FakeLDAP {
    public static $servers=[], $redcapConfigs=[], $calls=[], $results=[], $closed=[];
    public static $tableSuccess=false;
    public static function reset() { self::$calls=self::$results=self::$closed=[]; }
    public static function result($entries) { $r=(object)['entries'=>$entries,'freed'=>false];self::$results[]=$r;return $r; }
}
function ldap_connect($url,$port) { FakeLDAP::$calls[]=$url;return (object)['url'=>$url]; }
function ldap_set_option(...$args) { return true; }
function ldap_get_option($ldap,$option,&$value) { $value=2; return true; }
function ldap_bind($ldap,$dn=null,$password=null) {
    if ($dn===null) return true;
    return $password==='correct' && in_array($dn,FakeLDAP::$servers[$ldap->url]['accept']??[],true);
}
function ldap_search($ldap,$base,$filter,$attributes) {
    $s=FakeLDAP::$servers[$ldap->url];
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
function config($url,$group='') { return ['url'=>$url,'host'=>$url,'port'=>389,'basedn'=>'dc=test','group'=>$group]; }
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
FakeLDAP::$servers=['other'=>['entries'=>[entry('other','Other','other@example.test')],'accept'=>['other']],
    'redcap'=>['entries'=>[entry('redcap','REDCap','redcap@example.test')],'accept'=>['redcap']]];
$r=runBackends();check($r['method']==='Custom' && !FakeLDAP::$calls,'Custom succeeds before any other backend');
$settings->customCredentials=[];FakeLDAP::$tableSuccess=true;
$r=runBackends();check($r['method']==='Table' && FakeLDAP::$calls===['Table'],'Table precedes both LDAP sources');
FakeLDAP::$tableSuccess=false;
$r=runBackends();check(str_starts_with($r['method'],'Other LDAP') && $r['email']==='other@example.test' && FakeLDAP::$calls===['Table','other'],'Other LDAP wins before REDCap LDAP');
FakeLDAP::$servers['other']['accept']=[];
$r=runBackends();check($r['method']==='LDAP' && $r['email']==='redcap@example.test' && FakeLDAP::$calls===['Table','other','redcap'],'Failed Other LDAP falls through to REDCap');
$settings->useTable=$settings->useOtherLDAP=false;
FakeLDAP::$redcapConfigs=[config('bad'),config('good'),config('late')];
FakeLDAP::$servers['bad']=['entries'=>[entry('bad','Wrong','wrong@example.test')],'accept'=>[]];
FakeLDAP::$servers['good']=['entries'=>[entry('good')],'accept'=>['good']];
$r=runBackends();check($r['success'] && $r['fullname']==='' && $r['email']==='' && FakeLDAP::$calls===['bad','good'],'Rejected directory attributes cannot leak and first accepted directory stops iteration');
FakeLDAP::$redcapConfigs=[config('multi')];
FakeLDAP::$servers['multi']=['entries'=>[entry('bad','Wrong','wrong@example.test'),entry('good')],'accept'=>['good'],
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
echo "Passed backend precedence, LDAP isolation, group denial, and handle-lifetime regressions.\n";
}
