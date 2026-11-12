<?php
// php -n tests/ldap-core-regressions.php: scripted legacy/current driver callbacks, no network.
namespace ExternalModules { class AbstractExternalModule { public $framework; public $PREFIX='fixture'; } }
namespace DE\RUB\SurveyAuthExternalModule {
    function extension_loaded($name) { return $name==='ldap' ? \CoreFixture::$extension : \extension_loaded($name); }
}
namespace {
if (extension_loaded('ldap')) throw new RuntimeException('Run with php -n.');
require dirname(__DIR__).'/SurveyAuthExternalModule.php';
require __DIR__.'/fixtures/ldap/core-driver-contract.php';
define('APP_PATH_WEBTOOLS',__DIR__.'/fixtures/');
define('LDAP_OPT_PROTOCOL_VERSION',17); define('LDAP_OPT_DIAGNOSTIC_MESSAGE',50);
class Auth { function __construct(...$args) { throw new RuntimeException('Staff Auth must not be constructed'); } }
class CoreFixture {
    public static $extension=true, $closed=[], $failCleanup=false, $failProtocolRead=false;
}
class FakeLDAP { public static $redcapConfigs=[]; }
function ldap_get_option($handle,$option,&$value) {
    if ($handle->closed) throw new RuntimeException('Closed connection');
    if ($option===LDAP_OPT_PROTOCOL_VERSION && CoreFixture::$failProtocolRead) return false;
    $value=$option===LDAP_OPT_PROTOCOL_VERSION ? $handle->version : $handle->diagnostic;
    return true;
}
function ldap_errno($handle) { if ($handle->closed) throw new RuntimeException('Closed connection'); return $handle->errno; }
function ldap_error($handle) { return 'fixture LDAP error'; }
function ldap_unbind($handle) {
    if (CoreFixture::$failCleanup) throw new RuntimeException('cleanup failure fixture-password');
    if ($handle->closed) throw new RuntimeException('Connection closed twice');
    $handle->closed=true; CoreFixture::$closed[]=$handle; return true;
}
function check($ok,$label) { if (!$ok) throw new RuntimeException($label); }
$module=new \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule();
$settings=(new ReflectionClass(\DE\RUB\SurveyAuthExternalModule\SurveyAuthSettings::class))->newInstanceWithoutConstructor();
$settings->ldapMappings=['fullname'=>['cn'],'firstname'=>['givenname'],'lastname'=>['sn'],'email'=>['mail']];
$settings->fallbackToTableUserInfo=false;
$settings->otherLDAPConfigs=[];
$settings->useCustom=$settings->useTable=$settings->useOtherLDAP=false; $settings->useLDAP=true;
$settings->lockoutCount=$settings->lockouttime=0; $settings->useWhitelist=false;
$settings->log='none'; $settings->errorMsg='Generic error'; $settings->failMsg='Denied';
(new ReflectionProperty($module,'settings'))->setValue($module,$settings);
$module->framework=new class {
    public $logs=[], $queries=[], $failQuery=false;
    function log($message,$parameters) { $this->logs[]=[$message,$parameters]; }
    function query($sql,$params) {
        if ($this->failQuery) throw new RuntimeException('synthetic table outage');
        $this->queries[]=$params;
        return new class { function fetch_assoc() { return ['user_email'=>'fallback@example.test','user_firstname'=>'Fallback','user_lastname'=>'Name']; } };
    }
};
$config=['url'=>'ldap://fixture.test','port'=>636,'version'=>3,'start_tls'=>true,
    'binddn'=>'cn=fixture-service,dc=test','bindpw'=>'service-secret'];
function attempt($config,$username='fixture-user',$password='fixture-password') {
    global $module;
    $r=['success'=>false,'log_error'=>[]];
    (new ReflectionMethod($module,'doRedcapLDAPauth'))->invokeArgs($module,[$username,$password,$config,&$r]);
    return $r;
}
function connectDriver($driver,$version=3,$errno=0) {
    $driver->options['url']='ldap://fixture.test:389';
    $driver->conn_id=(object)['closed'=>false,'version'=>$version,'errno'=>$errno,
        'diagnostic'=>'diagnostic fixture-password service-secret cn=fixture-service,dc=test'];
    $driver->_auth_obj->log('Auth_Container_LDAP::_connect() called.');
}
function candidate($driver,$name='Accepted',$email='ACCEPTED@example.test') {
    $driver->_auth_obj->setAuthData('cn',$name);
    $driver->_auth_obj->setAuthData('mail',$email);
    $driver->_auth_obj->setAuthData('userPassword','DIRECTORY_SECRET_MUST_NOT_ESCAPE');
    $driver->_auth_obj->log('Bind as uid=fixture-user,dc=test');
}
function finishDriver($driver,$modern) {
    $driver->_auth_obj->log('Auth_Container_LDAP::_disconnect() called.');
    if ($modern) { ldap_unbind($driver->conn_id); $driver->conn_id=false; }
}
$state=[$_SESSION=['survey'=>'unchanged'],$_POST=['sentinel'=>'post'],$_COOKIE=['sentinel'=>'cookie']];
foreach ([false,true] as $modern) {
    CoreFixture::$closed=[];
    Auth_Container_LDAP::$authenticate=function($driver) use ($modern) {
        connectDriver($driver); $driver->_auth_obj->log('Starting TLS session'); candidate($driver);
        if ($modern) $driver->_auth_obj->setAuthData('redcap_ldap_profile',['mail'=>['wrong-profile@example.test']]);
        finishDriver($driver,$modern); return true;
    };
    $r=attempt($config);
    check($r['success'] && $r['fullname']==='Accepted' && $r['email']==='accepted@example.test' && !$r['log_error'],
        'Legacy/current driver success uses mapped attributes, not the newer fixed profile');
    check(count(CoreFixture::$closed)===1,'Legacy/current handles close exactly once');
    check(Auth_Container_LDAP::$constructed[array_key_last(Auth_Container_LDAP::$constructed)]===$config,
        'Core configuration is passed through without Survey Auth defaults or port rewriting');
    check(!str_contains(json_encode($r),'DIRECTORY_SECRET'),'Unmapped directory secrets are discarded');
    Auth_Container_LDAP::$authenticate=function($driver) use ($modern) {
        connectDriver($driver,3,49); candidate($driver); $driver->_auth_obj->log('NOT authenticated!');
        finishDriver($driver,$modern); return false;
    };
    $r=attempt($config);
    check(!$r['success'] && !isset($r['email']) && !$r['log_error'],'Invalid user bind discards staged identity without a technical error');
    Auth_Container_LDAP::$authenticate=function($driver) use ($modern) {
        connectDriver($driver,3,81); $driver->_auth_obj->log('Binding with credentials');
        $driver->_auth_obj->log('Bind failed'); finishDriver($driver,$modern);
        return new PEAR_Error('primary failure fixture-password service-secret cn=fixture-service,dc=test');
    };
    $r=attempt($config);
    check(!$r['success'] && str_contains($r['log_error'][0],'primary failure') && str_contains($r['log_error'][0],'service bind'),
        'PEAR error cannot grant access and keeps pre-disconnect stage');
    foreach (['fixture-password','service-secret','cn=fixture-service,dc=test'] as $secret) check(!str_contains($r['log_error'][0],$secret),'Diagnostics redact credentials');
    $details=json_decode(substr($r['log_error'][0],strlen('REDCap LDAP error: ')),true,512,JSON_THROW_ON_ERROR);
    check($details['ldap_errno']===81 && $details['endpoint']==='ldap://fixture.test:389','Closed-driver errors retain native diagnostics and effective endpoint');
}
// The dispatcher and adapter must pass raw credentials and configuration to core.
foreach ([['', ''], ['fixture-user', "fixture-\0password"], ["fixture-\0user", 'fixture-password']] as [$username,$password]) {
    $seen=null;
    Auth_Container_LDAP::$authenticate=function($driver,$user,$pass) use (&$seen) {
        $seen=[$user,$pass]; return false;
    };
    FakeLDAP::$redcapConfigs=$config; $r=['success'=>false,'log_error'=>[]];
    (new ReflectionMethod($module,'authenticateLDAP'))->invokeArgs($module,[$username,$password,&$r]);
    check($seen===[$username,$password] && !$r['success'] && !$r['log_error'],
        'Empty/NUL credentials reach the installed driver unchanged');
}
foreach ([['version'=>2],['version'=>'invalid'],['version'=>null],['start_tls'=>'false'],['start_tls'=>1]] as $change) {
    $cfg=array_replace($config,$change); if ($cfg['version']===null) unset($cfg['version']);
    Auth_Container_LDAP::$authenticate=function($driver) { connectDriver($driver); candidate($driver); return true; };
    $r=attempt($cfg);
    check($r['success'] && Auth_Container_LDAP::$constructed[array_key_last(Auth_Container_LDAP::$constructed)]===$cfg,
        'Protocol and TLS options are delegated without additional adapter validation');
}
foreach ([false,true] as $tls) {
    Auth_Container_LDAP::$authenticate=function($driver) use ($tls) {
        connectDriver($driver,2);
        $driver->_auth_obj->log($tls ? 'Starting TLS session' : 'Binding with credentials');
        candidate($driver); return true;
    };
    check(attempt(array_replace($config,['start_tls'=>$tls]))['success'],
        'Adapter does not add protocol verification to core TLS or bind callbacks');
}
CoreFixture::$failProtocolRead=true;
Auth_Container_LDAP::$authenticate=function($driver) { connectDriver($driver); $driver->_auth_obj->log('Binding with credentials'); candidate($driver); return true; };
$r=attempt($config); CoreFixture::$failProtocolRead=false;
check($r['success'],'Adapter does not reject core acceptance when protocol cannot be read');
Auth_Container_LDAP::$authenticate=function($driver,$username,$password) {
    connectDriver($driver); throw new RuntimeException('credential echo '.$password.' '.str_replace("\0", '', $password));
};
$r=attempt($config,'fixture-user',"unique-\0normalized-secret");
check(!$r['success'] && !str_contains($r['log_error'][0],'normalized-secret'),
    'Diagnostics redact both the raw password and the form normalized by core');
Auth_Container_LDAP::$authenticate=function($driver) {
    connectDriver($driver); candidate($driver,'Rejected','rejected@example.test');
    // A later candidate has no mapped attributes. The first candidate must not survive.
    $driver->_auth_obj->log('Bind as uid=second,dc=test'); return true;
};
$r=attempt($config);
check($r['success'] && $r['fullname']==='' && $r['email']==='','Candidate attributes never survive into a later accepted entry');
$settings->fallbackToTableUserInfo=true; $module->framework->failQuery=true;
$r=attempt($config);
check(!$r['success'] && str_contains($r['log_error'][0],'table identity fallback') && !isset($r['email']),
    'Table fallback outage identifies its stage and does not publish partial success');
$settings->fallbackToTableUserInfo=false; $module->framework->failQuery=false;
Auth_Container_LDAP::$authenticate=function($driver) {
    connectDriver($driver,3,81);
    $driver->_auth_obj->log('Searching with ldap_search and filter (uid=fixture-user) in dc=test');
    $handler=set_error_handler(static fn()=>false); restore_error_handler();
    $handler(E_WARNING,'ldap_search(): failure fixture-password service-secret',__FILE__,__LINE__);
    $driver->_auth_obj->log('User not found'); return false;
};
$outerHandler=static fn()=>false;
set_error_handler($outerHandler,E_WARNING);
$r=attempt($config);
$restored=set_error_handler($outerHandler,E_WARNING); restore_error_handler(); restore_error_handler();
check($restored===$outerHandler,'Original error handler is restored after driver failure');
check(!$r['success'] && str_contains($r['log_error'][0],'ldap_search()') && !str_contains($r['log_error'][0],'fixture-password'),
    'Operational native warnings retain context and redact credentials');
Auth_Container_LDAP::$authenticate=function($driver) { connectDriver($driver); candidate($driver); return 1; };
check(!attempt($config)['success'],'Only literal true is accepted');
Auth_Container_LDAP::$authenticate=function($driver) { connectDriver($driver); throw new RuntimeException('primary failure fixture-password'); };
CoreFixture::$failCleanup=true;
$r=attempt($config); CoreFixture::$failCleanup=false;
check(!$r['success'] && str_contains($r['log_error'][0],'primary failure') && str_contains($r['log_error'][0],'cleanup failure'),
    'Cleanup failure does not replace original failure and remains diagnosable');
check(!str_contains($r['log_error'][0],'fixture-password'),'Cleanup diagnostics redact passwords');
CoreFixture::$extension=false;
$r=attempt($config); CoreFixture::$extension=true;
check(!$r['success'] && str_contains($r['log_error'][0],'LDAP extension not loaded'),'Missing extension produces a diagnostic instead of PEAR termination');
FakeLDAP::$redcapConfigs=$config;
$_SERVER['REMOTE_ADDR']='192.0.2.7';
Auth_Container_LDAP::$authenticate=function($driver) { connectDriver($driver); throw new RuntimeException('private backend detail fixture-password'); };
$r=$module->authenticate('fixture-user','fixture-password',87,'survey',123,1,null);
check(!$r['success'] && $r['error']==='Generic error' && count($module->framework->logs)===1,
    'Technical failures retain generic participant error and log independently of attempt mode');
check($module->framework->logs[0][1]['project_id']===87,'Adapter diagnostics retain project scope');
check([$_SESSION,$_POST,$_COOKIE]===$state,'No staff-session or request side effects');
$cfg=json_decode(file_get_contents(dirname(__DIR__).'/config.json'),true,512,JSON_THROW_ON_ERROR);
check($cfg['compatibility']['redcap-version-min']==='16.0.0','REDCap 16.0.0 minimum is declared');
echo "Passed core LDAP adapter strict outcomes, legacy/current cleanup, attribute isolation, core credential/TLS parity, diagnostics, and session isolation regressions.\n";
}
