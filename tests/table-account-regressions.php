<?php
// Exercise actual Table login and shared grant revalidation with synthetic accounts.
require __DIR__.'/session-regressions.php';
class User {
    public static $account=['user_suspended_time'=>null,'user_email'=>'fixture@example.test','user_firstname'=>'Test','user_lastname'=>'User'];
    public static function getUserInfo($username){return self::$account;}
}
class Authentication {
    public static $calls=0;
    public static function verifyTableUsernamePassword($username,$password){self::$calls++;return $username==='fixture' && $password==='correct';}
}
function tableLogin($password='correct'){
    global $module;
    $r=['success'=>false];
    (new ReflectionMethod($module,'authenticateTable'))->invokeArgs($module,['fixture',$password,&$r]);
    return $r;
}
$active=User::$account;
check(tableLogin()['success'],'Active Table account can authenticate');
check(!tableLogin('wrong')['success'],'Wrong Table password is rejected');
foreach([null,array_replace($active,['user_suspended_time'=>'2026-09-08 12:00:00'])] as $account){
    User::$account=$account;$before=Authentication::$calls;
    check(!tableLogin()['success'] && Authentication::$calls===$before,'Missing/suspended accounts are rejected before password verification');
}
User::$account=$active;
$module->framework=new class {
    public $auth=['password'=>'hash-before','password_salt'=>'salt-before'];
    public function query($sql,$params){
        check($params===['fixture'],'Password revision query is scoped to the grant identity');
        return new ArrayIterator($this->auth===null?[]:[$this->auth]);
    }
};
$settings->useWhitelist=false;setPrivate($module,'settings',$settings);
$grant=['method'=>'Table','username'=>'fixture','account_revision'=>callPrivate($module,'surveyAccountRevision','fixture')];
check(callPrivate($module,'surveyIdentityActive',$grant),'Unchanged active account retains its grant');
User::$account=array_replace($active,['user_suspended_time'=>'2026-09-08 12:00:00']);
check(!callPrivate($module,'surveyIdentityActive',$grant),'Suspension revokes an existing grant');
User::$account=null;check(!callPrivate($module,'surveyIdentityActive',$grant),'Deleted account revokes an existing grant');
User::$account=$active;$original=$module->framework->auth;
foreach([array_replace($original,['password'=>'hash-after']),array_replace($original,['password_salt'=>'salt-after']),null] as $auth){
    $module->framework->auth=$auth;
    check(!callPrivate($module,'surveyIdentityActive',$grant),'Password/salt change or removed credentials revoke the old grant');
}
$module->framework->auth=['password'=>'hash-after','password_salt'=>'salt-after'];
$grant['account_revision']=callPrivate($module,'surveyAccountRevision','fixture');
check(callPrivate($module,'surveyIdentityActive',$grant),'Fresh revision after reauthentication can authorize the active account');
$settings->useWhitelist=true;$settings->whitelist=['someone-else'];
check(!callPrivate($module,'surveyIdentityActive',$grant),'Allowlist removal revokes an otherwise active account');
$settings->whitelist=['fixture'];check(callPrivate($module,'surveyIdentityActive',$grant),'Allowlisted active account retains access');
echo "Passed Table login, suspension, deletion, password revision, and allowlist revocation regressions.\n";
