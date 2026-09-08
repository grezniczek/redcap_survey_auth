<?php
// Copy routing and publication ordering with synthetic core/framework adapters.
ob_start();
require __DIR__.'/session-regressions.php';
define('USERID','editor');
function json_encode_rc($value) { return json_encode($value); }
class UserRights { public static $admin=false; public static function isSuperUserNotImpersonator(){return self::$admin;} }
class ProjectDashboards {
    public static $rows=[], $fail=false;
    public function getDashboards($pid,$id=null) {return self::$rows[$id]??[];}
    public function copyDash($id) {
        if(self::$fail)return false;
        $copy=$this->getDashboards(1,$id);
        check($copy['is_public']==='0','Core copy receives a private source snapshot');
        self::$rows[3]=$copy;
        return 3;
    }
    public function renderDashboardList(){return '<div>Dashboard list</div>';}
}
$framework=new class {
    public $settings=[], $failWrite=false, $writes=0, $published=false;
    public function getProjectSetting($key,$pid){return $this->settings[$key]??null;}
    public function setProjectSetting($key,$value,$pid){
        check(ProjectDashboards::$rows[3]['is_public']==='0','Copy remains private while settings are written');
        if($this->failWrite)throw new RuntimeException('simulated write failure');
        $this->writes++;$this->settings[$key]=$value;
    }
    public function query($sql,$params){
        check($this->writes===3,'All settings must be saved before publication');
        check($params===[1,3],'Publication targets only the new project dashboard');
        $this->published=true;ProjectDashboards::$rows[3]['is_public']='1';
    }
};
$module->framework=$framework;
function copyFixture($sourcePublic='1',$endpoint='external',$protected='1',$deny='1') {
 global $module,$framework;
 ProjectDashboards::$rows=[2=>['is_public'=>$sourcePublic,'title'=>'Source']];
 $framework->settings=['surveyauth_dash_protected_2'=>$protected,'surveyauth_dash_endpoint_2'=>$endpoint,'surveyauth_dash_denyexternal_2'=>$deny];
 $framework->writes=0;$framework->published=false;
 $_POST=['dash_id'=>'2'];$_SERVER['REQUEST_METHOD']='POST';$module->exited=false;http_response_code(200);
 ob_start();callPrivate($module,'copyDashboardWithProtection',1);$body=ob_get_clean();
 check($module->exited,'Module stops the controller from making a second copy');
 check(ProjectDashboards::$rows[2]['is_public']===$sourcePublic,'Source public status never changes');
 return $body;
}
$GLOBALS['user_rights']=['design'=>1];$GLOBALS['project_dashboard_allow_public']='1';
foreach(['both','internal','external'] as $endpoint){
 $body=copyFixture('1',$endpoint);
 check(json_decode($body,true)['new_dash_id']===3 && $framework->published,'Copy preserves native response and public status');
 foreach(['protected','endpoint','denyexternal'] as $key) check($framework->settings['surveyauth_dash_'.$key.'_3']===$framework->settings['surveyauth_dash_'.$key.'_2'],'Copy preserves '.$key);
}
copyFixture('0');check(!$framework->published,'Private source remains private');
$GLOBALS['project_dashboard_allow_public']='2';copyFixture();check(!$framework->published,'Normal staff cannot bypass public-dashboard approval policy');
UserRights::$admin=true;copyFixture();check($framework->published,'Core superuser publication rule is preserved');UserRights::$admin=false;
$GLOBALS['project_dashboard_allow_public']='1';$framework->failWrite=true;
check(copyFixture()==='0' && http_response_code()===503 && !$framework->published && ProjectDashboards::$rows[3]['is_public']==='0','Failed settings write leaves copy private');
$framework->failWrite=false;ProjectDashboards::$fail=true;
check(copyFixture()==='0' && $framework->writes===0,'Failed core copy writes no destination settings');ProjectDashboards::$fail=false;
$GLOBALS['user_rights']['design']=0;
check(copyFixture()==='0' && http_response_code()===403 && !isset(ProjectDashboards::$rows[3]),'Missing design rights cannot copy');
$GLOBALS['user_rights']['design']=1;
copyFixture('1','both',null,null);check($framework->settings['surveyauth_dash_protected_3']===null,'Unprotected source retains native default');
echo "Passed dashboard copy inheritance, permissions, and safe publication regressions.\n";
ob_end_flush();
