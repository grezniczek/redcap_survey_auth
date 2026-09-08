<?php
require __DIR__.'/session-regressions.php';
$module=new class extends \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule { public $PREFIX='redcap_survey_auth'; };
$framework=new class {
    // Project 2 represents a disabled project; project 3 has an explicit writing choice.
    public $settings=[
        1=>['surveyauth_successmsg'=>'Old message','surveyauth_continuelabel'=>'Old label','surveyauth_custom'=>'keep'],
        2=>['surveyauth_successmsg'=>'Disabled project message','surveyauth_token'=>'legacy'],
        3=>['surveyauth_token'=>'legacy','surveyauth_canwrite'=>false],
        4=>['surveyauth_token'=>'','surveyauth_canwrite'=>true],
    ];
    public $writes=0,$failKey=null;
    public function prefixSettingKey($key){return $key;}
    public function query($sql,$params){
        check(str_contains($sql,'m.directory_prefix=?') && str_contains($sql,'s.project_id IS NOT NULL'),'Discovery scopes settings to this module and project level');
        check($params===['redcap_survey_auth','surveyauth_token','surveyauth_successmsg','surveyauth_continuelabel'],'Discovery selects only retired keys');
        $rows=[];
        foreach($this->settings as $pid=>$values)if(array_intersect(array_keys($values),array_slice($params,1)))$rows[]=['project_id'=>$pid];
        return new class($rows) {
            public function __construct(private $rows){}
            public function fetch_assoc(){return array_shift($this->rows);}
        };
    }
    public function getProjectSetting($key,$pid){return $this->settings[$pid][$key]??null;}
    public function setProjectSetting($key,$value,$pid){$this->settings[$pid][$key]=$value;$this->writes++;}
    public function removeProjectSetting($key,$pid){
        if($key===$this->failKey)throw new RuntimeException('Simulated cleanup failure');
        if(array_key_exists($key,$this->settings[$pid]??[])){unset($this->settings[$pid][$key]);$this->writes++;}
    }
};
$module->framework=$framework;
$module->redcap_module_system_enable('9.9.9');
check($framework->settings[1]===['surveyauth_custom'=>'keep'],'Retired presentation settings removed; active settings preserved');
check($framework->settings[2]===['surveyauth_canwrite'=>true],'Disabled project receives token migration and retired-setting cleanup');
check($framework->settings[3]===['surveyauth_canwrite'=>false],'Explicit disabled writing remains disabled');
check($framework->settings[4]===['surveyauth_canwrite'=>true],'Explicit enabled writing remains enabled');
$before=$framework->settings;$writes=$framework->writes;
$module->redcap_module_system_enable('2.1.1');
check($framework->settings===$before && $framework->writes===$writes,'Repeated migration depends on stored state, not version ordering');
$framework->settings[5]=['surveyauth_token'=>'','surveyauth_continuelabel'=>'Imported'];
$module->redcap_module_project_enable('9.9.9',5);
check($framework->settings[5]===[],'Project enable removes imported settings without enabling writes for an empty token');
$framework->settings[6]=['surveyauth_token'=>'legacy','surveyauth_successmsg'=>'Old'];
$framework->failKey='surveyauth_successmsg';$failed=false;
try{$module->redcap_module_project_enable('9.9.9',6);}catch(RuntimeException $e){$failed=true;}
check($failed && $framework->settings[6]['surveyauth_canwrite']===true,'Cleanup failure is visible after preserving the legacy writing choice');
$framework->failKey=null;$module->redcap_module_project_enable('9.9.9',6);
check($framework->settings[6]===['surveyauth_canwrite'=>true],'Retry completes a partially applied migration safely');
check(!method_exists($module,'redcap_module_system_change_version'),'Obsolete hook is removed');
echo "Passed retired-setting cleanup, disabled projects, legacy choices, and migration retry regressions.\n";
