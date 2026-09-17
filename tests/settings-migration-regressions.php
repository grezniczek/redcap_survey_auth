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
    public $systemSettings=[];
    public $writes=0,$systemWrites=0,$failKey=null,$systemFailKey=null;
    public function __construct(){
        $now=time();
        $this->systemSettings=[
            'surveyauth_lockouttime'=>'5',
            'surveyauth_lockouts'=>json_encode([
                '192.0.2.1'=>['n'=>2,'ts'=>$now],
                '192.0.2.2'=>['n'=>4,'ts'=>$now-301],
                '192.0.2.3'=>['n'=>1,'ts'=>$now],
                'invalid-address'=>['n'=>9,'ts'=>$now],
            ]),
            'surveyauth_lockouts_3'=>json_encode(['192.0.2.1'=>['n'=>3,'ts'=>$now+1]]),
        ];
    }
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
    public function getSystemSetting($key){return $this->systemSettings[$key]??null;}
    public function setSystemSetting($key,$value){
        if($key===$this->systemFailKey)throw new RuntimeException('Simulated system migration failure');
        $this->systemSettings[$key]=$value;$this->systemWrites++;
    }
    public function removeSystemSetting($key){
        if(array_key_exists($key,$this->systemSettings)){unset($this->systemSettings[$key]);$this->systemWrites++;}
    }
    public function setProjectSetting($key,$value,$pid){$this->settings[$pid][$key]=$value;$this->writes++;}
    public function removeProjectSetting($key,$pid){
        if($key===$this->failKey)throw new RuntimeException('Simulated cleanup failure');
        if(array_key_exists($key,$this->settings[$pid]??[])){unset($this->settings[$pid][$key]);$this->writes++;}
    }
};
$module->framework=$framework;
$module->redcap_module_system_enable('9.9.9');
check(!isset($framework->systemSettings['surveyauth_lockouts']),'Legacy lockout setting is removed after bucket migration');
$bucket1=callPrivate($module,'lockoutBucketSettingKey',callPrivate($module,'lockoutBucketForIp','192.0.2.1'));
$bucket3=callPrivate($module,'lockoutBucketSettingKey',callPrivate($module,'lockoutBucketForIp','192.0.2.3'));
$migrated1=json_decode($framework->systemSettings[$bucket1],true);
$migrated3=json_decode($framework->systemSettings[$bucket3],true);
check($migrated1['192.0.2.1']['n']===3 && $migrated3['192.0.2.3']['n']===1,
    'Migration merges valid counters into their deterministic buckets and retains the newer entry');
check(!str_contains(json_encode($framework->systemSettings),'192.0.2.2') &&
    !str_contains(json_encode($framework->systemSettings),'invalid-address'),
    'Migration discards expired and malformed legacy counters');
check($framework->settings[1]===['surveyauth_custom'=>'keep'],'Retired presentation settings removed; active settings preserved');
check($framework->settings[2]===['surveyauth_canwrite'=>true],'Disabled project receives token migration and retired-setting cleanup');
check($framework->settings[3]===['surveyauth_canwrite'=>false],'Explicit disabled writing remains disabled');
check($framework->settings[4]===['surveyauth_canwrite'=>true],'Explicit enabled writing remains enabled');
$before=$framework->settings;$writes=$framework->writes;$systemWrites=$framework->systemWrites;
$module->redcap_module_system_enable('2.1.1');
check($framework->settings===$before && $framework->writes===$writes && $framework->systemWrites===$systemWrites,
    'Repeated migrations depend on stored state, not version ordering');
$retryA='198.51.100.1';$retryB='203.0.113.1';
$retryKeyB=callPrivate($module,'lockoutBucketSettingKey',callPrivate($module,'lockoutBucketForIp',$retryB));
$framework->systemSettings['surveyauth_lockouts']=json_encode([
    $retryA=>['n'=>1,'ts'=>time()],$retryB=>['n'=>2,'ts'=>time()],
]);
$framework->systemFailKey=$retryKeyB;$failed=false;
try{$module->redcap_module_system_enable('9.9.9');}catch(RuntimeException $e){$failed=true;}
check($failed && isset($framework->systemSettings['surveyauth_lockouts']),
    'A partial bucket migration preserves its legacy source');
$framework->systemFailKey=null;$module->redcap_module_system_enable('9.9.9');
check(!isset($framework->systemSettings['surveyauth_lockouts']) &&
    isset(json_decode($framework->systemSettings[$retryKeyB],true)[$retryB]),
    'Retry merges partial bucket writes and removes the source only after success');
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
