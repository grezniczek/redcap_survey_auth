<?php namespace DE\RUB\SurveyAuthExternalModule;

/**
 * A helper class that holds settings info for this external module.
 */
class SurveyAuthSettings {
    public $canwrite = false;
    public $log;
    public $text;
    public $usernameLabel;
    public $passwordLabel;
    public $submitLabel;
    public $failMsg;
    public $lockoutCount = 3;
    public $lockoutMsg;
    public $lockouttime;
    public $successMsg;
    public $errorMsg;
    public $continueLabel;
    public $blobSecret;
    public $blobHmac;
    public $isProject;
    public $useTable;
    public $useLDAP;
    public $useOtherLDAP;
    public $useCustom;
    public $customCredentials;
    public $otherLDAPConfigs;
    public $fallbackToTableUserInfo;
    public $ldapMappings = array(
        "email" => array(),
        "fullname" => array(),
        "firstname" => array(),
        "lastname" => array()
    );
    public $useWhitelist;
    public $whitelist;
    public $lockoutStatus;
    // Dashboard
    public $dash_protected;
    public $dash_endpoint;
    public $dash_noaccessmsg;
    public $dash_denyexternal;
    // Report
    public $report_protected;
    public $report_endpoint;
    public $report_noaccessmsg;
    public $report_denyexternal;

    private $m;

    function __construct($module, $project_id = null, $dash_id = 0, $report_id = 0) 
    {
        $this->isProject = $project_id != null;
        $this->m = $module;
        $this->blobSecret = $module->getSystemSetting("surveyauth_blobsecret");
        $this->blobHmac = $module->getSystemSetting("surveyauth_blobhmac");
        $lockouttime = $module->getSystemSetting("surveyauth_lockouttime");
        $this->lockouttime = is_numeric($lockouttime) ? $lockouttime * 1 : 5;
        $this->lockoutStatus = $this->lockouttime === 0 ? array() : json_decode($module->getSystemSetting("surveyauth_lockouts"), true);
        // Only in the context of a project
        if ($this->isProject) {
            $this->log = $this->getValue("surveyauth_log", "all");
            $this->canwrite = $this->getValue("surveyauth_canwrite", false);
            $this->text = $this->getValue("surveyauth_text", "Login is required to continue.");
            $this->usernameLabel = $this->getValue("surveyauth_usernamelabel", "Username");
            $this->passwordLabel = $this->getValue("surveyauth_passwordlabel", "Password");
            $this->submitLabel = $this->getValue("surveyauth_submitlabel", "Submit");
            $this->failMsg = $this->getValue("surveyauth_failmsg", "Invalid username and/or password or access denied.");
            $lockoutCount = $this->getValue("surveyauth_lockoutcount", "3");
            if ($lockoutCount === "0") {
                $this->lockoutCount = 0;
            }
            else if (isnumber($lockoutCount)) {
                $lockoutCount = (int)($lockoutCount);
                $this->lockoutCount = $lockoutCount > 0 ? $lockoutCount : 3;
            }
            $this->lockoutMsg = $this->getValue("surveyauth_lockoutmsg", "Too many failed login attempts. Please try again later.");
            $this->successMsg = $this->getValue("surveyauth_successmsg", "Authentication was successful. You will be automatically forwarded to the survey momentarily.");
            $this->errorMsg = $this->getValue("surveyauth_errormsg", "A technical error prevented completion of the authentication process. Please notify the system administrator.");
            $this->continueLabel = $this->getValue("surveyauth_continuelabel", "Continue to Survey");
            $this->useTable = $this->getValue("surveyauth_usetable", false);
            $this->useLDAP = $this->getValue("surveyauth_useldap", false);
            $this->useOtherLDAP = $this->getValue("surveyauth_useotherldap", false);
            $this->useCustom = $this->getValue("surveyauth_usecustom", false);
            $this->otherLDAPConfigs = json_decode($this->getValue("surveyauth_otherldap", "[]"), true);
            $this->fallbackToTableUserInfo = $this->getValue("surveyauth_ldap_uifallback", false);
            if (!is_array($this->otherLDAPConfigs)) $this->otherLDAPConfigs = array();
            $defaults = array(
                "email" => "email,mail",
                "fullname" => "",
                "firstname" => "givenName",
                "lastname" => "sn"
            );
            foreach (array_keys($defaults) as $key) {
                foreach(explode(",", $this->getValue("surveyauth_ldapmap_{$key}", $defaults[$key])) as $item) {
                    $item = trim($item);
                    if (strlen($item)) $this->ldapMappings[$key][] = $item;
                }
            }
            $this->customCredentials = $this->parseCustomCredentials($this->getValue("surveyauth_custom", ""));
            $this->useWhitelist = $this->getValue("surveyauth_usewhitelist", false);
            $this->whitelist = $this->parseWhitelist($this->getValue("surveyauth_whitelist", ""));
            // Dashboard settings
            $this->dash_noaccessmsg = $this->getValue("surveyauth_dash_noaccessmsg", "Access to this page is not allowed from your location.");
            if ($dash_id > 0) {
                $this->dash_protected = $this->getValue("surveyauth_dash_protected_$dash_id", false) == "1";
                $this->dash_endpoint = $this->getValue("surveyauth_dash_endpoint_$dash_id", "both");
                $this->dash_denyexternal = $this->getValue("surveyauth_dash_denyexternal_$dash_id", false) == "1";
            }
            // Report settings
            $this->report_noaccessmsg = $this->getValue("surveyauth_report_noaccessmsg", "Access to this page is not allowed from your location.");
            if ($report_id > 0) {
                $this->report_protected = $this->getValue("surveyauth_report_protected_$report_id", false) == "1";
                $this->report_endpoint = $this->getValue("surveyauth_report_endpoint_$report_id", "both");
                $this->report_denyexternal = $this->getValue("surveyauth_report_denyexternal_$report_id", false) == "1";
            }
        }
    }

    private function getValue($name, $default) 
    {
        $value = $this->m->getProjectSetting($name);
        return strlen($value) ? $value : $default;
    }

    private function parseCustomCredentials($raw) 
    {
        $creds = array();
        $lines = explode("\n", $raw);
        foreach ($lines as $line) {
            $parts = explode(":", $line);
            if (count($parts) > 1) {
                $username = strtolower($parts[0]);
                $password = join(":", array_slice($parts, 1));
                $creds[$username] = $password;
            }
        }
        return $creds;
    }

    private function parseWhitelist($raw) 
    {
        $whitelist = array();
        $lines = explode("\n", $raw);
        foreach ($lines as $line) {
            $line = trim(strtolower($line));
            if (strlen($line)) array_push($whitelist, $line);
        }
        return $whitelist;
    }
}
