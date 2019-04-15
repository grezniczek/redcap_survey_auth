<?php

namespace RUB\SurveyAuthExternalModule;

use ExternalModules\AbstractExternalModule;

/**
 * ExternalModule class for Patient Finder.
 */
class SurveyAuthExternalModule extends AbstractExternalModule {
    
    public static $ACTIONTAG = "SURVEY-AUTH";
    public $IDENTITY = "5a859937-929f-4434-9b35-f2905c193030";

    private $settings;

    function __construct()
    {
        // Need to call parent constructor first!
        parent::__construct();

        // Parse module settings into a convenience object (only in project scope).
        if (isset($GLOBALS["project_id"])) {
            $this->settings = new SurveyAuthSettings($this);
        }
    }

    /**
     * Hook function that is executed for every survey page in projects where the module is enabled.
     */
    function redcap_survey_page_top($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance = 1) 
    {
        // Check if there is a token.
        if (!strlen($this->settings->token)) return;

        // Get the project's data dictionary for the current instrument and find the action tag.
        $dd = json_decode(\REDCap::getDataDictionary($project_id, 'json', true, null, $instrument, false));
        $taggedFields = $this->getTaggedFields($dd);
        // There must be at most one tagged field.
        $tf = count($taggedFields) === 1 ? $taggedFields[0] : null;
        if ($tf == null) return;

        // Check if $record is defined. If not, then authentication needs to be performed.
        if ($record == null) {
            // Need to authenticate - inject JavaScript and HTML.
            $jsUrl = $this->getUrl("surveyauth.js");
            print "<script type=\"text/javascript\" src=\"{$jsUrl}\"></script>";
            $queryUrl = $this->getUrl("authenticate.php", true);
            $template = file_get_contents(dirname(__FILE__)."/ui.html");
            $replace = array(
                "{GUID}" => $tf->guid,
                "{PREFIX}" => $this->PREFIX,
                "{QUERYURL}" => $queryUrl,
                "{SURVEYTITLE}" => $GLOBALS["title"],
                "{INSTRUCTIONS}" => $this->settings->text,
                "{USERNAMELABEL}" => $this->settings->usernamelabel,
                "{PASSWORDLABEL}" => $this->settings->passwordlabel,
                "{SUBMITLABEL}" => $this->settings->submitlabel,
                "{FAILMSG}" => $this->settings->failmsg,
                "{DEBUG}" => $this->settings->debug ? " data-debug=\"1\"" : ""
            );
            print str_replace(array_keys($replace), array_values($replace), $template);

            $this->exitAfterHook();
/*
            // For now, assume authentication has succeded
            // Add a new record.
            $apiUrl = APP_PATH_WEBROOT_FULL . "api/";
            $recordIdField = \REDCap::getRecordIdField();
            $payload = array(array(
                "{$recordIdField}" => "new-{$tf->guid}",
                "{$tf->successField}" => "{$tf->successValue}"
            )); 
            $payloadJson = json_encode($payload);
            $request = array(
                'token' => $token,
                'content' => 'record',
                'format' => 'json',
                'type' => 'flat',
                'overwriteBehavior' => 'normal',
                'forceAutoNumber' => 'true',
                'data' => $payloadJson,
                'returnContent' => 'ids',
                'returnFormat' => 'json'
            );
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $apiUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_VERBOSE, 0);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_AUTOREFERER, true);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_FRESH_CONNECT, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($request, '', '&'));
            $responseJson = curl_exec($ch);
            curl_close($ch);

            $response = json_decode($responseJson);
            $recordId = $response[0];
            $link = \REDCap::getSurveyLink($recordId, $instrument, $event_id, $repeat_instance);
*/
        }
        else {
            // Having a record means that authentication has succeded.
        }




//        $response = \REDCap::saveData($project_id, 'json', '{ "login": 1 }');

    }

    /**
     * A helper function that extracts parts of the data dictionary with the module's action tag.
     */
    private function getTaggedFields($dataDictionary) 
    {
        $fields = array();
        foreach ($dataDictionary as $fieldInfo) {
            if (strpos($fieldInfo->field_annotation, SurveyAuthExternalModule::$ACTIONTAG)) {
                array_push($fields, new SurveyAuthInfo($fieldInfo, $dataDictionary));
            }
        }
        return $fields;
    }


    /**
     * Determines, whether the credentials are valid.
     */
    function authenticate($username, $password) 
    {
        $success = true;
        $error = "";
        $record = null;

        if ($success) {

            // Write the log entry.
            $logData = array(
                "action_description" => "SurveyAuth: Performed authentication operation for '{$username}'",
                "changes_made" => $success ? "Successful" : "Failed/Denied",
                "sql" => null,
                "record" => $record,
                "event" => null,
                "project_id" => $GLOBALS["project_id"]
            );
            \REDCap::logEvent($logData["action_description"], $logData["changes_made"], $logData["sql"], $logData["record"], $logData["event"], $logData["project_id"]);
        }

        // Prepare response.
        $json = array(
            "success" => $success
        );
        if ($success) {
            $json["target"] = "https://www.google.de";
        }
        else {
            $json["error"] = $error;
        }

        // Return response as JSON.
        return json_encode($json);
    }
}


/**
 * A helper class that holds settings info for this external module.
 */
class SurveyAuthSettings 
{
    public $debug;
    public $token;
    public $text;
    public $usernamelabel;
    public $passwordlabel;
    public $submitlabel;
    public $failmsg;
    private $m;

    function __construct($module) 
    {
        $this->m = $module;
        $this->debug = $module->getSystemSetting("surveyauth_globaldebug") || $module->getProjectSetting("surveyauth_debug");
        $this->token = $module->getProjectSetting("surveyauth_token");

        $this->text = $this->getValue("surveyauth_text", "Login is required to continue.");
        $this->usernamelabel = $this->getValue("surveyauth_usernamelabel", "Username");
        $this->passwordlabel = $this->getValue("surveyauth_passwordlabel", "Password");
        $this->submitlabel = $this->getValue("surveyauth_submitlabel", "Submit");
        $this->failmsg = $this->getValue("surveyauth_failmsg", "Invalid username and/or password or access denied.");
    }

    private function getValue($name, $default) 
    {
        $value = $this->m->getProjectSetting($name);
        return strlen($value) ? $value : $default;
    }
}



/**
 * A helper class that holds information about the behavior of the SurveyAuth module.
 */
class SurveyAuthInfo 
{
    public $guid;
    public $successField;
    public $successValue;
    public $map = array();
    public $dateFormat = "dmy";

    private $ALLOWEDMAPPINGS = array("success", "username", "email", "fullname", "timestamp");

    function __construct($fieldInfo, $dd) 
    {
        $this->guid = SurveyAuthInfo::GUID();
        $this->fieldName = $fieldInfo->field_name;
        // Extract and parse parameters.
        $re = '/@' . SurveyAuthExternalModule::$ACTIONTAG . '\((?\'config\'.+=.+)\)/m';
        preg_match_all($re, $fieldInfo->field_annotation, $matches, PREG_SET_ORDER, 0);
        foreach (explode(",", $matches[0]["config"]) as $config) {
            $config = explode("=", trim($config), 2);
            $key = strtolower(trim($config[0]));
            $value = $config[1];
            if (in_array($key, $this->ALLOWEDMAPPINGS, true)) {
                switch($key) {
                    case "success": {
                        $this->successField = $fieldInfo->field_name;
                        $this->successValue = $value;
                        break;
                    } 
                    default: {
                        $this->map[$key] = $value; 
                        break;
                    }
                }
            }
        }
        // Is timestamp mapped? If so, extract the date format.
        if (array_key_exists("timestamp", $this->map)) {
            foreach($dd as $f) {
                if ($f->field_name == $this->map["timestamp"] && $f->field_type == "text") {
                    switch($f->text_validation_type_or_show_slider_number) {
                        case "date_ymd": $this->dateFormat = "Y-m-d"; break;
                        case "date_mdy": $this->dateFormat = "m-d-Y"; break;
                        case "date_dmy": $this->dateFormat = "d-m-Y"; break;
                        case "datetime_ymd": $this->dateFormat = "Y-m-d H:i"; break;
                        case "datetime_mdy": $this->dateFormat = "m-d-Y H:i"; break;
                        case "datetime_dmy": $this->dateFormat = "d-m-Y H:i"; break;
                        case "datetime_seconds_ymd": $this->dateFormat = "Y-m-d H:i:s"; break;
                        case "datetime_seconds_mdy": $this->dateFormat = "m-d-Y H:i:s"; break;
                        case "datetime_seconds_dmy": $this->dateFormat = "d-m-Y H:i:s"; break;
                    }
                    break;
                }
            }
        }
    }

    /**
     * Helper function that collapses the associative array into a comma-separated string of key=value pairs.
     */
    public function getCollapsedMap() 
    {
        $pairs = array();
        foreach ($this->map as $k => $v) {
            array_push($pairs, "{$k}={$v}");
        }
        return join(",", $pairs);
    }

    /**
     * Generates a GUID in the format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
     */
    private static function GUID() 
    {
        if (function_exists('com_create_guid') === true) {
            return strtolower(trim(com_create_guid(), '{}'));
        }
        return strtolower(sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535)));
    }
}


