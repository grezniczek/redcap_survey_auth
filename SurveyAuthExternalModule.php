<?php

namespace RUB\SurveyAuthExternalModule;

use ExternalModules\AbstractExternalModule;

/**
 * ExternalModule class for Patient Finder.
 */
class SurveyAuthExternalModule extends AbstractExternalModule {

    public static $ACTIONTAG = "SURVEY-AUTH";
    /**
     * Used to verify the identity of this module in the ajax call to patientfinder.php.
     */
    public $IDENTITY = "5a859937-929f-4434-9b35-f2905c193030";

    /**
     * Hook function that is executed for every survey page in projects where the module is enabled.
     */
    function redcap_survey_page_top($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance = 1) {
        // Determine, whether the module runs in debug mode.
        $debug = $this->getSystemSetting("surveyauth_globaldebug") || $this->getProjectSetting("surveyauth_debug");

        // Get the project's data dictionary for the current instrument and find the action tag.
        $dd = json_decode(\REDCap::getDataDictionary($project_id, 'json', true, null, $instrument, false));
        $taggedFields = $this->getTaggedFields($dd);
        if (count($taggedFields) > 0) {


            /*
            // Inject JavaScript code.
            $jsUrl = $this->getUrl("patientfinder.js");
            print "<script type=\"text/javascript\" src=\"{$jsUrl}\"></script>";
            // Check whether the use of PatientFinder is allowed for the user.
            if ($this->isAllowed()) {
                // Inject CSS.
                $css = file_get_contents(dirname(__FILE__)."/ui.css");
                $replace = array(
                    "-PREFIX-" => $this->PREFIX
                );
                print "<style>" . str_replace(array_keys($replace), array_values($replace), $css) . "</style>";
                // Invoke setup for each PatientFinder once the page is ready.
                $queryUrl = $this->getUrl("patientfinder.php");
                foreach ($taggedFields as $pf) {
                    $template = file_get_contents(dirname(__FILE__)."/ui.html");
                    $replace = array(
                        "{GUID}" => $pf->guid,
                        "{PREFIX}" => $this->PREFIX,
                        "{SOURCE}" => $pf->source == null ? "" : $pf->source,
                        "{AUTO}" => $pf->mode == "auto" ? "true" : "false",
                        "{QUERYURL}" => $queryUrl,
                        "{RECORD}" => $record,
                        "{MAP}" => $pf->getCollapsedMap(),
                        "{DATEFORMAT}" => $pf->dateFormat,
                        "{DEBUG}" => $debug ? " data-debug=\"1\"" : ""
                    );
                    print str_replace(array_keys($replace), array_values($replace), $template);
                    print "<script type=\"text/javascript\">
                        $(function () {
                            SEGPatientFinder.setup('{$this->PREFIX}', '{$pf->guid}', '{$pf->fieldName}');
                        });
                    </script>";
                }
            }
            */
        }
    }

    /**
     * A helper function that extracts parts of the data dictionary with the module's action tag.
     */
    private function getTaggedFields($dataDictionary) {
        $fields = array();
        foreach ($dataDictionary as $fieldInfo) {
            if (strpos($fieldInfo->field_annotation, SurveyAuthExternalModule::$ACTIONTAG)) {
                array_push($fields, new SurveyAuthInfo($fieldInfo, $dataDictionary));
            }
        }
        return $fields;
    }
}

/**
 * A helper class that holds information about the behavior of the SurveyAuth widget.
 */
class SurveyAuthInfo {
    public $guid;
    public $successField;
    public $successValue;
    public $map = array();
    public $dateFormat = "dmy";

    private $ALLOWEDMAPPINGS = array("success", "username", "email", "fullname", "timestamp");

    function __construct($fieldInfo, $dd) {
        $this->guid = SurveyAuthInfo::GUID();

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
                        $parts = explode(":", $value, 2);
                        $this->successField = strtolower(trim($parts[0]));
                        $this->successValue = $parts[1];
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
    public function getCollapsedMap() {
        $pairs = array();
        foreach ($this->map as $k => $v) {
            array_push($pairs, "{$k}={$v}");
        }
        return join(",", $pairs);
    }

    /**
     * Generates a GUID in the format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
     */
    private static function GUID() {
        if (function_exists('com_create_guid') === true)
        {
            return strtolower(trim(com_create_guid(), '{}'));
        }
        return strtolower(sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535)));
    }
}


