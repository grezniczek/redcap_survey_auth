<?php namespace DE\RUB\SurveyAuthExternalModule;

/**
 * A helper class that holds information about the behavior of the SurveyAuth module.
 */
class SurveyAuthInfo 
{
    public $successField;
    public $successValue;
    public $map = array();
    public $dateFormat = "Y-m-d";

    private $ALLOWEDMAPPINGS = array("success", "username", "email", "fullname", "timestamp");

    function __construct($field_name, $misc, $dd) {
        $recordIdField = \REDCap::getRecordIdField();
        $valid_field_names = array ();
        foreach ($dd as $f) {
            if ($f->field_name != $recordIdField) {
                array_push($valid_field_names, $f->field_name);
            }
        }
        // Extract and parse parameters
        $at_params = \Form::getValueInParenthesesActionTag($misc, "@".SurveyAuthExternalModule::$ACTIONTAG);
        if (!empty($at_params)) {
            foreach (explode(",", $at_params) as $config) {
                $config = explode("=", trim($config), 2);
                $key = strtolower(trim($config[0]));
                $value = $config[1];
                if (in_array($key, $this->ALLOWEDMAPPINGS, true)) {
                    switch($key) {
                        case "success": {
                            $this->successField = $field_name;
                            $this->successValue = $value;
                            break;
                        } 
                        default: {
                            if (in_array($value, $valid_field_names)) {
                                $this->map[$key] = $value; 
                            }
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
                            case "date_ymd":
                            case "date_mdy":
                            case "date_dmy":
                                $this->dateFormat = "Y-m-d";
                                break;
                            case "datetime_ymd":
                            case "datetime_mdy":
                            case "datetime_dmy":
                                $this->dateFormat = "Y-m-d H:i"; 
                                break;
                            case "datetime_seconds_ymd":
                            case "datetime_seconds_mdy":
                            case "datetime_seconds_dmy":
                                $this->dateFormat = "Y-m-d H:i:s"; 
                                break;
                        }
                        break;
                    }
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
}
