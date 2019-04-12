<?php

namespace RUB\SurveyAuthExternalModule;

class SurveyAuthenticator {

    private $record;
    private $debug = false;
    private $em;
    private $dateFormat = "d-m-Y";
    private $supportedDateFormats = array("Y-m-d", "m-d-Y", "d-m-Y", "Y-m-d H:i", "m-d-Y H:i", "d-m-Y H:i", "Y-m-d H:i:s", "m-d-Y H:i:s", "d-m-Y H:i:s");

    function __construct($record, $dateFormat, $module)
    {
        $this->record = $record;
        $this->em = $module;
        $this->debug = $module->getSystemSetting("patientfinder_globaldebug") || $module->getProjectSetting("patientfinder_debug");
        // Date format.
        if (in_array($dateFormat, $this->supportedDateFormats)) {
            $this->dateFormat = $dateFormat;
        }
    }

    public function Authenticate($username, $password) {

        $success = true;
        $error = "";

        if ($success) {
            $timestamp = date("Y-m-d H:i:s");
            $logData = array(
                "action_description" => "SurveyAuth: Performed authentication operation ({$timestamp})",
                "changes_made" => null,
                "sql" => null,
                "record" => $this->record,
                "event" => null,
                "project_id" => $GLOBALS["project_id"]
            );
            // Write the log entry
            \REDCap::logEvent($logData["action_description"], $logData["changes_made"], $logData["sql"], $logData["record"], $logData["event"], $logData["project_id"]);
        }

        $json = array(
            "success" => $success,
            "error" => $error
        );

        // Return response as JSON.
        return json_encode($json);
    }
}

// Check if this was properly called through the EM framework.
if (isset($module) &&  isset($module->IDENTITY) && $module->IDENTITY == "5a859937-929f-4434-9b35-f2905c193030") {
    // Get values from POSTed json.
     $json = file_get_contents("php://input");
     $params = json_decode($json);
     if (strlen($json) > 0 && json_last_error() == JSON_ERROR_NONE) {
        // Initialize authenticator with the parameters.
        $sa = new SurveyAuthenticator(trim($params["record"]), trim($params["dateFormat"]), $module);
        // Attempt authentication and print the result.
        $response = $sa->Authenticate($username, $password);
        print $response;
     }
     else {
         print json_encode(array(
             "success" => false,
             "error" => "Invalid request."
         ));
     }
}
else {
    // Something is wrong. Hack attack?
    print json_encode(array(
        "success" => false,
        "error" => "You are not allowed to do this."
    ));
}
