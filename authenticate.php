<?php

namespace RUB\SurveyAuthExternalModule;

class SurveyAuthenticator {

    private $module;
    private $settings;

    function __construct($module)
    {
        $this->module = $module;
        $this->settings = new SurveyAuthSettings($module);
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
     $data = json_decode($json, true);
     if (strlen($json) > 0 && json_last_error() == JSON_ERROR_NONE) {
        // Attempt authentication and print the result.
        $username = $data["username"];
        $password = $data["password"];
        $response = $module->authenticate($username, $password);
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
