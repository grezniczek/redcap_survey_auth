<?php

namespace RUB\SurveyAuthExternalModule;

// Check if this was properly called through the EM framework and within the context of a project.
if (isset($module) &&  isset($module->IDENTITY) && $module->IDENTITY == "5a859937-929f-4434-9b35-f2905c193030" && isset($GLOBALS["project_id"])) {
    // Get values from POSTed json.
     $json = file_get_contents("php://input");
     $data = json_decode($json, true);
     if (strlen($json) > 0 && json_last_error() == JSON_ERROR_NONE) {
        // Attempt authentication and print the result.
        $username = "{$data["username"]}";
        $password = "{$data["password"]}";
        $blob = "{$data["blob"]}";
        $response = $module->authenticate($username, $password, $blob);
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