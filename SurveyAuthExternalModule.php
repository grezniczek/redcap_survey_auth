<?php namespace DE\RUB\SurveyAuthExternalModule;

use Exception;
use ExternalModules\AbstractExternalModule;

require_once "classes/SurveyAuthSettings.php";
require_once "classes/SurveyAuthInfo.php";

/**
 * ExternalModule class for survey authentication.
 */
class SurveyAuthExternalModule extends AbstractExternalModule {
    
    public static $ACTIONTAG = "SURVEY-AUTH";

    /** @var SurveyAuthSettings Module Settings */
    private $settings;

    function redcap_module_system_change_version($version, $old_version) {
        $new = explode(".", str_replace("v", "", $version), 2);
        $new = ($new[0].".".str_replace(".", "", $new[1])) * 1;
        $old = explode(".", str_replace("v", "", $old_version), 2);
        $old = ($old[0].".".str_replace(".", "", $old[1])) * 1;
        if ($old < 1.30) {
            // Upgrade all projects with a token to canwrite and delete the token
            $projects = $this->getProjectsWithModuleEnabled();
            foreach ($projects as $pid) {
                $token = $this->getProjectSetting("surveyauth_token", $pid);
                if (!empty($token)) {
                    $this->setProjectSetting("surveyauth_canwrite", true, $pid);
                }
                // Remove in any case
                $this->removeProjectSetting("surveyauth_token", $pid);
            }
        }
    }

    function redcap_every_page_before_render($project_id) {
        $page = defined("PAGE") ? PAGE : "";
        // This hook handles three things:
        //  1. Saving dashboard protection settings
        //  2. Denying access to public dashboards when set to be blocked from the external survey endpoint
        //  3. Display and evaluate the login dialog on protected dashboards

        // (1) Saving dashboard protection settings
        if ($page == "ProjectDashController:save") {
            $this->save_dash_settings(isset($_GET["dash_id"]) ? $_GET["dash_id"] : "", $_POST);
            return;
        }
        
        // Nothing to do if not a public dashboard page or when public dashboards are disabled
        if ($page != "surveys/index.php" || !isset($_GET["__dashboard"])) return;
        if ($GLOBALS['project_dashboard_allow_public'] == '0' || !$GLOBALS["dash_id"]) return;

        // Gather data and settings
        $dash_id = $GLOBALS["dash_id"];
        $protected = $this->getProjectSetting("survey_auth_protected_$dash_id") == "1";
        $deny_external = $this->getProjectSetting("survey_auth_deny_external_$dash_id") == "1";
        $endpoint = $this->getProjectSetting("survey_auth_endpoint_$dash_id") ?? "both";
        $endpoint_options = (!empty($GLOBALS["redcap_survey_base_url"]) && $GLOBALS["redcap_base_url"] !== $GLOBALS["redcap_survey_base_url"]);

        // (2) Deny external access
        if ($endpoint_options && $deny_external) {
            $addr = $_SERVER["REQUEST_SCHEME"]."://".$_SERVER["HTTP_HOST"];
            if (starts_with($GLOBALS["redcap_survey_base_url"], $addr)) {
                $msg = $this->getProjectSetting("surveyauth_dashboardnoaccessmsg") ?? "Access to this page is not allowed from your location.";
                header("HTTP/1.0 403 Forbidden");
                print $msg;
                $this->exitAfterHook();
                return;
            }
        }

        // (3) Login

        
    }

    /**
     * Save protection settings for a dashboard
     * @param string $dash_id The dashboard ID
     * @param array $post Copy of $_POST
     * @return void 
     */
    function save_dash_settings($dash_id, $post) {
        if ($dash_id == "") return;
        if (isset($post["is_public"]) && $post["is_public"] == "on") {
            // Store settings
            $this->setProjectSetting("survey_auth_protected_$dash_id", (isset($post["survey_auth_protected"]) && $post["survey_auth_protected"] == "on") ? "1" : "0");
            $this->setProjectSetting("survey_auth_deny_external_$dash_id", (isset($post["survey_auth_deny_external"]) && $post["survey_auth_deny_external"] == "on") ? "1" : "0");
            $endpoint_setting = (isset($post["survey_auth_endpoint"]) && in_array($post["survey_auth_endpoint"], ["both", "internal", "external"])) ? $post["survey_auth_endpoint"] : "both";
            $this->setProjectSetting("survey_auth_endpoint_$dash_id", $endpoint_setting);
        }
        else {
            // Clear all settings
            $this->setProjectSetting("survey_auth_protected_$dash_id", null);
            $this->setProjectSetting("survey_auth_endpoint_$dash_id", null);
            $this->setProjectSetting("survey_auth_deny_external_$dash_id", null);
        }
    }

    function redcap_every_page_top($project_id) {
        $page = defined("PAGE") ? PAGE : "";
        if ($page != "ProjectDashController:index" || !isset($_GET["addedit"]) || $_GET["addedit"] != "1") return;
        $dash_id = isset($_GET["dash_id"]) ? $_GET["dash_id"] : "";
        if ($dash_id == "") return;
        // Is this a public dashboard?
        $dashboards = new \ProjectDashboards();
        $dash = $dashboards->getDashboards($project_id, $dash_id);
        if ($dash["is_public"] != "1") return;
        // Get protection status
        $protect = $this->getProjectSetting("survey_auth_protected_$dash_id") == "1" ? "checked='checked'" : "";
        $protect_endpoint = $this->getProjectSetting("survey_auth_endpoint_$dash_id") ?? "both";
        $deny_external = $this->getProjectSetting("survey_auth_deny_external_$dash_id") == "1" ? "checked='checked'" : "";
        $endpoint_options = (!empty($GLOBALS["redcap_survey_base_url"]) && $GLOBALS["redcap_base_url"] !== $GLOBALS["redcap_survey_base_url"]) ? "true" : "false";
        // Inject Javascript
        // This will render the input elements that allow setting the protection status for public dashboards only
        ?>
        <script>
            $(function() {
                const $container = $('#public_link_div').parent();
                $('<div></div>')
                .addClass("custom-control custom-switch mt-2")
                .append("<input class='custom-control-input' name='survey_auth_protected' id='survey_auth_protected' <?=$protect?> type='checkbox'>")
                .append("<label class='custom-control-label ms-1 mb-0' for='survey_auth_protected'>Dashboard is protected by Survey Auth</label>")
                .appendTo($container);
                if(<?= $endpoint_options ?>) {
                    // Options: Protect internal links, external links, or both; furthermore, option to deny access from external links
                    $('<div></div>')
                    .css({
                        'display': 'flex',
                        'align-items': 'center',
                        'font-weight': 'normal'
                    })
                    .addClass("ms-4 mt-1 mb-2")
                    .append("<span class='me-1'>Apply to:</span>")
                    .append("<input class='form-check-input ms-2' name='survey_auth_endpoint' id='survey_auth_endpoint_both' type='radio' value='both' <?=$protect_endpoint == "both" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='survey_auth_endpoint_both'>Both endpoints</label>")
                    .append("<input class='form-check-input ms-4' name='survey_auth_endpoint' id='survey_auth_endpoint_external' type='radio' value='external' <?=$protect_endpoint == "internal" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='survey_auth_endpoint_external'>(External) Survey endpoint only</label>")
                    .append("<input class='form-check-input ms-4' name='survey_auth_endpoint' id='survey_auth_endpoint_internal' type='radio' value='internal' <?=$protect_endpoint == "external" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='survey_auth_endpoint_internal'>(Internal) REDCap endpoint only</label>")
                    .appendTo($container);
                    $('<div></div>')
                    .addClass("custom-control custom-switch mt-1")
                    .append("<input class='custom-control-input' name='survey_auth_deny_external' id='survey_auth_deny_external' <?=$deny_external?> type='checkbox'>")
                    .append("<label class='custom-control-label ms-1' for='survey_auth_deny_external'>Deny access via (external) survey endpoint</label>")
                    .appendTo($container);
                }
            });
        </script>
        <?php
    }

    /**
     * Hook function that is executed for every survey page in projects where the module is enabled.
     */
    function redcap_survey_page_top($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance = 1) {
        if (!empty($response_id)) {
            $participant_id = $GLOBALS["participant_id"]; // \Survey::getParticipantIdFromRecordSurveyEvent($record, $survey_id, $event_id, $repeat_instance);
            $record = \Survey::getRecordFromPartId([$participant_id])[$participant_id];
            if ($record != null) {
                // We can be sure that the record exists! So we can safely do this:
                // We must set this to something other than 0 in order to get @IF action tag parsing to work (Form::evaluateIfActionTag() relies on this global).
                $GLOBALS["hidden_edit"] = 1;
            }
        }

        $this->settings = new SurveyAuthSettings($this);

        // Check if auth has already happened, in which case we stop any further processing
        if (isset($_GET["__at"])) {
            $at_blob = $this->base64_url_decode($_GET["__at"]);
            $at_decoded = $this->fromSecureBlob($at_blob);
            if ($at_decoded == "%%".$survey_hash) {
                $new_blob = $this->base64_url_encode($this->toSecureBlob("%%".$survey_hash));
                // Modify form action to include auth info
                print "<script>$(function() { $('#form').attr('action', $('#form').attr('action') + '&__at={$new_blob}'); }); </script>";
                return;
            } 
        }

        // This is needed for older versions of REDCap in order to write crytographic keys and lockouts to system settings.
        if (method_exists($this, "disableUserBasedSettingPermissions")) {
            $this->disableUserBasedSettingPermissions();
        }

        // Get the project's data dictionary for the current instrument and find the action tag.
        $dd = json_decode(\REDCap::getDataDictionary($project_id, 'json', true, null, $instrument, false));
        $taggedFields = $this->getTaggedFields($dd, $project_id, $record, $event_id, $instrument, $repeat_instance);
        // If there is none, then there is nothing to do.
        if (!count($taggedFields)) return;

        // Default response (unless changed)
        $response = array ( 
            "success" => false,
            "error" => null
        );

        // Get values from POST.
        if (isset($_POST["{$this->PREFIX}-username"]) && 
            isset($_POST["{$this->PREFIX}-password"]) &&
            isset($_POST["{$this->PREFIX}-blob"])) {
            // Band-aid fix: Remove log entry with clear text password from redcap_log_view table
            $delete_log = $this->query(
                "DELETE FROM `redcap_log_view` WHERE `project_id` = ? AND `event` = 'PAGE_VIEW' AND `form_name` = ? AND `miscellaneous` LIKE '// POST%[redcap_survey_auth-password]%'",
                [
                    $project_id,
                    $instrument
                ]
            );
            // Extract data from POST.
            $username = $_POST["{$this->PREFIX}-username"];
            $password = $_POST["{$this->PREFIX}-password"];
            $encrypted_blob = $_POST["{$this->PREFIX}-blob"];
            // Validate blob.
            $blob = $this->fromSecureBlob($encrypted_blob);
            if ($blob == null || $blob["project_id"] != $project_id || $blob["survey_hash"] != $survey_hash) {
                $response = array (
                    "success" => false,
                    "error" => $this->settings->failMsg
                );
            }
            else {
                // Blob was valid, try to authenticate.
                $record = $record ?? $blob["record"];
                $response = $this->authenticate($username, $password, $project_id, $instrument, $event_id, $repeat_instance, $record);
            }
        }

        $logo = "";

        // Success? If not, then authentication needs to be performed.
        if ($response["success"] !== true) {

            // Inject JavaScript and HTML.
            $js = file_get_contents(__DIR__ . "/surveyauth.js");
            $orig_query_params = explode("?", $_SERVER["REQUEST_URI"], 2)[1] ?? "";
            $orig_query_params = strlen($orig_query_params) ? "?$orig_query_params" : "";
            $queryUrl = APP_PATH_SURVEY_FULL . $orig_query_params;
            $blob = $this->toSecureBlob(array(
                "project_id" => $project_id,
                "survey_hash" => $survey_hash,
                "instrument" => $instrument,
                "event_id" => $event_id,
                "repeat_instance" => $repeat_instance,
                "record" => $record,
                "random" => $this->genKey(16) // Add some random stuff.
            ));
            $response_hash = "";
            if (!empty($response_id)) {
                $response_hash = \Survey::encryptResponseHash($response_id, $participant_id);
                $response_hash = "<input type=\"hidden\" name=\"__response_hash__\" value=\"{$response_hash}\">";
            }
            $record_id_field = \REDCap::getRecordIdField();
            $record_id = $record == null ? "" : "<input type=\"hidden\" name=\"{$record_id_field}\" value=\"{$record}\">";
            $isMobile = isset($GLOBALS["isMobileDevice"]) && $GLOBALS["isMobileDevice"];
            if (is_numeric($GLOBALS["logo"])) {
                //Set max-width for logo (include for mobile devices)
                $logo_width = $isMobile ? '300' : '600';
                // Get img dimensions (local file storage only)
                $thisImgMaxWidth = $logo_width;
                $styleDim = "max-width:{$thisImgMaxWidth}px;";
                if (method_exists("\Files", "getImgWidthHeightByDocId")) {
                    list ($thisImgWidth, $thisImgHeight) = \Files::getImgWidthHeightByDocId($GLOBALS["logo"]);
                    if (is_numeric($thisImgHeight)) {
                        $thisImgMaxHeight = round($thisImgMaxWidth / $thisImgWidth * $thisImgHeight);
                        if ($thisImgWidth < $thisImgMaxWidth) {
                            // Use native dimensions.
                            $styleDim = "width:{$thisImgWidth}px;max-width:{$thisImgWidth}px;height:{$thisImgHeight}px;max-height:{$thisImgHeight}px;";
                        } else {
                            // Shrink size.
                            $styleDim = "width:{$thisImgMaxWidth}px;max-width:{$thisImgMaxWidth}px;height:{$thisImgMaxHeight}px;max-height:{$thisImgMaxHeight}px;";
                        }
                    }
                }
                if (method_exists("\Files", "docIdHash")) {
                    $logo = "<div style=\"padding:10px 0 0;\"><img id=\"survey_logo\" onload=\"try{reloadSpeakIconsForLogo()}catch(e){}\" " .
                        "src=\"".APP_PATH_SURVEY."index.php?pid={$project_id}&doc_id_hash=".\Files::docIdHash($GLOBALS["logo"]) .
                        "&__passthru=".urlencode("DataEntry/image_view.php")."&s={$GLOBALS["hash"]}&id={$GLOBALS["logo"]}\" alt=\"" . 
                        js_escape($GLOBALS["lang"]["survey_1140"])."\" title=\"".js_escape($GLOBALS["lang"]["survey_1140"]) .
                        "\" style=\"max-width:{$logo_width}px;$styleDim\"></div>";
                }
            }
            $mobile = $isMobile ? "_mobile" : "";
            $template = file_get_contents(__DIR__ . "/ui{$mobile}.html");
            $replace = array(
                "{JS}" => $js,
                "{LOGO}" => $logo,
                "{PREFIX}" => $this->PREFIX,
                "{QUERYURL}" => $queryUrl,
                "{SURVEYTITLE}" => $GLOBALS["title"],
                "{INSTRUCTIONS}" => $this->settings->text,
                "{USERNAMELABEL}" => $this->settings->usernameLabel,
                "{PASSWORDLABEL}" => $this->settings->passwordLabel,
                "{SUBMITLABEL}" => $this->settings->submitLabel,
                "{FAILMSG}" => $response["error"],
                "{ERROR}" => strlen($response["error"]) ? "block" : "none",
                "{BLOB}" => $blob,
                "{RECORDID}" => $record_id,
                "{RESPONSEHASH}" => $response_hash,
            );
            print str_replace(array_keys($replace), array_values($replace), $template);
            // No further processing (i.e. do not let REDCap render the survey page).
            $this->exitAfterHook();
        }
        else {
            // Success == true means that authentication has succeded.
            // When a forward url is define, then forward
            if (isset($response["targetUrl"])) {
                $template = file_get_contents(__DIR__ . "/forward.html");
                $replace = array(
                    "{LOGO}" => $logo,
                    "{PREFIX}" => $this->PREFIX,
                    "{SURVEYTITLE}" => $GLOBALS["title"],
                    "{SUCCESSMSG}" => $this->settings->successMsg,
                    "{CONTINUELABEL}" => $this->settings->continueLabel,
                    "{TARGETURL}" => $response["targetUrl"],
                );
                print str_replace(array_keys($replace), array_values($replace), $template);
                // No further processing (i.e. do not let REDCap render the survey page).
                $this->exitAfterHook();
            }
            // Otherwise, there is nothing to do. We let the user continue to the survey.
        }
    }

    /**
     * A helper function that extracts parts of the data dictionary with the module's action tag.
     */
    private function getTaggedFields($dataDictionary, $project_id, $record, $event_id, $instrument, $repeat_instance) {
        $fields = array();
        foreach ($dataDictionary as $fieldInfo) {
            $evaluatedFieldAnnotation = \Form::replaceIfActionTag($fieldInfo->field_annotation, $project_id, $record ?? "1", $event_id, $instrument, $repeat_instance);
            if (strpos($evaluatedFieldAnnotation, "@".SurveyAuthExternalModule::$ACTIONTAG)) {
                array_push($fields, new SurveyAuthInfo($fieldInfo->field_name, $evaluatedFieldAnnotation, $dataDictionary));
            }
        }
        return $fields;
    }

    private function base64_url_encode($input) {
        return strtr($input, '+/=', '._-');
    }

    private function base64_url_decode($input) {
        return strtr($input, '._-', '+/=');
    }


    /**
     * Determines, whether the credentials are valid.
     */
    function authenticate($username, $password, $project_id, $instrument, $event_id, $repeat_instance, $record) {
        $result = array (
            "success" => false,
            "username" => $username,
            "email" => null,
            "fullname" => null,
            "error" => null,
            "log_error" => array()
        );
        $ip = $_SERVER["REMOTE_ADDR"];
        if (strlen($_SERVER["HTTP_X_FORWARDED_FOR"])) $ip .= $_SERVER["HTTP_X_FORWARDED_FOR"];

        try {
            do {
                // Check lockout status.
                $lockoutCount = $this->checkLockoutStatus($ip);
                if ($this->settings->lockoutCount && $lockoutCount > $this->settings->lockoutCount - 1) {
                    $result["error"] = $this->settings->lockoutMsg;
                    $result["lockout"] = $this->settings->lockouttime * 60 * 1000;
                    break;
                }
                // Check credentials.
                // First, let's see if the whitelist is active.
                if ($this->settings->useWhitelist && !in_array(strtolower($username), $this->settings->whitelist)) {
                    break;
                }
                // Check custom credentials if enabled.
                if (!$result["success"] && $this->settings->useCustom) {
                    $this->authenticateCustom($username, $password, $result);
                }
                // Check REDCap table-based users.
                if (!$result["success"] && $this->settings->useTable) {
                    $this->authenticateTable($username, $password, $result);
                }
                // Check LDAP.
                if (!$result["success"] && $this->settings->useLDAP) {
                    $this->authenticateLDAP($username, $password, $result);
                }
                // Check other LDAP.
                if (!$result["success"] && $this->settings->useOtherLDAP) {
                    $this->authenticateOtherLDAP($username, $password, $result);
                }
                if (!$result["success"]) {
                    $result["error"] = count($result["log_error"]) ? $this->settings->errorMsg : $this->settings->failMsg;
                    // Update lockout status.
                    $this->updateLockoutStatus($ip);
                    break;
                }
                // Login was successful.
                if ($lockoutCount > 0) {
                    $this->clearLockoutStatus($ip);
                }
                // Determine, whether any data should be written to the form 
                $dd = json_decode(\REDCap::getDataDictionary($project_id, 'json', true, null, $instrument, false));
                $taggedFields = $this->getTaggedFields($dd, $project_id, $record, $event_id, $instrument, $repeat_instance);
                if (!count($taggedFields)) {
                    $result["log_error"][] = "Could not find a field tagged with the @" . self::$ACTIONTAG . " action tag.";
                }
                else {
                    // Use first, any further are ignored
                    $tf = $taggedFields[0];
                    $record_created = false;
                    // Anything to do?
                    if ($this->settings->canwrite && count($tf->map)) {
                        // If this is a nonpublic survey, $record will be set so. Otherwise, we have to get it after saving
                        $new_record = $record == null;
                        if ($new_record) {
                            // Use "NEW" - it will be overwritten later
                            $record = "NEW";
                        }
                        $result["timestamp"] = date($tf->dateFormat);
                        $data_values = array();
                        if (strlen($tf->successField)) $data_values[$tf->successField] = $tf->successValue;
                        // Add mapped data items.
                        foreach ($tf->map as $k => $v) {
                            if (strlen($tf->map[$k])) $data_values[$v] = $result[$k];
                        }
                        // Prepare data object for REDCap::saveData
                        $Proj = new \Project($project_id);
                        if ($Proj->isRepeatingEvent($event_id)) {
                            $data_to_save = array(
                                $record => array(
                                    "repeat_instances" => array(
                                        $event_id => array(
                                            "" => array(
                                                $repeat_instance => $data_values
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        else if ($Proj->isRepeatingForm($event_id, $instrument)) {
                            $data_to_save = array(
                                $record => array(
                                    "repeat_instances" => array(
                                        $event_id => array(
                                            $instrument => array(
                                                $repeat_instance => $data_values
                                            )
                                        )
                                    )
                                )
                            );
                        }
                        else {
                            $data_to_save = array(
                                $record => array(
                                    $event_id => $data_values
                                )
                            );
                        }
                        $response = \REDCap::saveData(
                            $project_id,       // project_id
                            'array',           // dataFormat
                            $data_to_save,     // data
                            'normal',          // overwriteBehavior
                            null,              // dateFormat
                            null,              // type (eav, flat)
                            null,              // group_id
                            true,              // dataLogging
                            true,              // performAutoCalc
                            true,              // commitData
                            false,             // logAsAutoCalculations
                            true,              // skipCalcFields
                            [],                // changeReasons
                            false,             // returnDataComparisonArray
                            true,              // skipFileUploadFields
                            false,             // removeLockedFields
                            $new_record,       // addingAutoNumberedRecords
                            true,              // bypassPromisCheck
                            null,              // csvDelimiter
                            false,             // bypassEconsentProtection
                            null               // loggingUser
                        );
                        if (isset($response["error"])) {
                            if ($new_record) $record = null;
                            $result["success"] = false;
                            $result["error"] = $this->settings->errorMsg;
                            $result["log_error"][] = "Failed to create a new record: " . $response["error"];
                            break;
                        }
                        else {
                            $record_created = true;
                            if ($new_record) {
                                $record = $response["ids"][$record];
                            }
                        }
                    }
                    // Get link to survey and add auth info
                    if ($record == null) {
                        $survey_id = \Survey::getSurveyId($instrument);
                        $survey_hash = \Survey::getSurveyHash($survey_id, $event_id);
                        $link = APP_PATH_SURVEY_FULL . "?s={$survey_hash}";
                    }
                    else {
                        $link = \REDCap::getSurveyLink($record, $instrument, $event_id, $repeat_instance, $project_id, $record_created);
                        $survey_hash = explode("?s=", $link, 2)[1];
                    }
                    $at = $this->toSecureBlob("%%".$survey_hash);
                    $result["targetUrl"] = $link . "&__at=" . $this->base64_url_encode($at);
                    $result["record"] = $record;
                }
            } while (false);
        }
        catch (\Exception $e) {
            $result["success"] = false;
            $result["error"] = $this->settings->errorMsg;
            $result["log_error"][] = $e->getMessage();
        }
        // Write a log entry.
        if ($this->settings->log == "all" || ($this->settings->log == "fail" && !$result["success"]) || ($this->settings->log == "success" && $result["success"])) {
            $changes = $result["success"] ? "Successful authentication via {$result["method"]}" : "Failed or denied login attempt (IP: {$ip})";
            if (count($result["log_error"])) {
                $changes .= "\n" . join("\n", $result["log_error"]);
            }
            $logData = array(
                "action_description" => "Survey Auth EM",
                "changes_made" => $changes,
                "sql" => null,
                "record" => $record,
                "event" => null,
                "project_id" => $GLOBALS["project_id"]
            );
            \REDCap::logEvent($logData["action_description"], $logData["changes_made"], $logData["sql"], $logData["record"], $logData["event"], $logData["project_id"]);
        }
        // Return result.
        return $result;
    }


    private function authenticateTable($username, $password, &$result) {
        try {
            if (\Authentication::verifyTableUsernamePassword($username, $password)) {
                $result["success"] = true;
                $result["method"] = "Table";
                try {
                    $ui = \User::getUserInfo($username);
                    $result["email"] = $ui["user_email"];
                    $result["fullname"] = trim("{$ui["user_firstname"]} {$ui["user_lastname"]}");
                }
                catch (\Exception $e) {
                    $result["log_error"][] = $e->getMessage();
                }
            }
        }
        catch (\Exception $e) {
            $result["log_error"][] = $e->getMessage();
        }
    }

    private function authenticateCustom($username, $password, &$result) {
        $username = strtolower($username);
        if (isset($this->settings->customCredentials[$username]) && $this->settings->customCredentials[$username] == $password) {
            $result["success"] = true;
            $result["method"] = "Custom";
        }
    }

    private function authenticateLDAP($username, $password, &$result) {
        include APP_PATH_WEBTOOLS . 'ldap/ldap_config.php';
        $configs = isset($GLOBALS["ldapdsn"]) ? $GLOBALS["ldapdsn"] : array();
        if (array_key_exists("url", $configs)) $configs = array ($configs);

        foreach ($configs as $config) {
            $this->doLDAPauth($username, $password, $config, $result);
            if ($result["success"]) {
                $result["method"] = "LDAP";
            }
        }
        if (!count($configs)) {
            $result["log_error"][] = "No REDCap LDAP configurations are available.";
        }
    }

    private function authenticateOtherLDAP($username, $password, &$result) {
        if (count($this->settings->otherLDAPConfigs) < 1) {
            $result["log_error"][] = "No 'Other LDAP' configurations available.";
        }
        foreach ($this->settings->otherLDAPConfigs as $config) {
            $this->doLDAPauth($username, $password, $config, $result);
            if ($result["success"]) {
                $result["method"] = "Other LDAP ({$config["host"]}:{$config["port"]})";
                break;
            }
        }
    }

    //region LDAP

    private function doLDAPauth($username, $password, $config, &$result) {
        // As we rely on the ldap module, check that it has been loaded.
        if (!extension_loaded("ldap")) {
            $result["log_error"][] = "LDAP extension not loaded.";
            return;
        }
        $config = $this->mergeLDAPConfig($config);
        try {
            // Connect to LDAP server.
            $ldap = ldap_connect($config["url"], $config["port"]);
            if ($ldap === false) {
                 throw new \Exception("Failed to connect to LDAP server.");
            }
            // Check version and TLS.
            if (is_numeric($config["version"]) && $config["version"] > 2) {
                @ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, $config["version"]);
                if (isset($config["start_tls"]) && $config["start_tls"]) {
                    if (@ldap_start_tls($ldap) === false) {
                        throw new \Exception("Could not start TLS session.");
                    }
                }
            }
            // Switch referrals.
            if (isset($config["referrals"]) && is_bool($config["referrals"])) {
                if (@ldap_set_option($ldap, LDAP_OPT_REFERRALS, $config["referrals"]) === false) {
                    throw new \Exception("Could not change LDAP referral options");
                }
            }
            // Bind with credentials or anonymously.
            if (strlen($config['binddn']) && strlen($config['bindpw'])) {
                if (@ldap_bind($ldap, $config["binddn"], $config["bindpw"]) === false) {
                    throw new \Exception("LDAP bind with credentials failed.");
                }
            } 
            else {
                if (@ldap_bind($ldap) === false) {
                    throw new \Exception("Anonymous LDAP bind failed.");
                }
            }
            $this->checkBaseDN($ldap, $config);
            // UTF8 Encode username for LDAPv3.
            if (@ldap_get_option($ldap, LDAP_OPT_PROTOCOL_VERSION, $version) && $version == 3) {
                $username = utf8_encode($username);
            }
            // Prepare search filter.
            $filter = sprintf("(&(%s=%s)%s)", $config['userattr'], $this->quoteFilterString($username), $config['userfilter']);
            $searchBasedn = $config["userdn"];
            // Prepare search base dn.
            $searchBasedn = $config["userdn"];
            if ($searchBasedn != "" && substr($searchBasedn, -1) != ",") {
                $searchBasedn .= ",";
            }
            $searchBasedn .= $config["basedn"];
            $searchAttributes = $config["attributes"];
            // Assemble parameters and determine function to use.
            $funcParams = array($ldap, $searchBasedn, $filter, $searchAttributes);
            $searchFunc = array(
                "one" => "ldap_list",
                "base" => "ldap_read",
                "sub" => "ldap_search"
            );
            $scope = isset($config["userscope"]) && in_array($config["userscope"], array_keys($searchFunc), true) ? $config["userscope"] : "sub";
            $searchFunc = $searchFunc[$scope];

            // Search.

            if (($resultId = @call_user_func_array($searchFunc, $funcParams)) === false) {
                // User not found.
            } 
            elseif (@ldap_count_entries($ldap, $resultId) >= 1) { 
                $entryId = @ldap_first_entry($ldap, $resultId);
                while ($entryId !== false) {
                    // Get the user dn.
                    $userDn = @ldap_get_dn($ldap, $entryId);
                    // Get attributes.
                    if ($attributes = @ldap_get_attributes($ldap, $entryId)) {
                        if (is_array($attributes) && count($attributes) > 0) {
                            // Extract data.
                            $data = array();
                            foreach (array_keys($this->settings->ldapMappings) as $key) {
                                $data[$key] = "";
                                foreach ($this->settings->ldapMappings[$key] as $attributeName) {
                                    if (isset($attributes[$attributeName]) && $attributes[$attributeName]["count"] >= 1) {
                                        $data[$key] = trim($attributes[$attributeName][0]);
                                        break;
                                    }
                                }
                            }
                            $result["fullname"] = strlen($data["fullname"]) ? $data["fullname"] : trim("{$data["firstname"]} {$data["lastname"]}");
                            $result["email"] = strtolower($data["email"]);
                        }
                    }
                    @ldap_free_result($resultId);
                    // Beware of empty passwords!
                    if ($password != "") {
                        // Try binding with the supplied user credentials.
                        if (@ldap_bind($ldap, $userDn, $password)) {
                            // Check group if appropiate.
                            if (strlen($config["group"])) {
                                // Check type of memberattr (dn or username).
                                $inGroup = $this->checkGroup($ldap, $config, ($config['memberisdn']) ? $userDn : $username);
                                $result["success"] = $inGroup;
                            } 
                            else {
                                $result["success"] = true;
                            }
                            if ($result["success"]) {
                                // Try to retrieve attributes while bound as the user.
                                if (($resultId = @ldap_read($ldap, $userDn, $filter, $searchAttributes)) !== false) {
                                    if (@ldap_count_entries($ldap, $resultId) >= 1) {
                                        $entryId = @ldap_first_entry($ldap, $resultId);
                                        while ($entryId !== false) {
                                            // Get the user dn.
                                            // The dn should match the user's dn exactly.
                                            if ($userDn != @ldap_get_dn($ldap, $entryId)) continue;
                                            // Get attributes.
                                            if ($attributes = @ldap_get_attributes($ldap, $entryId)) {
                                                if (is_array($attributes) && count($attributes) > 0) {
                                                    // Extract data.
                                                    $data = array();
                                                    foreach (array_keys($this->settings->ldapMappings) as $key) {
                                                        $data[$key] = "";
                                                        foreach ($this->settings->ldapMappings[$key] as $attributeName) {
                                                            if (isset($attributes[$attributeName]) && $attributes[$attributeName]["count"] >= 1) {
                                                                $data[$key] = trim($attributes[$attributeName][0]);
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    // Use data from here to set (overwrite) result if not empty.
                                                    $fullname = strlen($data["fullname"]) ? $data["fullname"] : trim("{$data["firstname"]} {$data["lastname"]}");
                                                    if (strlen($fullname)) $result["fullname"] = $fullname;
                                                    if (strlen($data["email"])) $result["email"] = strtolower($data["email"]);
                                                }
                                            }
                                            $entryId = @ldap_next_entry($ldap, $entryId);
                                        }
                                    }
                                    @ldap_free_result($resultId);
                                }
                                break;
                            }
                        }
                    }
                    $entryId = @ldap_next_entry($ldap, $entryId);
                }
            }
            @ldap_unbind($ldap);
            // Optional fallback mapping of username and email from REDCap's user table
            if ($this->settings->fallbackToTableUserInfo && (empty($result["fullname"]) || empty($result["email"]))) {
                $sql = "SELECT `user_email`, `user_firstname`, `user_lastname` FROM redcap_user_information WHERE `username` = ? LIMIT 1";
                $q = $this->query($sql, [$result["username"]]);
                if ($row = $q->fetch_assoc()) {
                    if (empty($result["fullname"])) $result["fullname"] = trim("{$row["user_firstname"]} {$row["user_lastname"]}");
                    if (empty($result["email"])) $result["email"] = $row["user_email"];
                }
            }
        }
        catch (\Exception $e) {
            $result["log_error"][] = "LDAP error: " . $e->getMessage();
        }
        // Close a potentially open connection
        try {
            @ldap_unbind($ldap);
        }
        catch (\Throwable $t) { 
            // Ignore 
        }
    }

    private function checkBaseDN($ldap, &$config) {
        if (!isset($config["basedn"])) $config["basedn"] = "";
        if ($config["basedn"] == "") {
            $result_id = @ldap_read($ldap, "", "(objectclass=*)", array("namingContexts"));
            if (@ldap_count_entries($ldap, $result_id) == 1) {
                $entry_id = @ldap_first_entry($ldap, $result_id);
                $attrs = @ldap_get_attributes($ldap, $entry_id);
                $basedn = $attrs['namingContexts'][0];
                if ($basedn != "") {
                    $config["basedn"] = $basedn;
                }
            }
            @ldap_free_result($result_id);
        }
        if ($config["basedn"] == "") {
            throw new \Exception("LDAP search base not specified.");
        }
    }

    /**
     * Escapes LDAP filter special characters as defined in RFC 2254.
     */
    private function quoteFilterString($raw) {
        $search = array('\\', '*', '(', ')', "\x00");
        $replace = array('\\\\', '\*', '\(', '\)', "\\\x00");
        return str_replace($search, $replace, $raw);
    }
    
    private function mergeLDAPConfig($config) {
        $defaultConfig = array(
            "url" => "",
            "host" => 'localhost',
            "port" => '389',
            "version" => 2,
            "referrals" => true,
            "binddn" => "",
            "bindpw" => "",
            "basedn" => "",
            "userdn" => "",
            "userscope" => "sub",
            "userattr" => "uid",
            "userfilter" => "(objectClass=posixAccount)",
            "attributes" => array(""), 
            "group" => "",
            "groupdn" => "",
            "groupscope" => "sub",
            "groupattr" => "cn",
            "groupfilter" => "(objectClass=groupOfUniqueNames)",
            "memberattr" => "uniqueMember",
            "memberisdn" => true,
            "start_tls" => false,
            "debug" => false,
            "try_all" => false
        );
        foreach ($config as $k => $v) {
            $defaultConfig[$k] = $v;
        }
        return $defaultConfig;
    }

    private function checkGroup($ldap, $config, $user) {
        // Make filter.
        $filter = sprintf("(&(%s=%s)(%s=%s)%s)", $config["groupattr"], $config["group"], $config["memberattr"], $this->quoteFilterString($user), $config["groupfilter"]);
        // Make search base dn,
        $searchBasedn = $config["groupdn"];
        if ($searchBasedn != "" && substr($searchBasedn, -1) != ",") {
            $searchBasedn .= ",";
        }
        $searchBasedn .= $config["basedn"];

        // Assemble parameters and determine function to use.
        $funcParams = array($ldap, $searchBasedn, $filter, array($config["memberattr"]));
        $searchFunc = array(
            "one" => "ldap_list",
            "base" => "ldap_read",
            "sub" => "ldap_search"
        );
        $scope = isset($config["groupscope"]) && in_array($config["groupscope"], array_keys($searchFunc), true) ? $config["groupscope"] : "sub";
        $searchFunc = $searchFunc[$scope];

        // Search.
        if (($resultId = @call_user_func_array($searchFunc, $funcParams)) != false) {
            if (@ldap_count_entries($ldap, $resultId) == 1) {
                @ldap_free_result($resultId);
                return true;
            }
        }
        // User is not a member of the group.
        return false;
    }

    //endregion

    //region Lockout

    /**
     * Helper function which checks whether failed login attempts have been recorded for an IP address.
     */
    private function checkLockoutStatus($ip) {
        if (isset($this->settings->lockoutStatus[$ip])) {
            $ls = $this->settings->lockoutStatus[$ip];
            if ($ls["n"] > 2) {
                $ts = $ls["ts"];
                if (((new \DateTime)->getTimestamp() - $ts) > ($this->settings->lockouttime * 60)) {
                    return 2;
                }
                $this->updateLockoutStatus($ip);
            }
            return $ls["n"];
        } 
        return 0;
    }

    /**
     * Helper function which updates the lockout status for an IP address.
     */
    private function updateLockoutStatus($ip) {
        if ($this->settings->lockouttime != 0) {
            $ls = isset($this->settings->lockoutStatus[$ip]) ? $this->settings->lockoutStatus[$ip] : array("n" => 0);
            $ls["n"]++;
            $ls["ts"] = (new \DateTime())->getTimestamp();
            $this->settings->lockoutStatus[$ip] = $ls;
            $this->setSystemSetting("surveyauth_lockouts", json_encode($this->settings->lockoutStatus));
        }
    }

    /**
     * Helper function which clears the lockout status for an IP address.
     */
    private function clearLockoutStatus($ip) {
        if (isset($this->settings->lockoutStatus[$ip])) {
            unset($this->settings->lockoutStatus[$ip]);
            $this->setSystemSetting("surveyauth_lockouts", json_encode($this->settings->lockoutStatus));
        }
    }

    //endregion

    //region Secret Blobs

    private $cipher = "AES-256-CBC";

    /**
     * Helper function to package an array into an encrytped blob (base64-encoded).
     * $data is expected to be an associative array.
     */
    private function toSecureBlob($data) {
        $this->checkKeys();
        $jsonData = json_encode($data);
        $key = base64_decode($this->settings->blobSecret);
        $ivLen = openssl_cipher_iv_length($this->cipher);
        $iv = openssl_random_pseudo_bytes($ivLen);
        $aesData = openssl_encrypt($jsonData, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $aesData, $this->settings->blobHmac, true);
        $blob = base64_encode($iv.$hmac.$aesData);
        return $blob;
    }

    /**
     * Helper function to decode an encrypted data blob.
     * Retruns an associative array or null if there was a problem.
     */
    private function fromSecureBlob($blob) {
        $this->checkKeys();
        $raw = base64_decode($blob);
        $key = base64_decode($this->settings->blobSecret);
        $ivlen = openssl_cipher_iv_length($this->cipher);
        $iv = substr($raw, 0, $ivlen);
        $blobHmac = substr($raw, $ivlen, 32);
        $aesData = substr($raw, $ivlen + 32);
        $jsonData = openssl_decrypt($aesData, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        $calcHmac = hash_hmac('sha256', $aesData, $this->settings->blobHmac, true);
        // Only return data if the hashes match.
        return hash_equals($blobHmac, $calcHmac) ? json_decode($jsonData, true) : null;
    }

    /**
     * Checks if cryptographic keys have been generated already, and if not generates and stores them.
     */
    private function checkKeys() {
        if (!strlen($this->settings->blobSecret)) {
            $this->settings->blobSecret = $this->genKey(32);
            $this->setSystemSetting("surveyauth_blobsecret", $this->settings->blobSecret);
        }
        if (!strlen($this->settings->blobHmac)) {
            $this->settings->blobHmac = $this->genKey(32);
            $this->setSystemSetting("surveyauth_blobhmac", $this->settings->blobHmac);
        }
    }

    private function genKey($keySize) {
        $key = openssl_random_pseudo_bytes($keySize);
        return base64_encode($key);
    }

    //endregion
}
