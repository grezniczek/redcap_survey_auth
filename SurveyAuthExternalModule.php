<?php
namespace RUB\SurveyAuthExternalModule;


use ExternalModules\AbstractExternalModule;

/**
 * ExternalModule class for survey authentication.
 */
class SurveyAuthExternalModule extends AbstractExternalModule {
    
    public static $ACTIONTAG = "SURVEY-AUTH";

    /** @var SurveyAuthSettings Module Settings */
    private $settings;

    /**
     * Hook function that is executed for every survey page in projects where the module is enabled.
     */
    function redcap_survey_page_top($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance = 1) 
    {
        // Only authenticate public surveys, i.e. when $record == null.
        if ($record !== null) return;

        // This is needed for older versions of REDCap in order to write crytographic keys and lockouts to system settings.
        if (method_exists($this, "disableUserBasedSettingPermissions")) {
            $this->disableUserBasedSettingPermissions();
        }

        $recordIdField = \REDCap::getRecordIdField();

        // Get the project's data dictionary for the current instrument and find the action tag.
        $dd = json_decode(\REDCap::getDataDictionary($project_id, 'json', true, null, $instrument, false));
        $taggedFields = $this->getTaggedFields($dd, $recordIdField);
        // If there is none, then there is nothing to do.
        if (!count($taggedFields)) return;

        $this->settings = new SurveyAuthSettings($this);
        
        // State management.
        $response = array ( 
            "success" => false,
            "error" => null
        );

        // Get values from POST.
        if (isset($_POST["{$this->PREFIX}-username"]) && 
            isset($_POST["{$this->PREFIX}-password"]) &&
            isset($_POST["{$this->PREFIX}-blob"])) {
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
                $response = $this->authenticate($username, $password, $project_id, $instrument, $event_id, $repeat_instance);
            }
        }

        // Success? If not, then authentication needs to be performed.
        if ($response["success"] !== true) {

            // Inject JavaScript and HTML.
            $js = file_get_contents(__DIR__ . "/surveyauth.js");
            print "<script>\n$js\n</script>";
            $queryUrl = APP_PATH_SURVEY_FULL . "?s=" . $survey_hash;
            $blob = $this->toSecureBlob(array(
                "project_id" => $project_id,
                "survey_hash" => $survey_hash,
                "instrument" => $instrument,
                "event_id" => $event_id,
                "repeat_instance" => $repeat_instance,
                "random" => $this->genKey(16) // Add some random stuff.
            ));
            $isMobile = isset($GLOBALS["isMobileDevice"]) && $GLOBALS["isMobileDevice"];
            $logo = "";
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
            );
            print str_replace(array_keys($replace), array_values($replace), $template);
            // No further processing (i.e. do not let REDCap render the survey page).
            $this->exitAfterHook();
        }
        else {
            // Success == true means that authentication has succeded.
            if ($response["mode"] == "token") {
                // In token mode, the record has been created. Thus, display a forwarder to the record-specific survey id.
                $template = file_get_contents(__DIR__ . "/forward.html");
                $replace = array(
                    "{LOGO}" => $logo,
                    "{PREFIX}" => $this->PREFIX,
                    "{SURVEYTITLE}" => $GLOBALS["title"],
                    "{SUCCESSMSG}" => $this->settings->successMsg,
                    "{CONTINUELABEL}" => $this->settings->continueLabel,
                    "{TARGETURL}" => $response["targetUrl"]
                );
                print str_replace(array_keys($replace), array_values($replace), $template);
                // No further processing (i.e. do not let REDCap render the survey page).
                $this->exitAfterHook();
            }
            else {
                // In simple mode, there is nothing to do. We let the user continue to the survey in anonymous mode.
            }
        }
    }

    /**
     * A helper function that extracts parts of the data dictionary with the module's action tag.
     */
    private function getTaggedFields($dataDictionary, $recordIdField) 
    {
        $fields = array();
        foreach ($dataDictionary as $fieldInfo) {
            if (strpos($fieldInfo->field_annotation, "@".SurveyAuthExternalModule::$ACTIONTAG)) {
                array_push($fields, new SurveyAuthInfo($fieldInfo, $dataDictionary, $recordIdField));
            }
        }
        return $fields;
    }


    /**
     * Determines, whether the credentials are valid.
     */
    function authenticate($username, $password, $project_id, $instrument, $event_id, $repeat_instance) 
    {
        $result = array (
            "success" => false,
            "username" => $username,
            "email" => null,
            "fullname" => null,
            "error" => null,
            "log_error" => array()
        );
        $record_id = null;
        $ip = $_SERVER["REMOTE_ADDR"];
        if (strlen($_SERVER["HTTP_X_FORWARDED_FOR"])) $ip .= $_SERVER["HTTP_X_FORWARDED_FOR"];

        try {
            do {
                // Check lockout status.
                $lockoutCount = $this->checkLockoutStatus($ip);
                if ($lockoutCount > 2) {
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
                // If a token is set, process action tag parameters and store any requested values.
                $token = $this->settings->token;
                if (strlen($token)) {

                    $result["mode"] = "token";
                    $recordIdField = \REDCap::getRecordIdField();

                    // Get data from data dictionary.
                    $dd = json_decode(\REDCap::getDataDictionary($project_id, 'json', true, null, $instrument, false));
                    $taggedFields= $this->getTaggedFields($dd, $recordIdField);
                    if (!count($taggedFields)) {
                        $result["log_error"][] = "Could not find a field tagged with the @" . self::$ACTIONTAG . " action tag.";
                        $result["mode"] = "simple";
                    }
                    else {
                        $tf = $taggedFields[0];

                        // Add a new record and set data.
                        $apiUrl = APP_PATH_WEBROOT_FULL . "api/";
                        $guid = SurveyAuthInfo::GUID();
                        $result["timestamp"] = date($tf->dateFormat);
                        $payload = array();
                        $payload[$recordIdField] = "new-{$guid}";
                        if (strlen($tf->successField)) $payload[$tf->successField] = $tf->successValue;
                        // Add mapped data items.
                        foreach ($tf->map as $k => $v) {
                            if (strlen($tf->map[$k])) $payload[$v] = $result[$k];
                        }
                        $payloadJson = json_encode(array($payload));
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
                        $response = json_decode($responseJson, true);
                        if (isset($response["error"])) {
                            $result["success"] = false;
                            $result["error"] = $this->settings->errorMsg;
                            $result["log_error"][] = "Failed to create a new record: " . $response["error"];
                            break;
                        }
                        $record_id = $response[0];
                        $link = \REDCap::getSurveyLink($record_id, $instrument, $event_id, $repeat_instance);
                        $result["targetUrl"] = $link;
                    }
                }
                else {
                    // No token - simple mode.
                    $result["mode"] = "simple";
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
                "record" => $record_id,
                "event" => null,
                "project_id" => $GLOBALS["project_id"]
            );
            \REDCap::logEvent($logData["action_description"], $logData["changes_made"], $logData["sql"], $logData["record"], $logData["event"], $logData["project_id"]);
        }
        // Return result.
        return $result;
    }


    private function authenticateTable($username, $password, &$result)
    {
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

    private function authenticateCustom($username, $password, &$result)
    {
        $username = strtolower($username);
        if (isset($this->settings->customCredentials[$username]) && $this->settings->customCredentials[$username] == $password) {
            $result["success"] = true;
            $result["method"] = "Custom";
        }
    }

    private function authenticateLDAP($username, $password, &$result) 
    {
        include APP_PATH_WEBTOOLS . 'ldap/ldap_config.php';
        $config = isset($GLOBALS["ldapdsn"]) ? $GLOBALS["ldapdsn"] : null;
        if ($config) {
            $this->doLDAPauth($username, $password, $config, $result);
            if ($result["success"]) {
                $result["method"] = "LDAP";
            }
        }
        else {
            $result["log_error"][] = "REDCap LDAP not available.";
        }
    }

    private function authenticateOtherLDAP($username, $password, &$result) 
    {
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

    private function doLDAPauth($username, $password, $config, &$result) 
    {
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
                $first = true;
                $entryId = null;
                do {
                    // Get the user dn.
                    if ($first) {
                        $entryId = @ldap_first_entry($ldap, $resultId);
                        $first = false;
                    } 
                    else {
                        $entryId = @ldap_next_entry($ldap, $entryId);
                        if ($entryId === false)
                            break;
                    }
                    $userDn  = @ldap_get_dn($ldap, $entryId);
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
                            // Check group if appropiate
                            if (strlen($config["group"])) {
                                // Check type of memberattr (dn or username).
                                $inGroup = $this->checkGroup($ldap, $config, ($config['memberisdn']) ? $userDn : $username);
                                $result["success"] = $inGroup;
                                break;
                            } 
                            else {
                                $result["success"] = true;
                                break;
                            }
                        }
                    }
                } while (true); 
            }
            @ldap_unbind($ldap);
        }
        catch (\Exception $e) {
            $result["log_error"][] = "LDAP error: " . $e->getMessage();
        }
        finally {
            @ldap_close($ldap);
        }
    }

    private function checkBaseDN($ldap, &$config) 
    {
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
    private function quoteFilterString($raw)
    {
        $search = array('\\', '*', '(', ')', "\x00");
        $replace = array('\\\\', '\*', '\(', '\)', "\\\x00");
        return str_replace($search, $replace, $raw);
    }
    
    private function mergeLDAPConfig($config)
    {
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

    private function checkGroup($ldap, $config, $user)
    {
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
    private function checkLockoutStatus($ip)
    {
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
    private function updateLockoutStatus($ip) 
    {
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
    private function clearLockoutStatus($ip) 
    {
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
    private function toSecureBlob($data)
    {
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
    private function fromSecureBlob($blob) 
    {
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
    private function checkKeys()
    {
        if (!strlen($this->settings->blobSecret)) {
            $this->settings->blobSecret = $this->genKey(32);
            $this->setSystemSetting("surveyauth_blobsecret", $this->settings->blobSecret);
        }
        if (!strlen($this->settings->blobHmac)) {
            $this->settings->blobHmac = $this->genKey(32);
            $this->setSystemSetting("surveyauth_blobhmac", $this->settings->blobHmac);
        }
    }

    private function genKey($keySize) 
    {
        $key = openssl_random_pseudo_bytes($keySize);
        return base64_encode($key);
    }

    //endregion
}

/**
 * A helper class that holds settings info for this external module.
 */
class SurveyAuthSettings 
{
    public $log;
    public $token;
    public $text;
    public $usernameLabel;
    public $passwordLabel;
    public $submitLabel;
    public $failMsg;
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
    public $ldapMappings = array(
        "email" => array(),
        "fullname" => array(),
        "firstname" => array(),
        "lastname" => array()
    );
    public $useWhitelist;
    public $whitelist;
    public $lockoutStatus;

    private $m;

    function __construct($module) 
    {
        $this->isProject = isset($GLOBALS["project_id"]);
        $this->m = $module;
        $this->blobSecret = $module->getSystemSetting("surveyauth_blobsecret");
        $this->blobHmac = $module->getSystemSetting("surveyauth_blobhmac");
        $lockouttime = $module->getSystemSetting("surveyauth_lockouttime");
        $this->lockouttime = is_numeric($lockouttime) ? $lockouttime * 1 : 5;
        $this->lockoutStatus = $this->lockouttime === 0 ? array() : json_decode($module->getSystemSetting("surveyauth_lockouts"), true);
        // Only in the context of a project
        if ($this->isProject) {
            $this->log = $this->getValue("surveyauth_log", "all");
            $this->token = $this->getValue("surveyauth_token", null);
            $this->text = $this->getValue("surveyauth_text", "Login is required to continue.");
            $this->usernameLabel = $this->getValue("surveyauth_usernamelabel", "Username");
            $this->passwordLabel = $this->getValue("surveyauth_passwordlabel", "Password");
            $this->submitLabel = $this->getValue("surveyauth_submitlabel", "Submit");
            $this->failMsg = $this->getValue("surveyauth_failmsg", "Invalid username and/or password or access denied.");
            $this->lockoutMsg = $this->getValue("surveyauth_lockoutmsg", "Too many failed login attempts. Please try again later.");
            $this->successMsg = $this->getValue("surveyauth_successmsg", "Authentication was successful. You will be automatically forwarded to the survey momentarily.");
            $this->errorMsg = $this->getValue("surveyauth_errormsg", "A technical error prevented completion of the authentication process. Please notify the system administrator.");
            $this->continueLabel = $this->getValue("surveyauth_continuelabel", "Continue to Survey");
            $this->useTable = $this->getValue("surveyauth_usetable", false);
            $this->useLDAP = $this->getValue("surveyauth_useldap", false);
            $this->useOtherLDAP = $this->getValue("surveyauth_useotherldap", false);
            $this->useCustom = $this->getValue("surveyauth_usecustom", false);
            $this->otherLDAPConfigs = json_decode($this->getValue("surveyauth_otherldap", "[]"), true);
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



/**
 * A helper class that holds information about the behavior of the SurveyAuth module.
 */
class SurveyAuthInfo 
{
    public $guid;
    public $successField;
    public $successValue;
    public $map = array();
    public $dateFormat = "Y-m-d";

    private $ALLOWEDMAPPINGS = array("success", "username", "email", "fullname", "timestamp");

    function __construct($fieldInfo, $dd, $recordIdField) 
    {
        $valid_field_names = array ();
        foreach ($dd as $f) {
            if ($f->field_name != $recordIdField) {
                array_push($valid_field_names, $f->field_name);
            }
        }
        $this->guid = SurveyAuthInfo::GUID();
        $this->fieldName = $fieldInfo->field_name;
        // Extract and parse parameters.
        $re = '/@' . SurveyAuthExternalModule::$ACTIONTAG . '\((?\'config\'.+=.+)\)/m';
        preg_match_all($re, $fieldInfo->field_annotation, $matches, PREG_SET_ORDER, 0);
        if (count($matches)) {
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
                            if (in_array($key, $valid_field_names)) {
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
    public static function GUID() 
    {
        if (function_exists('com_create_guid') === true) {
            return strtolower(trim(com_create_guid(), '{}'));
        }
        return strtolower(sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535)));
    }
}


