<?php
namespace RUB\SurveyAuthExternalModule;


use ExternalModules\AbstractExternalModule;

/**
 * ExternalModule class for survey authentication.
 */
class SurveyAuthExternalModule extends AbstractExternalModule {
    
    public static $ACTIONTAG = "SURVEY-AUTH";
    public $IDENTITY = "5a859937-929f-4434-9b35-f2905c193030";

    private $settings;

    function __construct()
    {
        // Need to call parent constructor first!
        parent::__construct();
        // Initialize settings.
        $this->settings = new SurveyAuthSettings($this);
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
        // If there is nothing to do simply return.
        if ($tf == null) return;

        // Check if $record is defined. If not, then authentication needs to be performed.
        if ($record == null) {

            // This is needed for older versions of REDCap in order to write crytographic keys and lockouts to system settings.
            if (method_exists($this, "disableUserBasedSettingPermissions")) {
                $this->disableUserBasedSettingPermissions();
            }

            // Need to authenticate - inject JavaScript and HTML.
            $jsUrl = $this->getUrl("surveyauth.js");
            print "<script type=\"text/javascript\" src=\"{$jsUrl}\"></script>";
            $queryUrl = $this->getUrl("authenticate.php", true);
            $blob = $this->toSecureBlob(array(
                "project_id" => $project_id,
                "group_id" => $group_id,
                "instrument" => $instrument,
                "event_id" => $event_id,
                "repeat_instance" => $repeat_instance
            ));
            $isMobile = isset($GLOBALS["isMobileDevice"]) && $GLOBALS["isMobileDevice"];
            $logo = "";
            if (is_numeric($GLOBALS["logo"])) {
                //Set max-width for logo (include for mobile devices)
                $logo_width = $isMobile ? '300' : '600';
                // Get img dimensions (local file storage only)
                $thisImgMaxWidth = $logo_width;
                $styleDim = "max-width:{$thisImgMaxWidth}px;";
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
                $logo .= "<div style=\"padding:10px 0 0;\"><img id=\"survey_logo\" onload=\"try{reloadSpeakIconsForLogo()}catch(e){}\" " .
                    "src=\"".APP_PATH_SURVEY."index.php?pid={$project_id}&doc_id_hash=".\Files::docIdHash($GLOBALS["logo"]) .
                    "&__passthru=".urlencode("DataEntry/image_view.php")."&s={$GLOBALS["hash"]}&id={$GLOBALS["logo"]}\" alt=\"" . 
                    js_escape($GLOBALS["lang"]["survey_1140"])."\" title=\"".js_escape($GLOBALS["lang"]["survey_1140"]) .
                    "\" style=\"max-width:{$logo_width}px;$styleDim\"></div>";
            }
            $mobile = $isMobile ? "_mobile" : "";
            $template = file_get_contents(dirname(__FILE__)."/ui{$mobile}.html");
            $replace = array(
                "{GUID}" => $tf->guid,
                "{LOGO}" => $logo,
                "{PREFIX}" => $this->PREFIX,
                "{QUERYURL}" => $queryUrl,
                "{SURVEYTITLE}" => $GLOBALS["title"],
                "{INSTRUCTIONS}" => $this->settings->text,
                "{USERNAMELABEL}" => $this->settings->usernameLabel,
                "{PASSWORDLABEL}" => $this->settings->passwordLabel,
                "{SUBMITLABEL}" => $this->settings->submitLabel,
                "{FAILMSG}" => $this->settings->failMsg,
                "{BLOB}" => $blob,
                "{DEBUG}" => $this->settings->debug ? " data-debug=\"1\"" : ""
            );
            print str_replace(array_keys($replace), array_values($replace), $template);
            // No further processing (i.e. do not let REDCap render the survey page).
            $this->exitAfterHook();
        }
        else {
            // Having a record means that authentication has succeded.
            // Thus, there is nothing to do.
        }
    }

    /**
     * A helper function that extracts parts of the data dictionary with the module's action tag.
     */
    private function getTaggedFields($dataDictionary) 
    {
        $fields = array();
        foreach ($dataDictionary as $fieldInfo) {
            if (strpos($fieldInfo->field_annotation, "@".SurveyAuthExternalModule::$ACTIONTAG)) {
                array_push($fields, new SurveyAuthInfo($fieldInfo, $dataDictionary));
            }
        }
        return $fields;
    }


    /**
     * Determines, whether the credentials are valid.
     */
    function authenticate($username, $password, $blob) 
    {
        $result = array (
            "success" => false,
            "username" => $username,
            "email" => null,
            "fullname" => null,
            "error" => null,
        );
        $record_id = null;
        $ip = $_SERVER["REMOTE_ADDR"] . $_SERVER["HTTP_X_FORWARDED_FOR"];

        do {
            // Retrieve transferred data.
            $data = $this->fromSecureBlob($blob);
            if ($data == null) {
                $result["error"] = "Failed to decrypt blob.";
                break;
            }
            // Verify project id.
            $project_id = $data["project_id"];
            if ($project_id != $GLOBALS["project_id"]) {
                $result["error"] = "Project ID mismatch.";
                break;
            }
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
                if (!$this->settings->debug || !strlen($result["error"])) {
                    $result["error"] = "Bad username / password.";
                }
                // Update lockout status.
                $this->updateLockoutStatus($ip);
                break;
            }

            // Login was successful.
            if ($lockoutCount > 0) {
                $this->clearLockoutStatus($ip);
            }

            // Get data from data dictionary.
            $dd = json_decode(\REDCap::getDataDictionary($project_id, 'json', true, null, $data["instrument"], false));
            $taggedFields= $this->getTaggedFields($dd);
            if (count($taggedFields) != 1) {
                $result["error"] = "Could not find a tagged field.";
                break;
            }
            $tf = $taggedFields[0];
            // Verify token exists.
            $token = $this->settings->token;
            if (!strlen($token)) {
                $result["error"] = "API token missing.";
                break;
            }

            // Add a new record and set data.
            $apiUrl = APP_PATH_WEBROOT_FULL . "api/";
            $recordIdField = \REDCap::getRecordIdField();
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
                $result["error"] = $response["error"];
                break;
            }
            $record_id = $response[0];
            $link = \REDCap::getSurveyLink($record_id, $data["instrument"], $data["event_id"], $data["repeat_instance"]);
            // We came to here, so all was good.
            $result["success"] = true;
        } while (false);

        // Write a log entry.
        if ($this->settings->log == "all" || ($this->settings->log == "fail" && !$result["success"]) || ($this->settings->log == "success" && $result["success"])) {
            $logData = array(
                "action_description" => "SurveyAuth: Performed authentication operation for '{$username}'",
                "changes_made" => $result["success"] ? "Successful" : "Failed/Denied",
                "sql" => $result["error"],
                "record" => $record_id,
                "event" => null,
                "project_id" => $GLOBALS["project_id"]
            );
            \REDCap::logEvent($logData["action_description"], $logData["changes_made"], $logData["sql"], $logData["record"], $logData["event"], $logData["project_id"]);
        }

        // Prepare response.
        $json = array(
            "success" => $result["success"]
        );
        if ($result["success"]) {
            $json["target"] = $link;
        }
        else {
            $json["error"] = $result["error"];
        }
        if (isset($result["lockout"])) {
            $json["lockout"] = $result["lockout"];
        }
        if ($this->settings->debug) {
            $json["auth_result"] = $result;
        }

        // Return response as JSON.
        return json_encode($json);
    }


    private function authenticateTable($username, $password, &$result)
    {
        try {
            if (\Authentication::verifyTableUsernamePassword($username, $password)) {
                $result["success"] = true;
                try {
                    $ui = \User::getUserInfo($username);
                    $result["email"] = $ui["user_email"];
                    $result["fullname"] = trim("{$ui["user_firstname"]} {$ui["user_lastname"]}");
                    throw new \Exception("Test");
                }
                catch (\Exception $e) {
                    $result["error"] = $e->getMessage();
                }
            }
        }
        catch (\Exception $e) {
            $result["error"] = $e->getMessage();
        }
    }

    private function authenticateCustom($username, $password, &$result)
    {
        $username = strtolower($username);
        if (isset($this->settings->customCredentials[$username]) && $this->settings->customCredentials[$username] == $password) {
            $result["success"] = true;
        }
    }

    private function authenticateLDAP($username, $password, &$result) 
    {
        include APP_PATH_WEBTOOLS . 'ldap/ldap_config.php';
        $config = isset($GLOBALS["ldapdsn"]) ? $GLOBALS["ldapdsn"] : null;
        if ($config) {
            $this->doLDAPauth($username, $password, $config, $result);
        }
        else {
            $result["error"] = "REDCap LDAP not available.";
        }
    }

    private function authenticateOtherLDAP($username, $password, &$result) 
    {
        $errors = array();
        if (count($this->settings->otherLDAPConfigs) < 1) {
            $result["error"] = "No Other LDAP configuraations available.";
        }
        foreach ($this->settings->otherLDAPConfigs as $config) {
            $this->doLDAPauth($username, $password, $config, $result);
            if (strlen($result["error"])) array_push($errors, $result["error"]);
            $result["error"] = null;
            if ($result["success"]) break;
        }
        $result["error"] = join("\n", $errors);
    }

    //region LDAP

    private function doLDAPauth($username, $password, $config, &$result) 
    {
        // As we rely on the ldap module, check that it has been loaded.
        if (!extension_loaded("ldap")) {
            $result["error"] = "LDAP extension not loaded.";
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
                            $lastname = (isset($attributes["sn"]) && $attributes["sn"]["count"] >= 1) ? $attributes["sn"][0] : "";
                            $firstname = (isset($attributes["givenName"]) && $attributes["givenName"]["count"] >= 1) ? $attributes["givenName"][0] : "";
                            $fullname = trim("{$firstname} {$lastname}");
                            $email = (isset($attributes["email"]) && $attributes["email"]["count"] >= 1) ? $attributes["email"][0] : "";
                            if (!strlen($email)) $email = (isset($attributes["mail"]) && $attributes["mail"]["count"] >= 1) ? $attributes["mail"][0] : "";
                            if (strlen($email)) $result["email"] = strtolower($email);
                            if (strlen($fullname)) $result["fullname"] = $fullname;
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
                } while (true); // ($config['try_all'] == true); 
            }
            @ldap_unbind($ldap);
        }
        catch (\Exception $e) {
            $result["error"] = "LDAP error: " . $e->getMessage();
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
    public $debug;
    public $log;
    public $token;
    public $text;
    public $usernameLabel;
    public $passwordLabel;
    public $submitLabel;
    public $failMsg;
    public $lockoutMsg;
    public $lockouttime;
    public $blobSecret;
    public $blobHmac;
    public $isProject;
    public $useTable;
    public $useLDAP;
    public $useOtherLDAP;
    public $useCustom;
    public $customCredentials;
    public $otherLDAPConfigs;
    public $useWhitelist;
    public $whitelist;
    public $lockoutStatus;

    private $m;

    function __construct($module) 
    {
        $this->isProject = isset($GLOBALS["project_id"]);
        $this->m = $module;
        $this->debug = $module->getSystemSetting("surveyauth_globaldebug") || ($this->isProject && $module->getProjectSetting("surveyauth_debug"));
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
            $this->useTable = $this->getValue("surveyauth_usetable", false);
            $this->useLDAP = $this->getValue("surveyauth_useldap", false);
            $this->useOtherLDAP = $this->getValue("surveyauth_useotherldap", false);
            $this->useCustom = $this->getValue("surveyauth_usecustom", false);
            $this->otherLDAPConfigs = json_decode($this->getValue("surveyauth_otherldap", "[]"), true);
            if (!is_array($this->otherLDAPConfigs)) $this->otherLDAPConfigs = array();
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

    function __construct($fieldInfo, $dd) 
    {
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


