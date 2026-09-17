<?php 

namespace DE\RUB\SurveyAuthExternalModule;

use ExternalModules\AbstractExternalModule;

require_once "classes/SurveyAuthSettings.php";
require_once "classes/SurveyAuthInfo.php";
require_once "classes/SurveySessionAuth.php";
require_once "classes/PublicResourceAuth.php";
require_once "classes/SurveyAuthMlm.php";

/**
 * ExternalModule class for survey authentication.
 */
class SurveyAuthExternalModule extends AbstractExternalModule {
    use SurveySessionAuth;
    use PublicResourceAuth;
    use SurveyAuthMlm;
    
    public static $ACTIONTAG = "SURVEY-AUTH";
    private const LOCKOUT_BUCKET_COUNT = 16;
    private const LOCKOUT_BUCKET_MAX_ENTRIES = 1024;
    private const LOCKOUT_BUCKET_MAX_BYTES = 262144;
    private const LOCKOUT_LEGACY_MAX_BYTES = 16777215;

    /** @var SurveyAuthSettings Module Settings */
    private $settings;

    #region Hooks

    function redcap_module_system_enable($version) {
        $this->migrateLockoutStorage();
        // Include retained settings for disabled projects, not just enabled projects.
        $keys = array_map(fn($key) => $this->framework->prefixSettingKey($key),
            ['surveyauth_token', 'surveyauth_successmsg', 'surveyauth_continuelabel']);
        $projects = $this->framework->query('SELECT DISTINCT s.project_id
            FROM redcap_external_module_settings s
            JOIN redcap_external_modules m ON m.external_module_id=s.external_module_id
            WHERE m.directory_prefix=? AND s.project_id IS NOT NULL AND s.`key` IN (?, ?, ?)',
            array_merge([$this->PREFIX], $keys));
        while ($row = $projects->fetch_assoc()) $this->migrateProjectSettings($row['project_id']);
    }

    function redcap_module_project_enable($version, $project_id) {
        // Also handle settings restored or imported after the system migration.
        $this->migrateProjectSettings($project_id);
    }

    function redcap_module_link_check_display($project_id, $link) {
        if ($link === null) return null;
        // Hide the dedicated editor unless it can affect a protected survey.
        if (($link['prefixedKey'] ?? null) === $this->PREFIX.'-mlm-login-translations' &&
            !$this->surveyMlmTranslationEditorAvailable((int)$project_id)) return null;
        return $link;
    }

    private function migrateProjectSettings($projectId): void {
        // Preserve the pre-1.3 token migration, using stored state rather than versions.
        // Never overwrite an explicitly configured Allow writing value.
        $token = $this->framework->getProjectSetting('surveyauth_token', $projectId);
        if (!empty($token) && $this->framework->getProjectSetting('surveyauth_canwrite', $projectId) === null) {
            $this->framework->setProjectSetting('surveyauth_canwrite', true, $projectId);
        }
        foreach (['surveyauth_token', 'surveyauth_successmsg', 'surveyauth_continuelabel'] as $key) {
            $this->framework->removeProjectSetting($key, $projectId);
        }
    }

    /** Move the released single-row lockout store into bounded hash buckets. */
    private function migrateLockoutStorage(): void {
        $legacyRaw = $this->framework->getSystemSetting('surveyauth_lockouts');
        if ($legacyRaw === null) return;
        $lockouttime = $this->framework->getSystemSetting('surveyauth_lockouttime');
        $lockouttime = is_numeric($lockouttime) ? $lockouttime * 1 : 5;
        $legacy = $this->normalizeLockoutStatus(
            $this->decodeLockoutStatus($legacyRaw, self::LOCKOUT_LEGACY_MAX_BYTES),
            $lockouttime
        );
        $migrated = [];
        foreach ($legacy as $ip => $entry) {
            $migrated[$this->lockoutBucketForIp($ip)][$ip] = $entry;
        }
        for ($i = 0; $i < self::LOCKOUT_BUCKET_COUNT; $i++) {
            $bucket = dechex($i);
            $key = $this->lockoutBucketSettingKey($bucket);
            $existingRaw = $this->framework->getSystemSetting($key);
            $existing = $this->normalizeLockoutStatus(
                $this->decodeLockoutStatus($existingRaw, self::LOCKOUT_BUCKET_MAX_BYTES),
                $lockouttime,
                $bucket
            );
            foreach ($migrated[$bucket] ?? [] as $ip => $entry) {
                $current = $existing[$ip] ?? null;
                if (!$current || $entry['ts'] > $current['ts'] ||
                    ($entry['ts'] === $current['ts'] && $entry['n'] > $current['n'])) {
                    $existing[$ip] = $entry;
                }
            }
            uasort($existing, static fn($a, $b) => $b['ts'] <=> $a['ts'] ?: $b['n'] <=> $a['n']);
            $existing = array_slice($existing, 0, self::LOCKOUT_BUCKET_MAX_ENTRIES, true);
            $encoded = json_encode($existing, JSON_THROW_ON_ERROR);
            while (strlen($encoded) > self::LOCKOUT_BUCKET_MAX_BYTES && $existing) {
                array_pop($existing);
                $encoded = json_encode($existing, JSON_THROW_ON_ERROR);
            }
            if ($existing) {
                if ($existingRaw !== $encoded) $this->framework->setSystemSetting($key, $encoded);
            } elseif ($existingRaw !== null) {
                $this->framework->removeSystemSetting($key);
            }
        }
        // Remove only after every bucket write has succeeded. A failed migration
        // leaves the source intact so the system-enable hook can retry safely.
        $this->framework->removeSystemSetting('surveyauth_lockouts');
    }

    function redcap_every_page_before_render($project_id) {
        $page = defined("PAGE") ? PAGE : "";
        // The framework validates this module's registered AJAX action before dispatch.
        if ($page === 'surveys/index.php' && ($_GET['__passthru'] ?? null) === 'ExternalModules' &&
            ($_GET['prefix'] ?? null) === $this->PREFIX && ($_GET['ajax'] ?? null) === '1') {
            $this->useSessionBoundLoginCsrf();
            return;
        }
        // This hook handles several things:
        //  - Saving dashboard and report protection settings
        //  - Denying access to public dashboards and reports when set to be blocked from the external survey endpoint
        //  - Display and evaluate the login dialog on protected dashboards and reports

        if ($page === 'ProjectDashController:copy') {
            $this->copyDashboardWithProtection($project_id);
            return;
        }

        // Save dashboard protection settings
        if ($page == "ProjectDashController:save") {
            $this->save_dashboard_settings(isset($_GET["dash_id"]) ? $_GET["dash_id"] : "", $_POST);
            return;
        }

        // Core file endpoints also accept survey hashes without the survey passthrough.
        if (isset($_GET['s']) && in_array($page, ['DataEntry/file_upload.php', 'DataEntry/file_download.php',
            'DataEntry/file_delete.php', 'DataEntry/image_view.php', 'Design/file_attachment_upload.php'], true)) {
            $this->protectSurveyBeforeProcessing($project_id);
            return;
        }
        // Nothing to do if not a public dashboard or report page
        $publicFile = in_array($page, ['DataEntry/file_download.php', 'DataEntry/image_view.php'], true)
            && (isset($_GET['__dashboard']) || isset($_GET['__report']));
        if ($page != "surveys/index.php" && !$publicFile) return;
        // Ambiguous selectors must never select a different protection policy
        // from the resource REDCap will render.
        if (isset($_GET["__dashboard"], $_GET["__report"])) {
            http_response_code(400);
            print "Conflicting resource selectors.";
            $this->exitAfterHook();
            return;
        }
        $page_type = "";
        if (isset($_GET["__dashboard"])) $page_type = "dashboard";
        if (isset($_GET["__report"])) $page_type = "report";
        if (isset($_GET['s']) && $page_type !== '') {
            $this->surveyStop('Conflicting resource selectors.', 400);
            return;
        }
        if (!in_array($page_type, ["dashboard", "report"])) {
            $this->protectSurveyBeforeProcessing($project_id);
            return;
        }

        if ($page_type == "dashboard") {
            $this->protect_dashboard($project_id);
            return;
        }
        if ($page_type == "report") {
            $this->protect_report($project_id);
            return;
        }
    }

    function redcap_every_page_top($project_id) {
        $page = defined("PAGE") ? PAGE : "";
        if ($page == "DataExport/index.php" &&  isset($_GET["addedit"]) && $_GET["addedit"] == "1") {
            $this->add_report_settings($project_id);
        }
        else if ($page == "ProjectDashController:index" && isset($_GET["addedit"]) && $_GET["addedit"] == "1") {
            $this->add_dashboard_settings($project_id);
        }
    }

    function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id) {
        if ($action === 'survey-login') return $this->surveyLoginAjax($payload, $project_id);
        // Report settings are handled by AJAX requests
        if ($action == "save-report-settings") return $this->save_report_settings($project_id, $payload);
    }

    function redcap_survey_page_top($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance = 1) {
        if ($this->restoreAuthenticationAfterStartOver($project_id, $record, $instrument, $event_id,
            $survey_hash, $response_id, $repeat_instance)) return;
        if (!empty($this->authorizedSurveyRequest['new'])) {
            print "<script>$(function(){ $('<input>', {type:'hidden',name:'__sa_new',value:'1'}).appendTo('#form'); });</script>";
        }
        // A public start has a session-bound flow ID to isolate concurrent starts.
        // It carries no authority without the grant in this browser's session.
        if ($this->authorizedSurveyRequest && $this->authorizedSurveyRequest['scope']['record'] === null) {
            $flow = json_encode($this->authorizedSurveyRequest['flow'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
            print "<script>$(function(){ $('<input>', {type:'hidden',name:'__sa_flow',value:$flow}).appendTo('#form'); });</script>";
        }
    }

    #endregion

    #region Public Reports

    private function protect_report($project_id) {
        $this->protectPublicResource($project_id, 'report');
    }

    private function add_report_settings(int $project_id): void {
        $reportIdInput = $_GET['report_id'] ?? null;
        if (!is_scalar($reportIdInput) || !ctype_digit((string)$reportIdInput) || (int)$reportIdInput < 1) return;
        $report_id = (int)$reportIdInput;
        if (!\DataExport::validateReportId($project_id, $report_id)) return;
        if (!$this->can_edit_report($project_id, $report_id)) return;
        // Get protection status
        $this->settings = new SurveyAuthSettings($this, $project_id, 0, $report_id);
        $protect = $this->settings->report_protected ? "checked='checked'" : "";
        $deny_external = $this->settings->report_denyexternal ? "checked='checked'" : "";
        $endpoint_options = (!empty($GLOBALS["redcap_survey_base_url"]) && $GLOBALS["redcap_base_url"] !== $GLOBALS["redcap_survey_base_url"]) ? "true" : "false";
        $this->initializeJavascriptModuleObject();
        $jsmo = $this->framework->getJavascriptModuleObjectName();
        $this->renderPublicResourceSettingsStyle();
        // Inject Javascript
        ?>
        <script>
            $(function() {
                const $row = $('<div class="survey-auth-settings-row"></div>').appendTo($('#public_link_div').parent());
                const $container = $('<div id="survey_auth_container"></div>').appendTo($row);
                $('<div></div>')
                .addClass("custom-control custom-switch mt-2")
                .append("<input class='custom-control-input' name='survey_auth_protected' id='survey_auth_protected' <?=$protect?> type='checkbox'>")
                .append("<label class='custom-control-label ms-1 mb-0' for='survey_auth_protected'>Report, when public, is protected by Survey Auth</label>")
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
                    .append("<input class='form-check-input ms-2' name='surveyauth_report_endpoint' id='surveyauth_report_endpoint_both' type='radio' value='both' <?=$this->settings->report_endpoint == "both" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='surveyauth_report_endpoint_both'>Both endpoints</label>")
                    .append("<input class='form-check-input ms-4' name='surveyauth_report_endpoint' id='surveyauth_report_endpoint_external' type='radio' value='external' <?=$this->settings->report_endpoint == "external" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='surveyauth_report_endpoint_external'>(External) Survey endpoint only</label>")
                    .append("<input class='form-check-input ms-4' name='surveyauth_report_endpoint' id='surveyauth_report_endpoint_internal' type='radio' value='internal' <?=$this->settings->report_endpoint == "internal" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='surveyauth_report_endpoint_internal'>(Internal) REDCap endpoint only</label>")
                    .appendTo($container);
                    $('<div></div>')
                    .addClass("custom-control custom-switch mt-1")
                    .append("<input class='custom-control-input' name='surveyauth_report_denyexternal' id='surveyauth_report_denyexternal' <?=$deny_external?> type='checkbox'>")
                    .append("<label class='custom-control-label ms-1' for='surveyauth_report_denyexternal'>Deny access via (external) survey endpoint</label>")
                    .appendTo($container);
                    <?php $this->renderEndpointCopyButtonsJavascript('report'); ?>
                }
                $container.on('change', function(e) {
                    <?=$jsmo?>.ajax('save-report-settings', {
                        report_id: <?=$report_id?>,
                        report_endpoint: $('input[name="surveyauth_report_endpoint"]:checked').val(),
                        report_denyexternal: $('input[name="surveyauth_report_denyexternal"]').prop("checked"),
                        report_protected: $('input[name="survey_auth_protected"]').prop("checked")
                    }).then(function(data) {
                        if (data == 1) {
                            $(e.target).addClass('surveyauth-setting-saved');
                            setTimeout(() => {
                                $(e.target).removeClass('surveyauth-setting-saved');
                            }, 150);
                        }
                    }).catch(function(err) {
                        console.error(err);
                    });
                });
            });
        </script>
        <style>
            input[type=checkbox].surveyauth-setting-saved {
                outline: 5px green solid;
                outline-offset: -2px;
                opacity: .7;
            }
            input[type=radio].surveyauth-setting-saved {
                outline: 5px green solid;
                opacity: .7;
            }
        </style>
        <?php
    }

    /**
     * Save protection settings for a report
     * @param int $project_id The project ID
     * @param array<string, mixed> $payload AJAX payload
     */
    private function save_report_settings(int $project_id, array $payload): int {
        $reportIdInput = $payload['report_id'] ?? null;
        if (!is_int($reportIdInput) && (!is_string($reportIdInput) || !ctype_digit($reportIdInput))) return 0;
        $report_id = (int)$reportIdInput;
        if ($report_id < 1 || !$this->can_edit_report($project_id, $report_id)) return 0;
        // Store settings
        $this->setProjectSetting("surveyauth_report_protected_$report_id", ($payload['report_protected'] ?? false) == true);
        $this->setProjectSetting("surveyauth_report_denyexternal_$report_id", ($payload['report_denyexternal'] ?? false) == true);
        $endpoint = $payload['report_endpoint'] ?? null;
        $endpoint_setting = is_string($endpoint) && in_array($endpoint, ['both', 'internal', 'external'], true) ? $endpoint : 'both';
        $this->setProjectSetting("surveyauth_report_endpoint_$report_id", $endpoint_setting);
        return 1;
    }

    private function can_edit_report(int $project_id, int $report_id): bool {
        // Check user rights
        if (!defined("USERID")) return false;
        $rights = \UserRights::getPrivileges($project_id, USERID)[$project_id][USERID];
        // Access to edit reports?
        if (!$rights["reports"]) return false;
        // Access to edit this report?
        $reports_edit_access = \DataExport::getReportsEditAccess(USERID, $rights['role_id'], $rights['group_id'], $report_id);
        if (empty($reports_edit_access)) return false;
        return true;
    }

    #endregion

    #region Public Dashboards

    private function protect_dashboard($project_id) {
        $this->protectPublicResource($project_id, 'dashboard');
    }

    private function copyDashboardWithProtection($projectId): void {
        // This is a staff controller route: core has already checked its CSRF token.
        if (!defined('USERID') || empty($GLOBALS['user_rights']['design']) ||
            ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            http_response_code(403);
            print '0';
            $this->exitAfterHook();
            return;
        }
        $sourceId = $_POST['dash_id'] ?? null;
        if (!is_scalar($sourceId) || !ctype_digit((string)$sourceId) || (int)$sourceId < 1) {
            http_response_code(400);
            print '0';
            $this->exitAfterHook();
            return;
        }
        try {
            $dashboards = new \ProjectDashboards();
            $source = $dashboards->getDashboards($projectId, $sourceId);
            if (empty($source)) throw new \RuntimeException('Dashboard not found in project.');
            $settings = [];
            foreach (['protected', 'endpoint', 'denyexternal'] as $key) {
                $settings[$key] = $this->framework->getProjectSetting('surveyauth_dash_'.$key.'_'.$sourceId, $projectId);
            }
            // Core copyDash() commits its own transaction. Override only its source
            // snapshot so it cannot expose a public copy before our settings exist.
            $copier = new class extends \ProjectDashboards {
                public function getDashboards($project_id, $dash_id=null) {
                    $dash = parent::getDashboards($project_id, $dash_id);
                    if (isset($dash['is_public'])) $dash['is_public'] = '0';
                    return $dash;
                }
            };
            $newId = $copier->copyDash($sourceId);
            if (!$newId) throw new \RuntimeException('Dashboard copy failed.');
            foreach ($settings as $key => $value) {
                $this->framework->setProjectSetting('surveyauth_dash_'.$key.'_'.$newId, $value, $projectId);
            }
            // Match core's public-dashboard approval rules for a copied resource.
            if ($source['is_public'] == '1' && (\UserRights::isSuperUserNotImpersonator() || $GLOBALS['project_dashboard_allow_public'] == '1')) {
                $this->framework->query('UPDATE redcap_project_dashboards SET is_public=1 WHERE project_id=? AND dash_id=?', [$projectId, $newId]);
            }
            print json_encode_rc(['new_dash_id'=>$newId, 'html'=>$dashboards->renderDashboardList()]);
        } catch (\Throwable $e) {
            // Any copy already created stays private if copying protection failed.
            http_response_code(503);
            print '0';
        }
        $this->exitAfterHook();
    }

    private function add_dashboard_settings($project_id) {
        $dash_id = isset($_GET["dash_id"]) ? $_GET["dash_id"] : "";
        if ($dash_id == "") return;
        // Is this a public dashboard?
        $dashboards = new \ProjectDashboards();
        $dash = $dashboards->getDashboards($project_id, $dash_id);
        if ($dash["is_public"] != "1") return;
        // Get protection status
        $this->settings = new SurveyAuthSettings($this, $project_id, $dash_id, 0);
        $protect = $this->settings->dash_protected ? "checked='checked'" : "";
        $deny_external = $this->settings->dash_denyexternal ? "checked='checked'" : "";
        $endpoint_options = (!empty($GLOBALS["redcap_survey_base_url"]) && $GLOBALS["redcap_base_url"] !== $GLOBALS["redcap_survey_base_url"]) ? "true" : "false";
        // Inject Javascript
        // This will render the input elements that allow setting the protection status for public dashboards only
        $this->renderPublicResourceSettingsStyle();
        ?>
        <script>
            $(function() {
                const $row = $('<div class="survey-auth-settings-row"></div>').appendTo($('#public_link_div').parent());
                const $container = $('<div id="survey_auth_container"></div>').appendTo($row);
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
                    .append("<input class='form-check-input ms-2' name='surveyauth_dash_endpoint' id='surveyauth_dash_endpoint_both' type='radio' value='both' <?=$this->settings->dash_endpoint == "both" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='surveyauth_dash_endpoint_both'>Both endpoints</label>")
                    .append("<input class='form-check-input ms-4' name='surveyauth_dash_endpoint' id='surveyauth_dash_endpoint_external' type='radio' value='external' <?=$this->settings->dash_endpoint == "external" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='surveyauth_dash_endpoint_external'>(External) Survey endpoint only</label>")
                    .append("<input class='form-check-input ms-4' name='surveyauth_dash_endpoint' id='surveyauth_dash_endpoint_internal' type='radio' value='internal' <?=$this->settings->dash_endpoint == "internal" ? "checked" : ""?>>")
                    .append("<label class='form-check-label ms-2 mb-0' for='surveyauth_dash_endpoint_internal'>(Internal) REDCap endpoint only</label>")
                    .appendTo($container);
                    $('<div></div>')
                    .addClass("custom-control custom-switch mt-1")
                    .append("<input class='custom-control-input' name='surveyauth_dash_denyexternal' id='surveyauth_dash_denyexternal' <?=$deny_external?> type='checkbox'>")
                    .append("<label class='custom-control-label ms-1' for='surveyauth_dash_denyexternal'>Deny access via (external) survey endpoint</label>")
                    .appendTo($container);
                    <?php $this->renderEndpointCopyButtonsJavascript('dash'); ?>
                }
            });
        </script>
        <?php
    }

    /**
     * Save protection settings for a dashboard
     * @param string $dash_id The dashboard ID
     * @param array $post Copy of $_POST
     * @return void 
     */
    private function save_dashboard_settings($dash_id, $post) {
        if ($dash_id == "") return;
        if (isset($post["is_public"]) && $post["is_public"] == "on") {
            // Store settings
            $this->setProjectSetting("surveyauth_dash_protected_$dash_id", (isset($post["survey_auth_protected"]) && $post["survey_auth_protected"] == "on") ? "1" : "0");
            $this->setProjectSetting("surveyauth_dash_denyexternal_$dash_id", (isset($post["surveyauth_dash_denyexternal"]) && $post["surveyauth_dash_denyexternal"] == "on") ? "1" : "0");
            $endpoint_setting = (isset($post["surveyauth_dash_endpoint"]) && in_array($post["surveyauth_dash_endpoint"], ["both", "internal", "external"])) ? $post["surveyauth_dash_endpoint"] : "both";
            $this->setProjectSetting("surveyauth_dash_endpoint_$dash_id", $endpoint_setting);
        }
        else {
            // Clear all settings
            $this->setProjectSetting("surveyauth_dash_protected_$dash_id", null);
            $this->setProjectSetting("surveyauth_dash_endpoint_$dash_id", null);
            $this->setProjectSetting("surveyauth_dash_denyexternal_$dash_id", null);
        }
    }

    #endregion

    #region Surveys

    #endregion

    #region Helpers

    private function renderEndpointCopyButtonsJavascript(string $type): void {
        $options = json_encode([
            'type' => $type,
            'parameter' => $type === 'report' ? '__report' : '__dashboard',
            'bases' => [
                'external' => rtrim($GLOBALS['redcap_survey_base_url'], '/') . '/surveys/',
                'internal' => rtrim($GLOBALS['redcap_base_url'], '/') . '/surveys/',
            ],
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        ?>
        {
            const options = <?= $options ?>;
            // Use the canonical public link, never a shortened URL or the staff editor URL.
            const publicLink = $('#' + options.type + 'url').val();
            const hash = publicLink ? new URL(publicLink, window.location.href).searchParams.get(options.parameter) : null;
            if (hash) {
                Object.entries(options.bases).forEach(([endpoint, base]) => {
                    const url = new URL(base);
                    url.searchParams.set(options.parameter, hash);
                    const title = 'Copy ' + endpoint + ' ' + (options.type === 'report' ? 'report' : 'dashboard') + ' link';
                    const $button = $('<button>', {
                        type: 'button',
                        class: 'btn btn-light btn-xs ms-1',
                        title: title,
                        'aria-label': title,
                        'data-clipboard-text': url.href
                    })
                    .css({padding: '2px 3px', 'font-size': '9px'})
                    .append($('<i>', {class: 'fas fa-copy', 'aria-hidden': 'true'}))
                    .insertAfter($container.find('label[for="surveyauth_' + options.type + '_endpoint_' + endpoint + '"]'));
                    // Separate from core's btn-clipboard handler, which inserts "Copied!" text.
                    const clipboard = new Clipboard($button[0]);
                    let feedback;
                    clipboard.on('success', function() {
                        if (feedback) feedback.cancel();
                        const background = getComputedStyle($button[0]).backgroundColor;
                        feedback = $button[0].animate([
                            {backgroundColor: background},
                            {backgroundColor: '#90ee90', offset: 0.2},
                            {backgroundColor: background}
                        ], {duration: 800, easing: 'ease-out'});
                    });
                });
            }
        }
        <?php
    }

    private function renderPublicResourceSettingsStyle(): void {
        ?>
        <style>
            .survey-auth-settings-row {
                display: block;
                float: none;
                clear: both;
                width: 100%;
            }
            #survey_auth_container {
                display: inline-block;
                float: none;
                box-sizing: border-box;
                margin: 10px 0;
                border: 1px gray dotted;
                padding: 5px 10px;
                width: 100%;
                background-color: aliceblue;
            }
        </style>
        <?php
    }

    /**
     * A helper function that returns an array indicating whether there are endpoint options and the currently used endpoint.
     * @return Array(bool, string)
     */
    private function get_endpoint() {
        $endpoint_options = (!empty($GLOBALS["redcap_survey_base_url"]) && $GLOBALS["redcap_base_url"] !== $GLOBALS["redcap_survey_base_url"]);
        $scheme = $_SERVER['REQUEST_SCHEME'] ?? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
        if (!is_string($scheme) || !in_array(strtolower($scheme), ['http', 'https'], true)) {
            throw new \RuntimeException('Trusted request scheme is unavailable.');
        }
        $scheme = strtolower($scheme);
        $serverName = $_SERVER['SERVER_NAME'] ?? null;
        $serverPort = $_SERVER['SERVER_PORT'] ?? ($scheme === 'https' ? 443 : 80);
        if (!is_string($serverName) || $serverName === '' || !is_scalar($serverPort) ||
            !ctype_digit((string)$serverPort) || (int)$serverPort < 1 || (int)$serverPort > 65535 ||
            preg_match('~[\x00-\x20\x7f\\\\/@?#]~', $serverName)) {
            throw new \RuntimeException('Trusted request endpoint is unavailable.');
        }
        if (filter_var($serverName, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $serverName = '['.$serverName.']';
        } elseif (str_contains($serverName, ':')) {
            throw new \RuntimeException('Invalid trusted server name.');
        }
        $defaultPort = $scheme === 'https' ? 443 : 80;
        $authority = $serverName.((int)$serverPort === $defaultPort ? '' : ':'.(int)$serverPort);
        // SERVER_NAME/SERVER_PORT are selected by the trusted web-server route.
        // HTTP_HOST is client-controlled and must not choose an access policy.
        $request = $this->endpointUrlParts($scheme.'://'.$authority.($_SERVER['REQUEST_URI'] ?? '/'));
        $bases = ['internal'=>$GLOBALS['redcap_base_url']];
        if ($endpoint_options) $bases['external'] = $GLOBALS['redcap_survey_base_url'];
        $endpoint = null;
        $matchedLength = -1;
        foreach ($bases as $name => $url) {
            $base = $this->endpointUrlParts($url);
            if (array_slice($request, 0, 3) !== array_slice($base, 0, 3)) continue;
            // A directory boundary prevents /redcap-other from matching /redcap.
            // Prefer the more specific base when one configured path contains the other.
            if (($request[3] === $base[3] || str_starts_with($request[3], $base[3].'/')) && strlen($base[3]) > $matchedLength) {
                $endpoint = $name;
                $matchedLength = strlen($base[3]);
            }
        }
        if ($endpoint === null) throw new \RuntimeException('Request does not match a configured REDCap endpoint.');
        return [$endpoint_options, $endpoint];
    }

    private function endpointUrlParts(string $url): array {
        $parts = parse_url($url);
        if (!$parts || empty($parts['host']) || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)
            || isset($parts['user']) || isset($parts['pass'])) {
            throw new \RuntimeException('Invalid REDCap endpoint URL.');
        }
        $scheme = strtolower($parts['scheme']);
        // Compare the routed path, without allowing encoded separators or dot segments
        // to select a less specific endpoint. Query parameters do not identify endpoints.
        $path = rawurldecode($parts['path'] ?? '/');
        if (str_contains($path, '\\') || str_contains($path, "\0")) throw new \RuntimeException('Invalid endpoint path.');
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') continue;
            if ($segment === '..') array_pop($segments);
            else $segments[] = $segment;
        }
        return [$scheme, strtolower($parts['host']), $parts['port'] ?? ($scheme === 'https' ? 443 : 80),
            count($segments) ? '/'.implode('/', $segments) : ''];
    }

    /**
     * A helper function that extracts parts of the data dictionary with the module's action tag.
     */
    private function getTaggedFields($dataDictionary, $project_id, $record, $event_id, $instrument, $repeat_instance) {
        $fields = array();
        foreach ($dataDictionary as $fieldInfo) {
            $evaluatedFieldAnnotation = \Form::replaceIfActionTag($fieldInfo->field_annotation, $project_id, $record ?? "1", $event_id, $instrument, $repeat_instance);
            // Match the complete tag, including at offset zero and with parameters.
            // Form::hasActionTag() splits on spaces and misses parameterized tags.
            if (preg_match('/(?<![A-Za-z0-9_@-])@'.preg_quote(self::$ACTIONTAG, '/').'(?![A-Za-z0-9_-])/', $evaluatedFieldAnnotation)) {
                array_push($fields, new SurveyAuthInfo($fieldInfo->field_name, $evaluatedFieldAnnotation, $dataDictionary));
            }
        }
        return $fields;
    }

    /** Load a survey instrument's metadata without treating failures as an unprotected survey. */
    private function getSurveyDataDictionary($projectId, string $instrument): array {
        $raw = \REDCap::getDataDictionary($projectId, 'json', true, null, $instrument, false);
        if (!is_string($raw) || $raw === '') throw new \RuntimeException('Survey metadata is unavailable.');
        $dictionary = json_decode($raw, false, 512, JSON_THROW_ON_ERROR);
        if (!is_array($dictionary) || !$dictionary) throw new \RuntimeException('Survey metadata is empty.');
        foreach ($dictionary as $field) {
            if (!is_object($field) || !is_string($field->field_name ?? null) || $field->field_name === '' ||
                !is_string($field->field_annotation ?? null)) {
                throw new \RuntimeException('Survey metadata is invalid.');
            }
        }
        return $dictionary;
    }

    #endregion

    #region Authentication

    function authenticatePublicDashboardOrReport($username, $password, $project_id, $log_title) {
        if (!is_string($username) || !is_string($password)) return ["success" => false, "error" => $this->settings->failMsg];
        $result = array (
            "success" => false,
            "error" => null,
            "log_error" => [],
        );
        $ip = $_SERVER["REMOTE_ADDR"];

        try {
            $this->authenticateWithLockout($username, $password, $result);
        }
        catch (\Exception $e) {
            $result["success"] = false;
            $result["error"] = $this->settings->errorMsg;
            $result["log_error"][] = $e->getMessage();
        }
        // Write a log entry.
        if ($this->settings->log == "all" || ($this->settings->log == "fail" && !$result["success"]) || ($this->settings->log == "success" && $result["success"])) {
            $changes = "$log_title: " . ($result["success"] ? "Successful authentication via {$result["method"]}" : "Failed or denied login attempt (IP: {$ip})");
            if (count($result["log_error"])) {
                $changes .= "\n" . join("\n", $result["log_error"]);
            }
            \Logging::logEvent("", "", "OTHER", null, $changes, "Survey Auth EM", "", "( ".$username." )", $project_id);
        }
        // Return result.
        return $result;
    }

    /**
     * Determines, whether the credentials are valid.
     */
    function authenticate($username, $password, $project_id, $instrument, $event_id, $repeat_instance, $record, $writeAuthenticationData = true) {
        if (!is_string($username) || !is_string($password)) return ["success" => false, "error" => $this->settings->failMsg];
        $result = array (
            "success" => false,
            "username" => $username,
            "email" => null,
            "fullname" => null,
            "error" => null,
            "log_error" => array()
        );
        $ip = $_SERVER["REMOTE_ADDR"];


        try {
            $this->authenticateWithLockout($username, $password, $result);
            if ($result['success']) {
                $result = $this->completeSurveyAuthentication($result, $project_id, $instrument, $event_id, $repeat_instance, $record, $writeAuthenticationData);
                $record = $result['record'] ?? $record;
            }
        }
        catch (\Exception $e) {
            $result["success"] = false;
            $result["error"] = $this->settings->errorMsg;
            $result["log_error"][] = $e->getMessage();
        }
        // Write a log entry.
        if ($this->settings->log == "all" || ($this->settings->log == "fail" && !$result["success"]) || ($this->settings->log == "success" && $result["success"])) {
            $changes = $result["success"] ? "Successful authentication via {$result["method"]}" : "Failed or denied login attempt (IP: {$ip})";
            // Quote submitted identifiers so control characters cannot forge log lines.
            // A failed attempt identifies only the submitted username, not a verified user.
            $changes .= "\nSubmitted username: ".json_encode($username, JSON_INVALID_UTF8_SUBSTITUTE);
            $changes .= "\nSurvey: ".json_encode($instrument, JSON_INVALID_UTF8_SUBSTITUTE)."; instance: ".(int)$repeat_instance;
            if (count($result["log_error"])) {
                $changes .= "\n" . join("\n", $result["log_error"]);
            }
            $logData = array(
                "action_description" => "Survey Auth EM",
                "changes_made" => $changes,
                "sql" => null,
                "record" => $record,
                "event" => $event_id,
                "project_id" => $project_id
            );
            \REDCap::logEvent($logData["action_description"], $logData["changes_made"], $logData["sql"], $logData["record"], $logData["event"], $logData["project_id"]);
        }
        // Return result.
        return $result;
    }


    // Complete metadata writes only after the response scope is known. This is
    // shared by direct survey login and authenticated return-code selection.
    private function completeSurveyAuthentication(array $result, $project_id, $instrument, $event_id, $repeat_instance, $record, bool $writeAuthenticationData = true): array {
        do {
            // Determine whether authentication metadata should be written.
            $dd = $this->getSurveyDataDictionary($project_id, $instrument);
            $taggedFields = $this->getTaggedFields($dd, $project_id, $record, $event_id, $instrument, $repeat_instance);
            if (!count($taggedFields)) {
                $result["success"] = false;
                $result["error"] = $this->settings->errorMsg;
                $result["log_error"][] = "Could not find a field tagged with the @" . self::$ACTIONTAG . " action tag.";
            }
            else {
                // Use first, any further are ignored
                $tf = $taggedFields[0];
                $record_created = false;
                // Anything to do?
                if ($writeAuthenticationData && $this->settings->canwrite && (count($tf->map) || $tf->successField !== null)) {
                    // If this is a nonpublic survey, $record will be set so. Otherwise, we have to get it after saving
                    $new_record = $record == null;
                    if ($new_record) {
                        // Use "NEW" - it will be overwritten later
                        $record = "NEW";
                    }
                    $result["timestamp"] = date($tf->dateFormat);
                    $data_values = array();
                    if ($tf->successField !== null) $data_values[$tf->successField] = $tf->successValue;
                    // Add mapped data items.
                    foreach ($tf->map as $k => $v) {
                        if (strlen($tf->map[$k])) $data_values[$v] = $result[$k];
                    }
                    $response = $this->saveSurveyAuthenticationValues($data_values, $project_id, $instrument,
                        $event_id, $repeat_instance, $record, $new_record);
                    if (!is_array($response) || !empty($response["errors"]) || ($new_record && !isset($response["ids"][$record]))) {
                        if ($new_record) $record = null;
                        $result["success"] = false;
                        $result["error"] = $this->settings->errorMsg;
                        $result["log_error"][] = "Authentication metadata could not be saved.";
                        break;
                    }
                    else {
                        $result['authentication_values'] = $data_values;
                        $record_created = true;
                        if ($new_record) {
                            $record = $response["ids"][$record];
                        }
                    }
                }
                // Get the survey link.
                if ($record == null) {
                    $survey_id = \Survey::getSurveyId($instrument);
                    $survey_hash = \Survey::getSurveyHash($survey_id, $event_id);
                    $link = APP_PATH_SURVEY_FULL . "?s={$survey_hash}";
                }
                else {
                    $link = \REDCap::getSurveyLink($record, $instrument, $event_id, $repeat_instance, $project_id, $record_created);
                    $survey_hash = explode("?s=", $link, 2)[1];
                }
                $result["targetUrl"] = $link;
                $result["record"] = $record;
            }
        } while (false);
        return $result;
    }

    private function saveSurveyAuthenticationValues(array $data_values, $project_id, $instrument,
        $event_id, $repeat_instance, $record, bool $new_record = false)
    {
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
        return $response;
    }

    private function authenticateWithLockout(string $username, string $password, array &$result): void {
        $ip = $_SERVER['REMOTE_ADDR'];
        if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new \RuntimeException('Client IP address is unavailable.');
        }
        $lock = null;
        // Serialize admission, verification and bookkeeping for this IP across
        // projects/sessions. The short storage lock is never held during LDAP.
        if ($this->settings->lockouttime > 0) {
            $lock = ':'.$this->PREFIX.':authentication:'.$ip;
            $q = $this->lockoutQuery('SELECT GET_LOCK(SHA2(CONCAT(DATABASE(), ?), 256), 5) AS acquired', [$lock]);
            if ((int)(db_fetch_assoc($q)['acquired'] ?? 0) !== 1) {
                throw new \RuntimeException('Authentication is busy. Please try again.');
            }
        }
        try {
            if ($this->settings->lockoutCount && $this->checkLockoutStatus($ip) >= $this->settings->lockoutCount) {
                $result['error'] = $this->settings->lockoutMsg;
                $result['lockout'] = $this->settings->lockouttime * 60 * 1000;
                return;
            }
            if ($this->settings->useWhitelist && !in_array(strtolower($username), $this->settings->whitelist, true)) {
                return;
            }
            $this->authenticateBackends($username, $password, $result);
            if ($result['success']) {
                $this->clearLockoutStatus($ip);
            } else {
                $result['error'] = count($result['log_error']) ? $this->settings->errorMsg : $this->settings->failMsg;
                $this->updateLockoutStatus($ip);
            }
        } finally {
            if ($lock !== null) $this->lockoutQuery('SELECT RELEASE_LOCK(SHA2(CONCAT(DATABASE(), ?), 256))', [$lock]);
        }
    }

    private function authenticateBackends($username, $password, array &$result): void {
        // Match the order presented in module settings and documentation.
        foreach (['Custom', 'Table', 'OtherLDAP', 'LDAP'] as $backend) {
            if (!$this->settings->{'use'.$backend}) continue;
            $attempt = ['success'=>false, 'username'=>$username, 'email'=>null, 'fullname'=>null, 'log_error'=>[]];
            $this->{'authenticate'.$backend}($username, $password, $attempt);
            $result['log_error'] = array_merge($result['log_error'], $attempt['log_error']);
            if ($attempt['success']) {
                unset($attempt['log_error']);
                $result = array_replace($result, $attempt);
                return;
            }
        }
    }

    private function authenticateTable($username, $password, &$result) {
        try {
            $account = \User::getUserInfo($username);
            if ($account && empty($account['user_suspended_time']) && \Authentication::verifyTableUsernamePassword($username, $password)) {
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
        if (!is_string($username) || !is_string($password) || $password === '') return;
        $username = strtolower(trim($username));
        if ($username !== '' && isset($this->settings->customCredentials[$username]) &&
            $this->settings->customCredentials[$username] !== '' &&
            hash_equals((string)$this->settings->customCredentials[$username], $password)) {
            $result["success"] = true;
            $result["method"] = "Custom";
        }
    }

    private function authenticateLDAP($username, $password, &$result) {
        include APP_PATH_WEBTOOLS . 'ldap/ldap_config.php';
        $configs = isset($GLOBALS["ldapdsn"]) ? $GLOBALS["ldapdsn"] : array();
        if (array_key_exists("url", $configs)) $configs = array ($configs);

        foreach ($configs as $config) {
            $attempt = ['success'=>false, 'username'=>$username, 'email'=>null, 'fullname'=>null, 'log_error'=>[]];
            $this->doLDAPauth($username, $password, $config, $attempt);
            $result['log_error'] = array_merge($result['log_error'], $attempt['log_error']);
            if ($attempt['success']) {
                unset($attempt['log_error']);
                $result = array_replace($result, $attempt, ['method'=>'LDAP']);
                break;
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
            $attempt = ['success'=>false, 'username'=>$username, 'email'=>null, 'fullname'=>null, 'log_error'=>[]];
            $this->doLDAPauth($username, $password, $config, $attempt);
            $result['log_error'] = array_merge($result['log_error'], $attempt['log_error']);
            if ($attempt['success']) {
                unset($attempt['log_error']);
                $result = array_replace($result, $attempt, ['method'=>"Other LDAP ({$config['host']}:{$config['port']})"]);
                break;
            }
        }
    }

    //region LDAP

    private function ldapIdentity($ldap, $entry): array {
        // LDAP attribute descriptions are case-insensitive; servers may preserve
        // schema casing (for example givenName) even when mappings use lowercase.
        $attributes = array_change_key_case(@ldap_get_attributes($ldap, $entry) ?: [], CASE_LOWER);
        $data = array_fill_keys(['email', 'fullname', 'firstname', 'lastname'], '');
        foreach ($this->settings->ldapMappings as $key => $names) {
            foreach ($names as $name) {
                $name = strtolower($name);
                if (isset($attributes[$name]) && $attributes[$name]['count'] >= 1) {
                    $data[$key] = trim($attributes[$name][0]);
                    break;
                }
            }
        }
        return ['fullname'=>$data['fullname'] !== '' ? $data['fullname'] : trim($data['firstname'].' '.$data['lastname']),
            'email'=>strtolower($data['email'])];
    }

    private function doLDAPauth($username, $password, $config, &$result) {
        // Never publish attributes from an entry that has not authenticated.
        $result['success'] = false;
        $result['fullname'] = $result['email'] = null;
        if ($password === '') return;
        if (!extension_loaded('ldap')) {
            $result['log_error'][] = 'LDAP extension not loaded.';
            return;
        }
        $config = $this->mergeLDAPConfig($config);
        $ldap = $search = $read = null;
        try {
            $ldap = ldap_connect($config['url'], $config['port']);
            if ($ldap === false) throw new \RuntimeException('Failed to connect to LDAP server.');
            if (!in_array($config['version'], [2, 3, '2', '3'], true) || !is_bool($config['start_tls']) ||
                ($config['start_tls'] && (int)$config['version'] !== 3)) {
                throw new \RuntimeException('Invalid LDAP protocol/TLS configuration.');
            }
            if (!@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, (int)$config['version'])) {
                throw new \RuntimeException('Could not set LDAP protocol version.');
            }
            if ($config['start_tls'] && !@ldap_start_tls($ldap)) {
                throw new \RuntimeException('Could not start TLS session.');
            }
            if (is_bool($config['referrals']) && !@ldap_set_option($ldap, LDAP_OPT_REFERRALS, $config['referrals'])) {
                throw new \RuntimeException('Could not change LDAP referral options.');
            }
            $bound = strlen($config['binddn']) && strlen($config['bindpw'])
                ? @ldap_bind($ldap, $config['binddn'], $config['bindpw']) : @ldap_bind($ldap);
            if (!$bound) throw new \RuntimeException('LDAP service bind failed.');
            $this->checkBaseDN($ldap, $config);
            $searchUsername = $username;
            // Browser form values already use UTF-8, as required by LDAP v3.
            $filter = sprintf('(&(%s=%s)%s)', $config['userattr'], $this->quoteFilterString($searchUsername), $config['userfilter']);
            $base = $config['userdn'];
            if ($base !== '' && substr($base, -1) !== ',') $base .= ',';
            $base .= $config['basedn'];
            $search = match ($config['userscope']) {
                'one' => @ldap_list($ldap, $base, $filter, $config['attributes']),
                'base' => @ldap_read($ldap, $base, $filter, $config['attributes']),
                default => @ldap_search($ldap, $base, $filter, $config['attributes'])
            };
            if ($search === false) return;
            for ($entry = @ldap_first_entry($ldap, $search); $entry !== false; $entry = @ldap_next_entry($ldap, $entry)) {
                $dn = @ldap_get_dn($ldap, $entry);
                $identity = $this->ldapIdentity($ldap, $entry);
                if (!@ldap_bind($ldap, $dn, $password)) continue;
                if (strlen($config['group']) && !$this->checkGroup($ldap, $config, $config['memberisdn'] ? $dn : $searchUsername)) continue;
                $read = @ldap_read($ldap, $dn, $filter, $config['attributes']);
                if ($read !== false) {
                    for ($userEntry = @ldap_first_entry($ldap, $read); $userEntry !== false; $userEntry = @ldap_next_entry($ldap, $userEntry)) {
                        if ($dn !== @ldap_get_dn($ldap, $userEntry)) continue;
                        foreach ($this->ldapIdentity($ldap, $userEntry) as $key => $value) {
                            if ($value !== '') $identity[$key] = $value;
                        }
                        break;
                    }
                }
                if ($this->settings->fallbackToTableUserInfo && (empty($identity['fullname']) || empty($identity['email']))) {
                    $q = $this->framework->query('SELECT user_email, user_firstname, user_lastname FROM redcap_user_information WHERE username=? LIMIT 1', [$username]);
                    if ($row = $q->fetch_assoc()) {
                        if (empty($identity['fullname'])) $identity['fullname'] = trim($row['user_firstname'].' '.$row['user_lastname']);
                        if (empty($identity['email'])) $identity['email'] = $row['user_email'];
                    }
                }
                $result = array_replace($result, $identity, ['success'=>true]);
                return;
            }
        } catch (\Throwable $e) {
            $result['log_error'][] = 'LDAP error: '.$e->getMessage();
        } finally {
            foreach ([$read, $search] as $handle) {
                if ($handle !== null && $handle !== false) @ldap_free_result($handle);
            }
            if ($ldap !== null && $ldap !== false) @ldap_unbind($ldap);
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
            "version" => 3,
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
            $member = @ldap_count_entries($ldap, $resultId) == 1;
            @ldap_free_result($resultId);
            return $member;
        }
        // User is not a member of the group.
        return false;
    }

    //endregion

    //region Lockout

    private function lockoutBucketForIp(string $ip): string {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new \RuntimeException('Invalid lockout address.');
        }
        // A hexadecimal nibble gives 16 stable, evenly distributed buckets.
        return dechex(ord(hash('sha256', $ip, true)[0]) >> 4);
    }

    private function lockoutBucketSettingKey(string $bucket): string {
        if (!preg_match('/^[0-9a-f]$/', $bucket)) throw new \RuntimeException('Invalid lockout bucket.');
        return 'surveyauth_lockouts_'.$bucket;
    }

    private function decodeLockoutStatus($raw, int $maxBytes): array {
        if ($raw === null || $raw === '') return [];
        if (!is_string($raw) || strlen($raw) > $maxBytes) {
            throw new \RuntimeException('Invalid lockout storage size.');
        }
        $status = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($status)) throw new \RuntimeException('Invalid lockout storage.');
        return $status;
    }

    private function normalizeLockoutStatus(array $status, $lockouttime, ?string $bucket = null): array {
        $normalized = [];
        $expiresBefore = time() - max(0, (int)ceil($lockouttime * 60));
        foreach ($status as $ip => $entry) {
            if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false || !is_array($entry) ||
                !isset($entry['n'], $entry['ts']) || !is_int($entry['n']) || !is_int($entry['ts']) ||
                $entry['n'] < 1 || $entry['ts'] <= $expiresBefore ||
                ($bucket !== null && $this->lockoutBucketForIp($ip) !== $bucket)) {
                continue;
            }
            $normalized[$ip] = ['n'=>$entry['n'], 'ts'=>$entry['ts']];
        }
        return $normalized;
    }

    /**
     * Helper function which checks whether failed login attempts have been recorded for an IP address.
     */
    private function checkLockoutStatus($ip) {
        if ($this->settings->lockouttime <= 0 || !$this->settings->lockoutCount) return 0;
        $this->refreshLockoutStatus($this->lockoutBucketForIp($ip));
        return $this->currentLockoutFailures($ip);
    }

    private function currentLockoutFailures($ip): int {
        $status = $this->settings->lockoutStatus[$ip] ?? null;
        if (!$status || time() >= $status["ts"] + $this->settings->lockouttime * 60) return 0;
        // Checking a blocked request must not increment failures or extend expiry.
        return (int)$status["n"];
    }

    /**
     * Record one failed authentication attempt, starting over after expiry.
     */
    private function updateLockoutStatus($ip) {
        if ($this->settings->lockouttime <= 0 || !$this->settings->lockoutCount) return;
        $bucket = $this->lockoutBucketForIp($ip);
        $this->mutateLockoutStatus($bucket, function () use ($ip) {
            if (!isset($this->settings->lockoutStatus[$ip]) &&
                count($this->settings->lockoutStatus) >= self::LOCKOUT_BUCKET_MAX_ENTRIES) {
                throw new \RuntimeException('Lockout storage capacity reached.');
            }
            $this->settings->lockoutStatus[$ip] = [
                'n' => $this->currentLockoutFailures($ip) + 1,
                'ts' => time()
            ];
            return true;
        });
    }

    private function clearLockoutStatus($ip) {
        $bucket = $this->lockoutBucketForIp($ip);
        $this->mutateLockoutStatus($bucket, function () use ($ip) {
            if (!isset($this->settings->lockoutStatus[$ip])) return false;
            unset($this->settings->lockoutStatus[$ip]);
            return true;
        });
    }

    private function lockoutQuery(string $sql, array $params = []) {
        // Advisory locks and their protected reads must use the primary connection.
        // Framework query() does not expose REDCap's primary-connection flag.
        $result = \db_query($sql, $params, null, MYSQLI_STORE_RESULT, true);
        if ($result === false) throw new \RuntimeException('Could not access lockout storage.');
        return $result;
    }

    private function refreshLockoutStatus(string $bucket): bool {
        $settingKey = $this->lockoutBucketSettingKey($bucket);
        $q = $this->lockoutQuery('SELECT s.value FROM redcap_external_module_settings s
            JOIN redcap_external_modules m ON m.external_module_id=s.external_module_id
            WHERE m.directory_prefix=? AND s.project_id IS NULL AND s.`key`=?',
            [$this->PREFIX, $this->framework->prefixSettingKey($settingKey)]);
        $row = db_fetch_assoc($q);
        if ($row && db_fetch_assoc($q)) throw new \RuntimeException('Duplicate lockout settings.');
        $status = $this->decodeLockoutStatus($row['value'] ?? null, self::LOCKOUT_BUCKET_MAX_BYTES);
        $this->settings->lockoutStatus = $this->normalizeLockoutStatus(
            $status,
            $this->settings->lockouttime,
            $bucket
        );
        if (count($this->settings->lockoutStatus) > self::LOCKOUT_BUCKET_MAX_ENTRIES) {
            throw new \RuntimeException('Invalid lockout storage capacity.');
        }
        return $this->settings->lockoutStatus !== $status;
    }

    private function mutateLockoutStatus(string $bucket, callable $change): void {
        $suffix = ':'.$this->PREFIX.':lockouts:'.$bucket;
        $q = $this->lockoutQuery('SELECT GET_LOCK(SHA2(CONCAT(DATABASE(), ?), 256), 5) AS acquired', [$suffix]);
        if ((int)(db_fetch_assoc($q)['acquired'] ?? 0) !== 1) {
            throw new \RuntimeException('Lockout storage is busy. Please try again.');
        }
        try {
            $pruned = $this->refreshLockoutStatus($bucket);
            if ($change() || $pruned) {
                $encoded = json_encode($this->settings->lockoutStatus, JSON_THROW_ON_ERROR);
                if (strlen($encoded) > self::LOCKOUT_BUCKET_MAX_BYTES) throw new \RuntimeException('Lockout storage capacity reached.');
                $this->framework->setSystemSetting($this->lockoutBucketSettingKey($bucket), $encoded);
            }
        } finally {
            $this->lockoutQuery('SELECT RELEASE_LOCK(SHA2(CONCAT(DATABASE(), ?), 256))', [$suffix]);
        }
    }

    //endregion

    #endregion

}
