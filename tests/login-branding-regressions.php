<?php
// Standalone login rendering tests; no installation, database, or credentials.
ob_start();
require __DIR__.'/session-regressions.php';
$fixture = new class extends SurveyAuthQueryFixture {
    public function initializeJavascriptModuleObject() { echo '<script>window.testSurveyAuthModule = {};</script>'; }
    public function getJavascriptModuleObjectName() { return 'window.testSurveyAuthModule'; }
    public function getCSRFToken() { return str_repeat('a',80); }
    public function loadREDCapJS() { $this->redcapJsLoaded = true; }
    public function loadBootstrap() { $this->bootstrapLoaded = true; }
};
$module->framework = $fixture;
$_SESSION['redcap_survey_auth_v2']['logins']['branding'] = [
    'scope' => $scope, 'csrf' => 'test-csrf', 'expires' => time()+600,
];
$settings->text = '<em>Please sign in.</em><script>alert(1)</script><img src="x" onerror="alert(2)">';
$settings->usernameLabel = 'Username';
$settings->passwordLabel = 'Password';
$settings->submitLabel = 'Sign in';
function renderBranding($branding, $error = '<unsafe-error>') {
    global $module, $fixture;
    $fixture->results = [[$branding]];
    ob_start();
    callPrivate($module, 'renderSurveyLogin', 'branding', $error);
    return ob_get_clean();
}
function checkLoginForm($html) {
    check(str_contains($html, 'data-context="branding"') && str_contains($html, 'data-csrf="test-csrf"'),
        'AJAX form retains its session context and independent CSRF');
    check(str_contains($html, 'initializeSurveyAuthLogin(document.getElementById(') &&
        str_contains($html, 'window.testSurveyAuthModule'), 'Form uses the initialized framework JSMO');
    check(!preg_match('/<input[^>]+name=/', $html), 'Credentials cannot fall back to ordinary form submission');
    check(str_contains($html, '<noscript>') && str_contains($html, 'type="submit" disabled'),
        'Login stays disabled until JavaScript initializes');
}
$loginTemplate = file_get_contents(dirname(__DIR__).'/html/session-login.php');
check(strpos($loginTemplate, '<h1 data-surveyauth-survey-title>') < strpos($loginTemplate, 'id="survey-auth-languages"') &&
    strpos($loginTemplate, 'id="survey-auth-languages"') < strpos($loginTemplate, '<h2 data-surveyauth-i18n="login.heading">'),
    'The MLM language selector is placed between the survey title and login prompt.');
check(!str_contains($loginTemplate, 'login.language_label') &&
    !str_contains($loginTemplate, 'data-surveyauth-i18n-aria-label') &&
    str_contains($loginTemplate, 'data-surveyauth-survey-logo') &&
    str_contains($loginTemplate, 'class="btn <?= $languageId === $mlmCatalogue[\'current\'] ? \'btn-primary\' : \'btn-outline-secondary\' ?> btn-sm"') &&
    str_contains($loginTemplate, 'class="form-control form-control-sm"') && str_contains($loginTemplate, 'class="btn btn-primary mt-3"'),
    'Login controls and the MLM selector retain their Bootstrap presentation.');
REDCap::$testFile = ['text/html', 'untrusted-name.html', base64_decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')];
$html = renderBranding(['title'=>'<b>A & B</b>', 'hide_title'=>0, 'doc_id'=>42]);
check($_SESSION['redcap_survey_auth_v2']['logins']['branding']['framework_csrf']===str_repeat('a',80),
    'Login context retains the framework token embedded in that tab');
checkLoginForm($html);
check(!str_contains($html, 'data-surveyauth-return-code'), 'Ineligible login contexts do not show a return-code control.');
$_SESSION['redcap_survey_auth_v2']['logins']['branding']['allow_return_code'] = true;
$returnHtml = renderBranding(['title'=>'Survey', 'hide_title'=>0, 'doc_id'=>null]);
check(str_contains($returnHtml, 'data-surveyauth-return-code') && str_contains($returnHtml, 'id="return-code"') &&
    str_contains($returnHtml, 'type="password"') && str_contains($returnHtml, 'maxlength="15"') && !preg_match('/<input[^>]+name=/', $returnHtml),
    'Eligible public survey contexts render an unnamed, masked, bounded return-code input.');
check(str_contains($returnHtml, 'data-surveyauth-core-i18n="survey_22"') &&
    str_contains($returnHtml, 'data-surveyauth-core-i18n="survey_118"') &&
    str_contains($returnHtml, 'data-surveyauth-core-i18n="survey_24"') &&
    strpos($returnHtml, 'data-surveyauth-core-i18n="survey_22"') < strpos($returnHtml, 'data-surveyauth-core-i18n="survey_24"') &&
    strpos($returnHtml, 'data-surveyauth-core-i18n="survey_24"') < strpos($returnHtml, 'data-surveyauth-core-i18n="survey_118"'),
    'Returning text uses MLM core strings, with the standard help directly below the heading.');
unset($_SESSION['redcap_survey_auth_v2']['logins']['branding']['allow_return_code']);
check(!empty($fixture->redcapJsLoaded) && !empty($fixture->bootstrapLoaded),
    'The standalone login loads the REDCap Bootstrap assets through framework helpers.');
check(preg_match('/<h1(?:\s[^>]*)?>A &amp; B<\/h1>/', $html) === 1, 'Survey title is plain, escaped text');
check(str_contains($html, '<em>Please sign in.</em>') && !str_contains($html, 'alert(1)') && !str_contains($html, 'onerror'),
    'Configured instruction HTML is filtered through REDCap before rendering.');
check(str_contains($html, 'src="data:image/png;base64,'), 'Logo type comes from image bytes, not stored MIME');
check(str_contains($html, '&lt;unsafe-error&gt;'), 'Failed login error remains escaped');
check(str_contains(renderBranding(['title'=>'Survey', 'hide_title'=>0, 'doc_id'=>null], ''),
    'id="survey-auth-error" role="alert" hidden'), 'Empty errors do not occupy space on the login page.');
check($fixture->queries[0][1] === [1,2], 'Branding lookup uses the stored project and survey');
check(REDCap::$fileReads === [42], 'Only the configured, project-owned logo is read');
$html = renderBranding(['title'=>'Hidden title', 'hide_title'=>1, 'doc_id'=>null]);
check(!str_contains($html, 'Hidden title') && !str_contains($html, 'class="survey-logo"'), 'Hidden title and absent logo stay absent');
check(REDCap::$fileReads === [42], 'No file read when the logo join rejects it');
REDCap::$testFile = ['image/png', 'logo.png', '<svg onload="alert(1)"></svg>'];
$html = renderBranding(['title'=>'Survey', 'hide_title'=>0, 'doc_id'=>43]);
check(!str_contains($html, 'class="survey-logo"'), 'Non-raster content cannot become a login logo');
$_SESSION['redcap_survey_auth_v2']['logins']['branding']['resource'] = ['type'=>'dashboard', 'title'=>'Dashboard', 'hash'=>'dashboard-hash'];
checkLoginForm(renderBranding([]));
$_SESSION['redcap_survey_auth_v2']['logins']['branding']['resource']['type'] = 'report';
checkLoginForm(renderBranding([]));
echo "Passed login branding and escaping regressions.\n";
ob_end_flush();
