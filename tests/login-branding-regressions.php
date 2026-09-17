<?php
// Standalone login rendering tests; no installation, database, or credentials.
ob_start();
require __DIR__.'/session-regressions.php';
$fixture = new class extends SurveyAuthQueryFixture {
    public function initializeJavascriptModuleObject() { echo '<script>window.testSurveyAuthModule = {};</script>'; }
    public function getJavascriptModuleObjectName() { return 'window.testSurveyAuthModule'; }
    public function getCSRFToken() { return str_repeat('a',80); }
};
$module->framework = $fixture;
$_SESSION['redcap_survey_auth_v2']['logins']['branding'] = [
    'scope' => $scope, 'csrf' => 'test-csrf', 'expires' => time()+600,
];
$settings->text = 'Please sign in.';
$settings->usernameLabel = 'Username';
$settings->passwordLabel = 'Password';
$settings->submitLabel = 'Sign in';
function renderBranding($branding) {
    global $module, $fixture;
    $fixture->results = [[$branding]];
    ob_start();
    callPrivate($module, 'renderSurveyLogin', 'branding', '<unsafe-error>');
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
REDCap::$testFile = ['text/html', 'untrusted-name.html', base64_decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')];
$html = renderBranding(['title'=>'<b>A & B</b>', 'hide_title'=>0, 'doc_id'=>42]);
check($_SESSION['redcap_survey_auth_v2']['logins']['branding']['framework_csrf']===str_repeat('a',80),
    'Login context retains the framework token embedded in that tab');
checkLoginForm($html);
check(preg_match('/<h1(?:\s[^>]*)?>A &amp; B<\/h1>/', $html) === 1, 'Survey title is plain, escaped text');
check(str_contains($html, 'src="data:image/png;base64,'), 'Logo type comes from image bytes, not stored MIME');
check(str_contains($html, '&lt;unsafe-error&gt;'), 'Failed login error remains escaped');
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
