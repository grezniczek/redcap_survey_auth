<?php
// Standalone login rendering tests; no installation, database, or credentials.
ob_start();
require __DIR__.'/session-regressions.php';
$fixture = new class extends SurveyAuthQueryFixture {
    public function getUrl($path, $noAuth) { return '/external_modules/?page=survey-login&pid=1'; }
};
$module->framework = $fixture;
$_COOKIE['redcap_external_module_csrf_token'] = str_repeat('a', 80);
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
REDCap::$testFile = ['text/html', 'untrusted-name.html', base64_decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')];
$html = renderBranding(['title'=>'<b>A & B</b>', 'hide_title'=>0, 'doc_id'=>42]);
check(str_contains($html, '<h1>A &amp; B</h1>'), 'Survey title is plain, escaped text');
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
echo "Passed login branding and escaping regressions.\n";
ob_end_flush();
