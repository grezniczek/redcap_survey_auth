<?php
// Separate processes exercise REDCap APIs that cannot coexist in one bootstrap.
if ($argc === 1) {
    foreach (['legacy', 'helper', 'entry'] as $core) {
        foreach (['root', 'subdirectory', 'separate'] as $layout) {
            $process = proc_open([PHP_BINARY, __FILE__, $core, $layout],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            if (!is_resource($process)) throw new RuntimeException('Could not start session fixture.');
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            $errors = stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            if (proc_close($process) !== 0 || $errors !== '') {
                throw new RuntimeException("$core/$layout failed: $output$errors");
            }
        }
    }
    echo "Passed legacy, helper and entry-point survey session naming regressions across three URL layouts.\n";
    exit;
}

ob_start();
session_save_path(sys_get_temp_dir());
[$script, $core, $layout] = $argv;
$base = $layout === 'subdirectory' ? '/redcap/' : '/';
define('PAGE', 'surveys/index.php');
define('APP_PATH_WEBROOT_PARENT', $base);
define('APP_PATH_SURVEY_FULL', 'https://survey.example'.$base.'surveys/');
$requestBase = $layout === 'separate' ? '/internal/' : $base;
$_SERVER['REQUEST_URI'] = $requestBase.'surveys/?s=fixture';

class SessionFixture
{
    public static $calls = 0;
    public static $fail = false;
    public static function init($name)
    {
        self::$calls++;
        if (self::$fail) return false;
        // Core does not restart a closed session when its ID remains set.
        if (session_id() !== '') return true;
        session_name($name);
        return session_start();
    }
}
if ($core === 'legacy') {
    class Session extends SessionFixture {}
} else {
    class Session extends SessionFixture
    {
        const cookie_name_survey_prefix = 'redcap_survey_session_';
        public static function getCookieName($isSurveyPage = false)
        {
            return ($isSurveyPage ? self::cookie_name_survey_prefix : 'redcap_session_').
                substr(sha1(APP_PATH_WEBROOT_PARENT), 0, 7);
        }
    }
}
require dirname(__DIR__).'/classes/SurveySessionAuth.php';
class SessionProbe
{
    use \DE\RUB\SurveyAuthExternalModule\SurveySessionAuth;
    public function ready(): bool { return $this->surveySessionReady(); }
}
function check($condition, $message)
{
    if (!$condition) throw new RuntimeException($message);
}
function resetSession()
{
    if (session_status() === PHP_SESSION_ACTIVE) session_destroy();
    session_id('');
}
function startSession($name)
{
    resetSession();
    session_name($name);
    check(session_start(), 'Fixture session starts');
}
$probe = new SessionProbe();
$defaultName = $core === 'legacy' ? 'survey' : Session::getCookieName(true);
$entryName = $core === 'legacy' ? 'survey' : Session::cookie_name_survey_prefix.
    substr(sha1(dirname(dirname($_SERVER['REQUEST_URI'])).'/'), 0, 7);

// Simulate the name established by core before the module hook.
startSession($core === 'entry' ? $entryName : $defaultName);
$_SESSION['native_survey_state'] = ['response' => 'fixture'];
$id = session_id(); $name = session_name(); $calls = Session::$calls;
check($probe->ready(), 'Core survey session is accepted');
check(session_id() === $id && session_name() === $name &&
    $_SESSION['native_survey_state'] === ['response' => 'fixture'] && Session::$calls === $calls,
    'Active survey session is preserved without reinitialization');

if ($core !== 'legacy') {
    // Both directory and explicit index.php requests share the entry-point name.
    $_SERVER['REQUEST_URI'] = $requestBase.'surveys/index.php?s=fixture';
    startSession($entryName);
    check($probe->ready(), 'Explicit index.php uses the same survey session');
}

resetSession();
check($probe->ready() && session_name() === $defaultName,
    'Missing session initializes through the helper or legacy fallback');
session_write_close();
check(!$probe->ready(), 'An inactive session is rejected even if core init returns true');
// Remove the synthetic file left by the closed-session case.
session_start(); resetSession();
Session::$fail = true;
check(!$probe->ready(), 'Failed initialization is rejected');
Session::$fail = false;

$invalidNames = ['PHPSESSID', 'redcap_session_'.substr(sha1($base), 0, 7),
    'redcap_survey_session_unrelated'];
if ($core !== 'legacy') $invalidNames[] = 'survey';
foreach ($invalidNames as $invalidName) {
    startSession($invalidName);
    $_SESSION['staff_state'] = 'preserved';
    $id = session_id(); $calls = Session::$calls;
    check(!$probe->ready(), 'Staff and unrelated survey sessions are rejected');
    check(session_id() === $id && session_name() === $invalidName &&
        $_SESSION['staff_state'] === 'preserved' && Session::$calls === $calls,
        'Rejected sessions are left untouched');
}
resetSession();
ob_end_clean();
