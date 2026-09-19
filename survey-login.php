<?php
// Routed through the EM Framework's NOAUTH page and CSRF validation.
if (!isset($module) || !($module instanceof \DE\RUB\SurveyAuthExternalModule\SurveyAuthExternalModule)) {
    http_response_code(403);
    exit;
}
try {
    $module->surveyLogin();
} catch (\Throwable $e) {
    http_response_code(503);
    print 'Survey login could not be completed. Please contact the survey administrator.';
}
