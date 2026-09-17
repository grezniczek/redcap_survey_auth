<!doctype html>
<html lang="<?= $escape($htmlLang) ?>"<?= $rtl ? ' dir="rtl"' : '' ?>>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $surveyTitle !== '' ? $surveyTitle.' — ' : '' ?><?= $escape($loginHeading) ?></title>
<style>
body { font: 1rem/1.5 system-ui, sans-serif; background: #f4f5f7; color: #222; margin: 0; }
main { max-width: 28rem; margin: 8vh auto; padding: 2rem; background: white; border-radius: .5rem; }
.survey-logo { display: block; max-width: 100%; height: auto; margin: 0 auto 1.5rem; }
h1 { overflow-wrap: anywhere; }
label { display: block; margin-top: 1rem; }
input { box-sizing: border-box; width: 100%; padding: .65rem; font: inherit; }
button { margin-top: 1.5rem; padding: .7rem 1.5rem; font: inherit; cursor: pointer; }
[role=alert] { color: #a32020; }
.survey-auth-languages { margin: 1rem 0; }
.survey-auth-languages button { margin: .25rem .5rem .25rem 0; }
</style>
<main>
<?php if ($logoSource !== ''): ?><img class="survey-logo" src="<?= $logoSource ?>" alt="<?= $escape($logoAlt) ?>"><?php endif; ?>
<?php if ($surveyTitle !== ''): ?><h1><?= $surveyTitle ?></h1><h2 data-surveyauth-i18n="login.heading"><?= $escape($loginHeading) ?></h2><?php else: ?>
<h1 data-surveyauth-i18n="login.heading"><?= $escape($loginHeading) ?></h1>
<?php endif; ?>
<div data-surveyauth-i18n="login.instructions" data-surveyauth-html="true"><?= $instructions ?></div>
<p id="survey-auth-error" role="alert"<?= $errorKey !== '' ? ' data-surveyauth-error-key="'.$escape($errorKey).'"' : '' ?>><?= $escape($error) ?></p>
<noscript><p><?= $escape($noJavascript) ?></p></noscript>
<?php if (count($mlmCatalogue['languages'] ?? []) > 1): ?>
<div class="survey-auth-languages" id="survey-auth-languages">
<strong data-surveyauth-i18n="login.language_label"><?= $escape($languageLabel) ?></strong>
<?php foreach ($mlmCatalogue['languages'] as $languageId => $language): ?>
<button type="button" data-surveyauth-language="<?= $escape($languageId) ?>"<?= $languageId === $mlmCatalogue['current'] ? ' aria-pressed="true"' : ' aria-pressed="false"' ?>><?= $escape($language['display']) ?></button>
<?php endforeach; ?>
</div>
<?php endif; ?>
<form id="survey-auth-login" data-context="<?= $escape($id) ?>" data-csrf="<?= $csrf ?>" onsubmit="return false">
<label for="username" data-surveyauth-i18n="login.username_label"><?= $escape($usernameLabel) ?></label>
<input id="username" autocomplete="username" required autofocus>
<label for="password" data-surveyauth-i18n="login.password_label"><?= $escape($passwordLabel) ?></label>
<input id="password" type="password" autocomplete="current-password" required>
<button type="submit" disabled data-surveyauth-i18n="login.submit_label"><?= $escape($submitLabel) ?></button>
</form>
</main>
<?= $moduleJavascript ?>
<script>
<?php require __DIR__.'/../js/survey-login.js'; ?>
initializeSurveyAuthLogin(document.getElementById('survey-auth-login'), <?= $jsObject ?>, <?= $mlmCatalogueJson ?>);
</script>
</html>
