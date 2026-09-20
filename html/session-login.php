<!doctype html>
<html lang="<?= $escape($htmlLang) ?>" <?= $rtl ? ' dir="rtl"' : '' ?>>

<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title id="survey-auth-page-title"><?= $surveyTitle !== '' ? $surveyTitle . ' — ' : '' ?><?= $escape($loginHeading) ?></title>
	<?= $redcapAssets ?>
	<?php if ($fontAwesomeCss !== ''): ?>
		<link rel="stylesheet" href="<?= $escape($fontAwesomeCss) ?>"><?php endif; ?>
	<?php if ($multiLanguageCss !== ''): ?>
		<link rel="stylesheet" href="<?= $escape($multiLanguageCss) ?>"><?php endif; ?>
	<style>
		body {
			font: 1rem/1.5 system-ui, sans-serif;
			background: #f4f5f7;
			color: #222;
			margin: 0;
		}
		main {
			max-width: 28rem;
			margin: 8vh auto;
			padding: 2rem;
			background: white;
			border-radius: .5rem;
		}
		.survey-logo {
			display: block;
			max-width: 100%;
			height: auto;
			margin: 0 auto 1.75rem;
		}
		h1 {
			overflow-wrap: anywhere;
			font-size: 1.75rem;
		}
		h2 {
			font-size: 1.5rem;
		}
		#survey-auth-error:not([hidden]) {
			margin-top: 1rem;
			padding: .75rem 1rem;
			color: #842029;
			background-color: #fff5f5;
			border: 1px solid #dc3545;
			border-radius: var(--bs-border-radius, .375rem);
		}
		.survey-auth-languages {
			margin-bottom: .5rem;
		}
		.survey-auth-languages button {
			margin-bottom: .2rem;
		}
		.survey-auth-language-check {
			display: none;
		}
		.btn-primary .survey-auth-language-check {
			display: inline;
		}
	</style>
</head>

<body>
	<main>
		<?php if ($logoSource !== ''): ?><img class="survey-logo" data-surveyauth-survey-logo src="<?= $logoSource ?>" alt="<?= $escape($logoAlt) ?>"><?php endif; ?>
		<?php if ($surveyTitle !== ''): ?><h1 data-surveyauth-survey-title><?= $surveyTitle ?></h1><?php endif; ?>
		<?php if (count($mlmCatalogue['languages'] ?? []) > 1): ?>
			<div class="survey-auth-languages" id="survey-auth-languages">
				<?php foreach ($mlmCatalogue['languages'] as $languageId => $language): ?>
					<button type="button" class="btn <?= $languageId === $mlmCatalogue['current'] ? 'btn-primary' : 'btn-outline-secondary' ?> btn-sm" data-surveyauth-language="<?= $escape($languageId) ?>" <?= $languageId === $mlmCatalogue['current'] ? ' aria-pressed="true"' : ' aria-pressed="false"' ?>><i class="fas fa-check me-1 survey-auth-language-check" aria-hidden="true"></i><?= $escape($language['display']) ?></button>
				<?php endforeach; ?>
			</div>
		<?php endif; ?>
		<?php if ($surveyTitle !== ''): ?><h2 data-surveyauth-i18n="login.heading"><?= $escape($loginHeading) ?></h2><?php else: ?>
			<h1 data-surveyauth-i18n="login.heading"><?= $escape($loginHeading) ?></h1>
		<?php endif; ?>
		<div data-surveyauth-i18n="login.instructions" data-surveyauth-html="true"><?= $instructions ?></div>
		<div id="survey-auth-error" role="alert"<?= trim($error) === '' ? ' hidden' : '' ?><?= $errorKey !== '' ? ' data-surveyauth-error-key="' . $escape($errorKey) . '"' : '' ?>><?= $escape($error) ?></div>
		<noscript>
			<p><?= $escape($noJavascript) ?></p>
		</noscript>
		<form id="survey-auth-login" data-context="<?= $escape($id) ?>" data-csrf="<?= $csrf ?>" onsubmit="return false">
			<label class="form-label mt-3" for="username" data-surveyauth-i18n="login.username_label"><?= $escape($usernameLabel) ?></label>
			<input class="form-control form-control-sm" id="username" autocomplete="username" required autofocus>
			<label class="form-label mt-2" for="password" data-surveyauth-i18n="login.password_label"><?= $escape($passwordLabel) ?></label>
			<input class="form-control form-control-sm" id="password" type="password" autocomplete="current-password" required>
			<?php if ($allowReturnCode): ?>
				<div class="mt-3" data-surveyauth-return-code>
					<div class="fw-semibold" data-surveyauth-core-i18n="survey_22"><?= $escape($returningHeading) ?></div>
					<div class="form-text" id="return-code-help" data-surveyauth-core-i18n="survey_24"><?= $escape($returnCodeHelp) ?></div>
					<label class="form-label mt-2" for="return-code" data-surveyauth-core-i18n="survey_118"><?= $escape($returnCodeLabel) ?></label>
					<input class="form-control form-control-sm" id="return-code" type="password" maxlength="15" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" aria-describedby="return-code-help">
				</div>
			<?php endif; ?>
			<button class="btn btn-primary mt-3" type="submit" disabled data-surveyauth-i18n="login.submit_label"><?= $escape($submitLabel) ?></button>
		</form>
	</main>
	<?= $moduleJavascript ?>
	<script>
		<?php require __DIR__ . '/../js/survey-login.js'; ?>
		initializeSurveyAuthLogin(document.getElementById('survey-auth-login'), <?= $jsObject ?>, <?= $mlmCatalogueJson ?>);
	</script>
</body>

</html>
