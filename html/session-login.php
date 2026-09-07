<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $surveyTitle !== '' ? $surveyTitle.' — ' : '' ?>Survey login</title>
<style>
body { font: 1rem/1.5 system-ui, sans-serif; background: #f4f5f7; color: #222; margin: 0; }
main { max-width: 28rem; margin: 8vh auto; padding: 2rem; background: white; border-radius: .5rem; }
.survey-logo { display: block; max-width: 100%; height: auto; margin: 0 auto 1.5rem; }
h1 { overflow-wrap: anywhere; }
label { display: block; margin-top: 1rem; }
input { box-sizing: border-box; width: 100%; padding: .65rem; font: inherit; }
button { margin-top: 1.5rem; padding: .7rem 1.5rem; font: inherit; cursor: pointer; }
[role=alert] { color: #a32020; }
</style>
<main>
<?php if ($logoSource !== ''): ?><img class="survey-logo" src="<?= $logoSource ?>" alt="Survey logo"><?php endif; ?>
<?php if ($surveyTitle !== ''): ?><h1><?= $surveyTitle ?></h1><h2>Survey login</h2><?php else: ?>
<h1>Survey login</h1>
<?php endif; ?>
<div><?= $instructions ?></div>
<?php if ($error !== ''): ?><p role="alert"><?= $error ?></p><?php endif; ?>
<form method="post" action="<?= $action ?>">
<input type="hidden" name="context" value="<?= $escape($id) ?>">
<input type="hidden" name="csrf" value="<?= $csrf ?>">
<input type="hidden" name="redcap_csrf_token" value="<?= $frameworkCsrf ?>">
<label for="username"><?= $usernameLabel ?></label>
<input id="username" name="username" autocomplete="username" required autofocus>
<label for="password"><?= $passwordLabel ?></label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit"><?= $submitLabel ?></button>
</form>
</main>
</html>
