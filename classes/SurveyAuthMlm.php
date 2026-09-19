<?php namespace DE\RUB\SurveyAuthExternalModule;

/**
 * Survey-only companion for the core Multi-Language Management feature.
 *
 * This deliberately owns only Survey Auth's participant-facing strings.  It
 * does not register, write, or otherwise extend MLM's own translation data.
 */
trait SurveyAuthMlm
{
    /**
     * @return array<string, array{label:string,value:string,html:bool}>
     */
    private function surveyMlmLoginItems(SurveyAuthSettings $settings): array
    {
        return [
            'login.heading' => ['label' => 'Login heading', 'value' => 'Survey login', 'html' => false],
            'login.instructions' => ['label' => 'Instructions above the login fields', 'value' => (string)$settings->text, 'html' => true],
            'login.username_label' => ['label' => 'Username label', 'value' => (string)$settings->usernameLabel, 'html' => false],
            'login.password_label' => ['label' => 'Password label', 'value' => (string)$settings->passwordLabel, 'html' => false],
            'login.submit_label' => ['label' => 'Submit button', 'value' => (string)$settings->submitLabel, 'html' => false],
            'login.failure' => ['label' => 'Invalid-login message', 'value' => (string)$settings->failMsg, 'html' => false],
            'login.lockout' => ['label' => 'Lockout message', 'value' => (string)$settings->lockoutMsg, 'html' => false],
            'login.technical_error' => ['label' => 'Technical-error message', 'value' => (string)$settings->errorMsg, 'html' => false],
            'login.cookie_required' => ['label' => 'Cookies-required message', 'value' => 'A survey session is required. Please enable cookies.', 'html' => false],
            'login.expired' => ['label' => 'Expired-login message', 'value' => 'Login expired or invalid. Please reopen the survey.', 'html' => false],
            'login.ajax_error' => ['label' => 'Browser communication error', 'value' => 'Login could not be completed. Please reopen this page and try again.', 'html' => false],
            'login.javascript_required' => ['label' => 'JavaScript-required message', 'value' => 'JavaScript is required to sign in. Please enable JavaScript and reopen this page.', 'html' => false],
            'login.start_over' => ['label' => 'Start-over reauthentication message', 'value' => 'Sign in again before starting over so authentication values can be restored. Then choose Start over again.', 'html' => false],
            'login.unsaved_submission' => ['label' => 'Unsaved-submission message', 'value' => 'Your submission was not saved. Sign in to reopen the survey. Unsaved answers are not restored automatically; use your browser Back button to recover them if available. Uploaded files may need to be selected again.', 'html' => false],
        ];
    }

    private function surveyMlmHasActionTag($annotation): bool
    {
        if (!is_string($annotation)) return false;
        return preg_match(
            '/(?<![A-Za-z0-9_@-])@'.preg_quote(SurveyAuthExternalModule::$ACTIONTAG, '/').'(?![A-Za-z0-9_-])/',
            $annotation
        ) === 1;
    }

    /** @return array<string, true> */
    private function surveyMlmProtectedSurveyForms(int $projectId): array
    {
        try {
            $project = new \Project($projectId);
            $metadata = $project->getMetadata();
            $forms = $project->getForms();
            $protected = [];
            foreach ($forms as $formName => $fi) {
                if (!isset($fi['survey_id']) || intval($fi['survey_id']) < 1) continue;
                foreach ($fi['fields'] as $fieldName => $_) {
                    if ($this->surveyMlmHasActionTag($metadata[$fieldName]['misc'] ?? null)) {
                        $protected[$formName] = true;
                    }
                }
            }
            return $protected;
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** @return array<string, array{display:string,html_lang:string,rtl:bool,forms:array<string, true>}> */
    private function surveyMlmProjectLanguages(int $projectId): array
    {
        if (!class_exists('\\MultiLanguageManagement\\MultiLanguage')) return [];
        $mlm = '\\MultiLanguageManagement\\MultiLanguage';
        try {
            if (!$mlm::isActive($projectId)) return [];
            $settings = $mlm::getProjectSettings($projectId);
            if (!is_array($settings['langs'] ?? null)) return [];
            $languages = [];
            foreach ($settings['langs'] as $languageId => $language) {
                if (!is_string($languageId) || !is_array($language) || empty($language['active'])) continue;
                $languages[$languageId] = [
                    'display' => (string)($language['display'] ?? $languageId),
                    'html_lang' => (string)($language['htmlLang'] ?? $mlm::formatLangIdForHtmlTag($languageId)),
                    'rtl' => !empty($language['rtl']),
                    'forms' => [],
                ];
            }
            if (!$languages) return [];
            $sorted = $mlm::sortLanguages($settings['langs'], array_keys($languages));
            return array_replace(array_flip($sorted), $languages);
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Gets the project-active MLM languages usable on every supplied protected
     * survey. The login selector must remain instrument-specific, unlike the
     * editor's project-level availability condition.
     *
     * @param array<string, true>|null $forms
     * @return array<string, array{display:string,html_lang:string,rtl:bool,forms:array<string, true>}>
     */
    private function surveyMlmLanguages(int $projectId, ?array $forms = null): array
    {
        $forms ??= $this->surveyMlmProtectedSurveyForms($projectId);
        if (!$forms) return [];
        $languages = $this->surveyMlmProjectLanguages($projectId);
        if (!$languages) return [];
        $mlm = '\\MultiLanguageManagement\\MultiLanguage';
        try {
            $settings = $mlm::getProjectSettings($projectId);
            foreach ($languages as $languageId => &$language) {
                foreach ($forms as $form => $_) {
                    if (!empty($settings['langs'][$languageId]['dd']['survey-active'][$form])) {
                        $language['forms'][$form] = true;
                    }
                }
                if (!$language['forms']) unset($languages[$languageId]);
            }
            unset($language);
            return $languages;
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * @param array<string, true> $allowedKeys
     * @return array<string, array<string, array{value:string,source_hash:string}>>
     */
    private function surveyMlmReadTranslations(int $projectId, array $allowedKeys): array
    {
        $raw = $this->framework->getProjectSetting(self::MLM_TRANSLATIONS_SETTING, $projectId);
        if (!is_string($raw) || $raw === '' || strlen($raw) > self::MLM_TRANSLATIONS_MAX_BYTES) return [];
        try {
            $stored = json_decode($raw, true, 128, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            return [];
        }
        if (!is_array($stored) || ($stored['version'] ?? null) !== self::MLM_TRANSLATIONS_VERSION ||
            !is_array($stored['languages'] ?? null)) return [];
        $result = [];
        foreach ($stored['languages'] as $languageId => $strings) {
            if (!is_string($languageId) || !is_array($strings)) continue;
            foreach ($strings as $key => $entry) {
                if (!isset($allowedKeys[$key]) || !is_array($entry) || !is_string($entry['value'] ?? null) ||
                    !is_string($entry['source_hash'] ?? null) || strlen($entry['value']) > 32768 ||
                    !preg_match('/^[a-f0-9]{64}$/', $entry['source_hash'])) continue;
                $result[$languageId][$key] = [
                    'value' => $entry['value'],
                    'source_hash' => $entry['source_hash'],
                ];
            }
        }
        return $result;
    }

    /** @param array<string, array<string, array{value:string,source_hash:string}>> $translations */
    private function surveyMlmResolveString(array $translations, string $languageId, string $fallbackLanguageId,
        string $key, string $reference): string
    {
        foreach (array_unique([$languageId, $fallbackLanguageId]) as $candidate) {
            $value = $translations[$candidate][$key]['value'] ?? null;
            if (is_string($value) && trim($value) !== '') return $value;
        }
        return $reference;
    }

    /** Preserve REDCap-supported formatting while removing active or unsafe markup. */
    private function surveyMlmSanitizeItem(array $item, string $value): string
    {
        return $item['html'] ? \filter_tags($value) : $value;
    }

    private function surveyMlmEncodeTranslations(array $translations): string
    {
        $encoded = json_encode([
            'version' => self::MLM_TRANSLATIONS_VERSION,
            'languages' => $translations,
        ], JSON_THROW_ON_ERROR);
        if (strlen($encoded) > self::MLM_TRANSLATIONS_MAX_BYTES) {
            throw new \LengthException('Survey Auth translations exceed the storage limit.');
        }
        return $encoded;
    }

    private function surveyMlmErrorKey(string $error, SurveyAuthSettings $settings): ?string
    {
        return match ($error) {
            $settings->failMsg => 'login.failure',
            $settings->lockoutMsg => 'login.lockout',
            $settings->errorMsg => 'login.technical_error',
            default => null,
        };
    }

    /**
     * @return array{enabled:bool,current:string,html_lang:string,rtl:bool,strings:array<string,string>,languages:array<string, array<string,mixed>>}
     */
    private function surveyMlmLoginPresentation(array $scope, SurveyAuthSettings $settings, string $surveyTitle = ''): array
    {
        $items = $this->surveyMlmLoginItems($settings);
        $strings = array_map(fn($item) => $this->surveyMlmSanitizeItem($item, $item['value']), $items);
        $default = [
            'enabled' => false,
            'current' => '',
            'html_lang' => 'en',
            'rtl' => false,
            'strings' => $strings,
            'languages' => [],
        ];
        $projectId = (int)($scope['project_id'] ?? 0);
        $form = $scope['form_name'] ?? null;
        if (!$projectId || !is_string($form) || !class_exists('\\MultiLanguageManagement\\MultiLanguage')) return $default;

        $languages = $this->surveyMlmLanguages($projectId, [$form => true]);
        if (!$languages) return $default;
        $mlm = '\\MultiLanguageManagement\\MultiLanguage';
        try {
            $context = \REDCap\Context::Builder()->is_survey()
                ->project_id($projectId)->survey_id($scope['survey_id'] ?? null)
                ->event_id($scope['event_id'] ?? null)->instrument($form)
                ->record($scope['record'] ?? null)->response_id($scope['response_id'] ?? null)
                ->instance($scope['instance'] ?? null)->Build();
            $current = $mlm::getCurrentLanguage($context);
            if (!is_string($current) || !isset($languages[$current])) $current = array_key_first($languages);
            $mlmSettings = $mlm::getProjectSettings($projectId);
            $fallback = is_string($mlmSettings['fallbackLang'] ?? null) ? $mlmSettings['fallbackLang'] : '';
            if (!isset($languages[$fallback])) $fallback = '';
        } catch (\Throwable $e) {
            return $default;
        }
        $allowedKeys = array_fill_keys(array_keys($items), true);
        $translations = $this->surveyMlmReadTranslations($projectId, $allowedKeys);
        $catalogue = [];
        foreach ($languages as $languageId => $language) {
            $resolved = [];
            foreach ($items as $key => $item) {
                $resolved[$key] = $this->surveyMlmSanitizeItem($item,
                    $this->surveyMlmResolveString($translations, $languageId, $fallback, $key, $item['value']));
            }
            $translatedSurveyTitle = $surveyTitle;
            $translatedLogoAlt = 'Survey logo';
            try {
                $translationContext = \REDCap\Context::Builder($context)->lang_id($languageId)->Build();
                if ($surveyTitle !== '') {
                    $title = $mlm::getDDTranslation($translationContext, 'survey-title', $form);
                    if (is_string($title) && strip_tags($title) !== '') $translatedSurveyTitle = strip_tags($title);
                }
                $logoAlt = $mlm::getDDTranslation($translationContext, 'survey-logo_alt_text', $form);
                if (is_string($logoAlt) && trim(strip_tags($logoAlt)) !== '') $translatedLogoAlt = strip_tags($logoAlt);
            } catch (\Throwable $e) {
                // The login continues safely with the reference title and logo description.
            }
            $catalogue[$languageId] = [
                'display' => $language['display'],
                'html_lang' => $language['html_lang'],
                'rtl' => $language['rtl'],
                'survey_title' => $translatedSurveyTitle,
                'survey_logo_alt' => $translatedLogoAlt,
                'strings' => $resolved,
            ];
        }
        return [
            'enabled' => true,
            'current' => $current,
            'html_lang' => $catalogue[$current]['html_lang'],
            'rtl' => $catalogue[$current]['rtl'],
            'strings' => $catalogue[$current]['strings'],
            'languages' => $catalogue,
        ];
    }

    /** Project-link condition: protected survey plus active MLM and an active project language. */
    private function surveyMlmTranslationEditorAvailable(int $projectId): bool
    {
        return (bool)$this->surveyMlmProtectedSurveyForms($projectId) &&
            (bool)$this->surveyMlmProjectLanguages($projectId);
    }

    public function renderMlmLoginTranslationsPage(): void
    {
        $projectId = (int)$this->framework->getProjectId();
        $escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $rights = defined('USERID') ? (\REDCap::getUserRights(USERID)[USERID] ?? []) : [];
        if (!$projectId || empty($rights['design'])) {
            http_response_code(403);
            print '<div class="alert alert-danger">Design rights are required to edit Survey Auth translations.</div>';
            return;
        }
        if (!$this->surveyMlmTranslationEditorAvailable($projectId)) {
            http_response_code(404);
            print '<div class="alert alert-warning">A protected survey and an active Multi-Language Management language are required.</div>';
            return;
        }
        $languages = $this->surveyMlmProjectLanguages($projectId);
        $protectedForms = $this->surveyMlmProtectedSurveyForms($projectId);
        $settings = new SurveyAuthSettings($this, $projectId);
        $items = $this->surveyMlmLoginItems($settings);
        $allowedKeys = array_fill_keys(array_keys($items), true);
        $translations = $this->surveyMlmReadTranslations($projectId, $allowedKeys);
        $notice = '';
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $submitted = $_POST['surveyauth_mlm_translation'] ?? [];
            if (!is_array($submitted)) $submitted = [];
            $saved = [];
            foreach ($languages as $languageId => $_) {
                $languageValues = $submitted[$languageId] ?? [];
                if (!is_array($languageValues)) continue;
                foreach ($items as $key => $item) {
                    $value = $languageValues[$key] ?? '';
                    if (!is_string($value) || trim($value) === '') continue;
                    $limit = $item['html'] ? 32768 : 4096;
                    if (strlen($value) > $limit) continue;
                    $saved[$languageId][$key] = [
                        'value' => $value,
                        'source_hash' => hash('sha256', $item['value']),
                    ];
                }
            }
            try {
                $encoded = $this->surveyMlmEncodeTranslations($saved);
                $this->framework->setProjectSetting(self::MLM_TRANSLATIONS_SETTING, $encoded, $projectId);
                $translations = $saved;
                $notice = '<div class="alert alert-success">Survey Auth login translations saved.</div>';
            } catch (\LengthException $e) {
                http_response_code(422);
                $notice = '<div class="alert alert-danger">Translations are too large to save.</div>';
            } catch (\Throwable $e) {
                http_response_code(500);
                $notice = '<div class="alert alert-danger">Translations could not be saved.</div>';
            }
        }
        $mlmSetupCss = defined('APP_PATH_CSS') ? APP_PATH_CSS.'multilanguage-setup.css' : '';
        $mlmBundleJavascript = defined('APP_PATH_JS') ? APP_PATH_JS.'Libraries/bundle-multilanguage.js' : '';
        ?>
        <?php if ($mlmSetupCss !== ''): ?><link rel="stylesheet" href="<?= $escape($mlmSetupCss) ?>"><?php endif; ?>
        <style>
            .surveyauth-mlm-editor-sticky {
                position: sticky;
                top: 0;
                z-index: 1020;
                padding: .5rem 0 1.25rem;
                background: var(--bs-body-bg, #fff);
            }
            .surveyauth-mlm-editor-sticky .projhdr { margin-top: 0; }
        </style>
        <div style="max-width: 950px">
            <form id="surveyauth-mlm-translations" method="post">
                <input type="hidden" name="redcap_csrf_token" value="<?= $escape($this->framework->getCSRFToken()) ?>">
                <div class="surveyauth-mlm-editor-sticky">
                    <div class="projhdr"><i class="fas fa-language"></i> Survey Auth login translations</div>
                    <p class="text-muted mb-2">Provide the text shown on Survey Auth login pages for each active Multi-Language Management language.</p>
                    <?= $notice ?>
                    <button class="btn btn-sm btn-primary mb-2" type="submit"><i class="fas fa-save me-1"></i> Save translations</button>
                    <div class="mlm-sub-category-nav nav d-block">
                        <ul class="nav nav-tabs" role="tablist">
                            <?php $first = true; foreach ($languages as $languageId => $language): ?>
                            <li class="nav-item" role="presentation"><a class="nav-link mlm-sub-category-link<?= $first ? ' active' : '' ?>" data-bs-toggle="tab" href="#surveyauth-mlm-<?= $escape($languageId) ?>" role="tab" aria-selected="<?= $first ? 'true' : 'false' ?>"><?= $escape($language['display']) ?></a></li>
                            <?php $first = false; endforeach; ?>
                        </ul>
                    </div>
                </div>
                <div class="tab-content">
                    <?php $first = true; foreach ($languages as $languageId => $language): ?>
                    <div class="tab-pane fade<?= $first ? ' show active' : '' ?>" id="surveyauth-mlm-<?= $escape($languageId) ?>" role="tabpanel">
                        <?php foreach ($items as $key => $item):
                            $entry = $translations[$languageId][$key] ?? null;
                            $stale = is_array($entry) && !hash_equals(hash('sha256', $item['value']), $entry['source_hash']);
                            $value = is_array($entry) ? $entry['value'] : '';
                        ?>
                        <div class="mb-3">
                            <label class="form-label fw-bold" for="surveyauth-mlm-<?= $escape($languageId.'-'.$key) ?>"><?= $escape($item['label']) ?><?= $stale ? ' <span class="badge bg-warning text-dark">Source changed</span>' : '' ?></label>
                            <div class="ms-2">

                                <textarea class="form-control form-control-sm textarea-autosize" rows="1" id="surveyauth-mlm-<?= $escape($languageId.'-'.$key) ?>" name="surveyauth_mlm_translation[<?= $escape($languageId) ?>][<?= $escape($key) ?>]" maxlength="<?= $item['html'] ? '32768' : '4096' ?>"><?= $escape($value) ?></textarea>
                                <div class="form-text">Reference: <?= $escape($item['value']) ?></div>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    <?php $first = false; endforeach; ?>
                </div>
            </form>
        </div>
        <?php if ($mlmBundleJavascript !== ''): ?><script src="<?= $escape($mlmBundleJavascript) ?>"></script><?php endif; ?>
        <script><?php require __DIR__.'/../js/mlm-translations.js'; ?>
        initializeSurveyAuthMlmTranslations();
        </script>
        <?php
    }
}
