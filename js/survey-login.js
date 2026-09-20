function initializeSurveyAuthLogin(form, module, translations) {
    const button = form.querySelector('button');
    const username = form.querySelector('#username');
    const passwordInput = form.querySelector('#password');
    const returnCodeInput = form.querySelector('#return-code');
    const error = document.getElementById('survey-auth-error');
    const languages = translations && typeof translations === 'object' && translations.languages &&
        typeof translations.languages === 'object' ? translations.languages : null;
    let currentLanguage = languages && typeof translations.current === 'string' ? translations.current : '';
    let pending = false;

    function stringFor(key) {
        const strings = languages && languages[currentLanguage] && languages[currentLanguage].strings;
        return strings && typeof strings[key] === 'string' ? strings[key] : null;
    }

    function coreStringFor(key) {
        const strings = languages && languages[currentLanguage] && languages[currentLanguage].core_strings;
        return strings && typeof strings[key] === 'string' ? strings[key] : null;
    }

    function rememberLanguage(language) {
        if (typeof window.setCookie === 'function') {
            window.setCookie('redcap-multilanguage-survey', language, 60);
            return;
        }
        const expiry = new Date();
        expiry.setDate(expiry.getDate() + 60);
        document.cookie = 'redcap-multilanguage-survey=' + encodeURIComponent(language) +
            '; expires=' + expiry.toUTCString() + '; path=/; SameSite=Lax';
    }

    function setError(key, fallback) {
        const translated = typeof key === 'string' ? stringFor(key) : null;
        const message = translated !== null ? translated : fallback;
        if (translated !== null) {
            if (error.dataset) error.dataset.surveyauthErrorKey = key;
            else if (typeof error.setAttribute === 'function') error.setAttribute('data-surveyauth-error-key', key);
        } else {
            if (error.dataset) delete error.dataset.surveyauthErrorKey;
            else if (typeof error.removeAttribute === 'function') error.removeAttribute('data-surveyauth-error-key');
        }
        error.textContent = message;
        error.hidden = message === '';
    }

    function setLanguage(language, persist) {
        if (!languages || !languages[language]) return;
        currentLanguage = language;
        const selected = languages[language];
        document.documentElement.lang = selected.html_lang || 'en';
        document.documentElement.dir = selected.rtl ? 'rtl' : 'ltr';
        document.querySelectorAll('[data-surveyauth-i18n]').forEach(function(element) {
            const value = stringFor(element.getAttribute('data-surveyauth-i18n'));
            if (value === null) return;
            // The configurable instruction field has always allowed intentional HTML.
            // Every other participant-facing string stays text-only.
            if (element.dataset.surveyauthHtml === 'true') element.innerHTML = value;
            else element.textContent = value;
        });
        document.querySelectorAll('[data-surveyauth-core-i18n]').forEach(function(element) {
            const value = coreStringFor(element.getAttribute('data-surveyauth-core-i18n'));
            if (value !== null) element.textContent = value;
        });
        if (typeof selected.survey_title === 'string') {
            document.querySelectorAll('[data-surveyauth-survey-title]').forEach(function(element) {
                element.textContent = selected.survey_title;
            });
            const pageTitle = typeof document.querySelector === 'function' ?
                document.querySelector('#survey-auth-page-title') : null;
            if (pageTitle) {
                const heading = stringFor('login.heading') || pageTitle.textContent;
                pageTitle.textContent = selected.survey_title === '' ? heading : selected.survey_title + ' — ' + heading;
            }
        }
        if (typeof selected.survey_logo_alt === 'string') {
            document.querySelectorAll('[data-surveyauth-survey-logo]').forEach(function(element) {
                element.setAttribute('alt', selected.survey_logo_alt);
            });
        }
        const errorKey = error.dataset ? error.dataset.surveyauthErrorKey :
            (typeof error.getAttribute === 'function' ? error.getAttribute('data-surveyauth-error-key') : null);
        if (errorKey) setError(errorKey, error.textContent);
        document.querySelectorAll('[data-surveyauth-language]').forEach(function(control) {
            const selected = control.dataset.surveyauthLanguage === language;
            control.setAttribute('aria-pressed', selected ? 'true' : 'false');
            control.className = 'btn ' + (selected ? 'btn-primary' : 'btn-outline-secondary') + ' btn-sm';
        });
        if (persist) rememberLanguage(language);
    }

    if (languages && languages[currentLanguage]) {
        setLanguage(currentLanguage, true);
        document.querySelectorAll('[data-surveyauth-language]').forEach(function(control) {
            control.addEventListener('click', function() { setLanguage(control.dataset.surveyauthLanguage, true); });
        });
    }
    button.disabled = false;
    form.addEventListener('submit', async function(event) {
        event.preventDefault();
        if (pending) return;
        pending = true;
        button.disabled = true;
        error.textContent = '';
        error.hidden = true;
        let password = passwordInput.value;
        passwordInput.value = '';
        let returnCode = returnCodeInput ? returnCodeInput.value : '';
        if (returnCodeInput) returnCodeInput.value = '';
        // JSMO can log its payload on transport errors. Serialize credentials once,
        // without leaving credentials or a response return code as properties of
        // the object retained by its queue.
        const context = form.dataset.context;
        const csrf = form.dataset.csrf;
        const user = username.value;
        let coreReturnCode = '';
        const payload = {toJSON() {
            const data = {context, csrf, username: user, password};
            password = '';
            if (returnCode !== '') {
                data.return_code = returnCode;
                coreReturnCode = returnCode;
            }
            returnCode = '';
            return data;
        }};
        let result;
        try {
            result = await module.ajax('survey-login', payload);
            if (result && result.success === true && typeof result.redirect === 'string') {
                const target = new URL(result.redirect, window.location.href);
                if (target.origin !== window.location.origin) throw new Error('Invalid redirect');
                if (result.post_return_code === true) {
                    if (coreReturnCode === '') throw new Error('Missing return code');
                    // REDCap's continuation route accepts the code only in POST.
                    // This is reached exclusively after the module has validated a
                    // public-survey return code and created its response grant.
                    const continuation = document.createElement('form');
                    continuation.method = 'post';
                    continuation.action = target.href;
                    continuation.style.display = 'none';
                    const code = document.createElement('input');
                    code.type = 'hidden';
                    code.name = '__code';
                    code.value = coreReturnCode;
                    continuation.appendChild(code);
                    document.body.appendChild(continuation);
                    continuation.submit();
                    code.value = '';
                    coreReturnCode = '';
                    return;
                }
                window.location.assign(target.href);
                return;
            }
            if (result && typeof result.csrf === 'string') form.dataset.csrf = result.csrf;
            setError(result && result.error_key, result && typeof result.error === 'string' ? result.error :
                'Login could not be completed. Please reopen this page and try again.');
        } catch (_) {
            setError('login.ajax_error', 'Login could not be completed. Please reopen this page and try again.');
        } finally {
            password = '';
            returnCode = '';
            coreReturnCode = '';
            pending = false;
            button.disabled = false;
        }
        if (result && result.error_key === 'login.return_code_invalid' && returnCodeInput) returnCodeInput.focus();
        else passwordInput.focus();
    });
}
