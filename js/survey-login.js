function initializeSurveyAuthLogin(form, module, translations) {
    const button = form.querySelector('button');
    const username = form.querySelector('#username');
    const passwordInput = form.querySelector('#password');
    const error = document.getElementById('survey-auth-error');
    const languages = translations && typeof translations === 'object' && translations.languages &&
        typeof translations.languages === 'object' ? translations.languages : null;
    let currentLanguage = languages && typeof translations.current === 'string' ? translations.current : '';
    let pending = false;

    function stringFor(key) {
        const strings = languages && languages[currentLanguage] && languages[currentLanguage].strings;
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
        if (translated !== null) {
            if (error.dataset) error.dataset.surveyauthErrorKey = key;
            else if (typeof error.setAttribute === 'function') error.setAttribute('data-surveyauth-error-key', key);
            error.textContent = translated;
        } else {
            if (error.dataset) delete error.dataset.surveyauthErrorKey;
            else if (typeof error.removeAttribute === 'function') error.removeAttribute('data-surveyauth-error-key');
            error.textContent = fallback;
        }
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
        const errorKey = error.dataset ? error.dataset.surveyauthErrorKey :
            (typeof error.getAttribute === 'function' ? error.getAttribute('data-surveyauth-error-key') : null);
        if (errorKey) setError(errorKey, error.textContent);
        document.querySelectorAll('[data-surveyauth-language]').forEach(function(control) {
            control.setAttribute('aria-pressed', control.dataset.surveyauthLanguage === language ? 'true' : 'false');
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
        let password = passwordInput.value;
        passwordInput.value = '';
        // JSMO can log its payload on transport errors. Serialize credentials once,
        // without leaving them as properties of the object retained by its queue.
        const context = form.dataset.context;
        const csrf = form.dataset.csrf;
        const user = username.value;
        const payload = {toJSON() {
            const data = {context, csrf, username: user, password};
            password = '';
            return data;
        }};
        try {
            const result = await module.ajax('survey-login', payload);
            if (result && result.success === true && typeof result.redirect === 'string') {
                const target = new URL(result.redirect, window.location.href);
                if (target.origin !== window.location.origin) throw new Error('Invalid redirect');
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
            pending = false;
            button.disabled = false;
        }
        passwordInput.focus();
    });
}
