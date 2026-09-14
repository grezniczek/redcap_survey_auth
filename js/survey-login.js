function initializeSurveyAuthLogin(form, module) {
    const button = form.querySelector('button');
    const username = form.querySelector('#username');
    const passwordInput = form.querySelector('#password');
    const error = document.getElementById('survey-auth-error');
    let pending = false;
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
            error.textContent = result && typeof result.error === 'string' ? result.error :
                'Login could not be completed. Please reopen this page and try again.';
        } catch (_) {
            error.textContent = 'Login could not be completed. Please reopen this page and try again.';
        } finally {
            password = '';
            pending = false;
            button.disabled = false;
        }
        passwordInput.focus();
    });
}
