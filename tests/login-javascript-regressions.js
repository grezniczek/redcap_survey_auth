const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../js/survey-login.js'), 'utf8');
function fixture(ajax, returnCode = null) {
    const button = {disabled: true};
    const username = {value: 'fixture'};
    const password = {value: 'synthetic-secret', focus() { this.focused = true; }};
    const returnCodeInput = returnCode === null ? null : {value: returnCode, focus() { this.focused = true; }};
    const error = {textContent: ''};
    let submit;
    const form = {dataset: {context: 'context', csrf: 'csrf'},
        querySelector(selector) { return {'button': button, '#username': username, '#password': password, '#return-code': returnCodeInput}[selector]; },
        addEventListener(event, callback) { assert.equal(event, 'submit'); submit = callback; }};
    const location = {href: 'https://survey.example/surveys/?s=fixture', origin: 'https://survey.example',
        assign(url) { this.redirect = url; }};
    const corePosts = [];
    const document = {
        getElementById() { return error; },
        createElement(tag) {
            if (tag === 'form') return {style: {}, appendChild(input) { this.input = input; }, submit() {
                corePosts.push({method: this.method, action: this.action, name: this.input.name, value: this.input.value, form: this});
            }};
            if (tag === 'input') return {};
            throw new Error('Unexpected DOM element: ' + tag);
        },
        body: {appendChild(element) { element.appended = true; }}
    };
    const context = vm.createContext({document, window: {location}, URL});
    vm.runInContext(source, context);
    context.initializeSurveyAuthLogin(form, {ajax});
    return {button, password, returnCodeInput, error, form, location, corePosts, submit() { return submit({preventDefault() {}}); }};
}
(async () => {
    let payload, transmitted, resolve, calls = 0;
    const f = fixture((action, data) => {
        calls++;
        assert.equal(action, 'survey-login');
        payload = data;
        transmitted = JSON.parse(JSON.stringify(data));
        return new Promise(r => { resolve = r; });
    });
    assert.equal(f.button.disabled, false);
    const returning = fixture((action, data) => {
        assert.equal(action, 'survey-login');
        assert.deepEqual(JSON.parse(JSON.stringify(data)), {
            context: 'context', csrf: 'csrf', username: 'fixture', password: 'synthetic-secret', return_code: 'RETURN-CODE'
        });
        assert.equal(JSON.stringify(data).includes('RETURN-CODE'), false,
            'The framework queue cannot serialize the return code after sending it.');
        return Promise.resolve({success: false, error: 'Invalid username, password, or return code.', error_key: 'login.return_code_invalid'});
    }, 'RETURN-CODE');
    await returning.submit();
    assert.equal(returning.returnCodeInput.value, '');
    assert.equal(returning.returnCodeInput.focused, true, 'Return-code failures focus the cleared return-code field.');
    const first = f.submit();
    assert.equal(f.button.disabled, true);
    assert.equal(f.password.value, '');
    assert.equal(transmitted.password, 'synthetic-secret');
    assert.equal(JSON.stringify(payload).includes('synthetic-secret'), false, 'Framework error logs cannot serialize the password again');
    await f.submit();
    assert.equal(calls, 1, 'Repeated submit cannot queue another credential attempt');
    resolve({success: false, error: '<unsafe-error>', csrf: 'new-csrf'});
    await first;
    assert.equal(f.form.dataset.csrf, 'new-csrf');
    assert.equal(f.error.textContent, '<unsafe-error>');
    assert.equal(f.error.hidden, false, 'A returned error is made visible.');
    assert.equal(f.password.focused, true);
    assert.equal(f.button.disabled, false);
    const good = fixture(async () => ({success: true, redirect: '/surveys/?s=fixture&__sa_flow=flow'}));
    await good.submit();
    assert.equal(good.location.redirect, 'https://survey.example/surveys/?s=fixture&__sa_flow=flow');
    const resume = fixture(async (action, data) => {
        assert.equal(action, 'survey-login');
        JSON.parse(JSON.stringify(data));
        return {success: true, redirect: '/surveys/?s=private', post_return_code: true};
    }, 'RETURN-CODE');
    await resume.submit();
    assert.equal(resume.location.redirect, undefined, 'A public return-code login does not use a GET redirect.');
    assert.deepEqual(resume.corePosts.map(({method, action, name, value}) => ({method, action, name, value})), [{
        method: 'post', action: 'https://survey.example/surveys/?s=private', name: '__code', value: 'RETURN-CODE'
    }], 'A validated public return code is posted exactly once to REDCap continuation.');
    assert.equal(resume.corePosts[0].form.input.value, '', 'The transient native return-code control is cleared after submission.');
    const bad = fixture(async () => ({success: true, redirect: 'https://elsewhere.example/'}));
    await bad.submit();
    assert.equal(bad.location.redirect, undefined);
    assert.match(bad.error.textContent, /reopen/);
    const failed = fixture(async () => { throw new Error('synthetic transport details'); });
    await failed.submit();
    assert.equal(failed.button.disabled, false);
    assert.equal(failed.error.textContent.includes('synthetic transport details'), false);

    const heading = {dataset: {}, textContent: '', getAttribute() { return 'login.heading'; }};
    const instruction = {dataset: {surveyauthHtml: 'true'}, innerHTML: '', getAttribute() { return 'login.instructions'; }};
    const surveyTitle = {textContent: ''};
    const surveyLogo = {setAttribute(name, value) { this[name] = value; }};
    const returningHeading = {textContent: '', getAttribute() { return 'survey_22'; }};
    const returnCodeLabel = {textContent: '', getAttribute() { return 'survey_118'; }};
    const returnCodeHelp = {textContent: '', getAttribute() { return 'survey_24'; }};
    const pageTitle = {textContent: ''};
    let changeLanguage;
    const languageButton = {dataset: {surveyauthLanguage: 'fr-FR'}, setAttribute(name, value) { this[name] = value; },
        addEventListener(event, callback) { assert.equal(event, 'click'); changeLanguage = callback; }};
    const languageError = {dataset: {}, textContent: ''};
    const languageSubmit = {disabled: true};
    const languageUsername = {value: ''};
    const languagePassword = {value: '', focus() {}};
    const languageForm = {dataset: {context: 'context', csrf: 'csrf'},
        querySelector(selector) { return {'button': languageSubmit, '#username': languageUsername, '#password': languagePassword}[selector]; },
        addEventListener() {}};
    const languageDocument = {
        documentElement: {},
        getElementById() { return languageError; },
        querySelectorAll(selector) {
            if (selector === '[data-surveyauth-i18n]') return [heading, instruction];
            if (selector === '[data-surveyauth-survey-title]') return [surveyTitle];
            if (selector === '[data-surveyauth-survey-logo]') return [surveyLogo];
            if (selector === '[data-surveyauth-core-i18n]') return [returningHeading, returnCodeLabel, returnCodeHelp];
            if (selector === '[data-surveyauth-language]') return [languageButton];
            return [];
        },
        querySelector(selector) { return selector === '#survey-auth-page-title' ? pageTitle : null; }
    };
    const remembered = [];
    const languageContext = vm.createContext({document: languageDocument,
        window: {location: {href: 'https://survey.example/', origin: 'https://survey.example/'}, setCookie(...args) { remembered.push(args); }}, URL});
    vm.runInContext(source, languageContext);
    languageContext.initializeSurveyAuthLogin(languageForm, {ajax: async () => ({success: false})}, {
        current: 'de-DE',
        languages: {
            'de-DE': {html_lang: 'de', rtl: false, survey_title: 'Deutsche Studie', survey_logo_alt: 'Logo der Studie', core_strings: {'survey_22': 'Zurückkehrend?', 'survey_118': 'Rückkehrcode', 'survey_24': 'Mit Rückkehrcode fortsetzen.'}, strings: {'login.heading': 'Anmelden', 'login.instructions': '<em>Bitte anmelden</em>'}},
            'fr-FR': {html_lang: 'fr', rtl: false, survey_title: 'Étude française', survey_logo_alt: 'Logo de l’étude', core_strings: {'survey_22': 'De retour ?', 'survey_118': 'Code de retour', 'survey_24': 'Reprenez avec votre code de retour.'}, strings: {'login.heading': 'Connexion', 'login.instructions': '<em>Veuillez vous connecter</em>'}}
        }
    });
    assert.equal(heading.textContent, 'Anmelden');
    assert.equal(instruction.innerHTML, '<em>Bitte anmelden</em>');
    assert.equal(surveyTitle.textContent, 'Deutsche Studie');
    assert.equal(surveyLogo.alt, 'Logo der Studie');
    assert.equal(returningHeading.textContent, 'Zurückkehrend?');
    assert.equal(returnCodeLabel.textContent, 'Rückkehrcode');
    assert.equal(returnCodeHelp.textContent, 'Mit Rückkehrcode fortsetzen.');
    assert.equal(pageTitle.textContent, 'Deutsche Studie — Anmelden');
    changeLanguage();
    assert.equal(heading.textContent, 'Connexion');
    assert.equal(surveyTitle.textContent, 'Étude française');
    assert.equal(surveyLogo.alt, 'Logo de l’étude');
    assert.equal(returningHeading.textContent, 'De retour ?');
    assert.equal(returnCodeLabel.textContent, 'Code de retour');
    assert.equal(pageTitle.textContent, 'Étude française — Connexion');
    assert.equal(languageDocument.documentElement.lang, 'fr');
    assert.equal(languageButton.className, 'btn btn-primary btn-sm');
    assert.deepEqual(remembered.at(-1), ['redcap-multilanguage-survey', 'fr-FR', 60]);
    console.log('Passed login JavaScript submission, retry, password cleanup, errors, and redirect regressions.');
})().catch(error => { console.error(error); process.exitCode = 1; });
