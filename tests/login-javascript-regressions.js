const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../js/survey-login.js'), 'utf8');
function fixture(ajax) {
    const button = {disabled: true};
    const username = {value: 'fixture'};
    const password = {value: 'synthetic-secret', focus() { this.focused = true; }};
    const error = {textContent: ''};
    let submit;
    const form = {dataset: {context: 'context', csrf: 'csrf'},
        querySelector(selector) { return {'button': button, '#username': username, '#password': password}[selector]; },
        addEventListener(event, callback) { assert.equal(event, 'submit'); submit = callback; }};
    const location = {href: 'https://survey.example/surveys/?s=fixture', origin: 'https://survey.example',
        assign(url) { this.redirect = url; }};
    const context = vm.createContext({document: {getElementById() { return error; }}, window: {location}, URL});
    vm.runInContext(source, context);
    context.initializeSurveyAuthLogin(form, {ajax});
    return {button, password, error, form, location, submit() { return submit({preventDefault() {}}); }};
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
    assert.equal(f.password.focused, true);
    assert.equal(f.button.disabled, false);
    const good = fixture(async () => ({success: true, redirect: '/surveys/?s=fixture&__sa_flow=flow'}));
    await good.submit();
    assert.equal(good.location.redirect, 'https://survey.example/surveys/?s=fixture&__sa_flow=flow');
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
            if (selector === '[data-surveyauth-language]') return [languageButton];
            return [];
        }
    };
    const remembered = [];
    const languageContext = vm.createContext({document: languageDocument,
        window: {location: {href: 'https://survey.example/', origin: 'https://survey.example/'}, setCookie(...args) { remembered.push(args); }}, URL});
    vm.runInContext(source, languageContext);
    languageContext.initializeSurveyAuthLogin(languageForm, {ajax: async () => ({success: false})}, {
        current: 'de-DE',
        languages: {
            'de-DE': {html_lang: 'de', rtl: false, strings: {'login.heading': 'Anmelden', 'login.instructions': '<em>Bitte anmelden</em>'}},
            'fr-FR': {html_lang: 'fr', rtl: false, strings: {'login.heading': 'Connexion', 'login.instructions': '<em>Veuillez vous connecter</em>'}}
        }
    });
    assert.equal(heading.textContent, 'Anmelden');
    assert.equal(instruction.innerHTML, '<em>Bitte anmelden</em>');
    changeLanguage();
    assert.equal(heading.textContent, 'Connexion');
    assert.equal(languageDocument.documentElement.lang, 'fr');
    assert.deepEqual(remembered.at(-1), ['redcap-multilanguage-survey', 'fr-FR', 60]);
    console.log('Passed login JavaScript submission, retry, password cleanup, errors, and redirect regressions.');
})().catch(error => { console.error(error); process.exitCode = 1; });
