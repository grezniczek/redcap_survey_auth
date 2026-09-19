const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(require('node:path').join(__dirname, '../js/mlm-translations.js'), 'utf8');
let tabChanged;
let autosizeCalls = 0;
let resized = 0;
const textareas = {
    length: 1,
    on(event) { assert.equal(event, 'focus'); return this; },
    textareaAutoSize() { autosizeCalls++; return this; }
};
const pane = {find(selector) {
    assert.equal(selector, '.textarea-autosize');
    return {trigger(event) { assert.equal(event, 'input'); resized++; }};
}};
const tabs = {on(event, callback) {
    assert.equal(event, 'shown.bs.tab');
    tabChanged = callback;
    return this;
}};
const editor = {find(selector) {
    if (selector === '.textarea-autosize') return textareas;
    if (selector === '[data-bs-toggle="tab"]') return tabs;
    throw new Error('Unexpected editor selector: ' + selector);
}};
function $(selector) {
    if (selector === '#surveyauth-mlm-translations') return editor;
    if (selector === '#selected-language') return pane;
    throw new Error('Unexpected selector: ' + selector);
}

const context = vm.createContext({$, console});
vm.runInContext(source, context);
context.initializeSurveyAuthMlmTranslations();
assert.equal(autosizeCalls, 1, 'The REDCap textareaAutosize plugin initializes every editor field.');
tabChanged({target: {getAttribute(attribute) { return attribute === 'href' ? '#selected-language' : null; }}});
assert.equal(resized, 1, 'A newly displayed language tab resizes its textareas.');
console.log('Passed MLM translation editor textarea autosize and language-tab regressions.');
