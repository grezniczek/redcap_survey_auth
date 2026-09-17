function initializeSurveyAuthMlmTranslations() {
    const $editor = $('#surveyauth-mlm-translations');
    const $textareas = $editor.find('.textarea-autosize');
    if (!$textareas.length || typeof $textareas.textareaAutoSize !== 'function') return;

    $textareas.on('focus', function() { $(this).trigger('input'); }).textareaAutoSize();
    $editor.find('[data-bs-toggle="tab"]').on('shown.bs.tab', function(event) {
        const target = event.target.getAttribute('data-bs-target') || event.target.getAttribute('href');
        if (typeof target !== 'string' || !target.startsWith('#')) return;
        $(target).find('.textarea-autosize').trigger('input');
    });
}
