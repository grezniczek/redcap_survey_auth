var RUBSurveyAuth = function() {
    return {
        disable: function(btn, disabled) {
            if (disabled) {
                btn.prop('disabled', true)
                btn.addClass('ui-button-disabled')
                btn.addClass('ui-state-disabled')
            }
            else {
                btn.prop('disabled', false)
                btn.removeClass('ui-button-disabled')
                btn.removeClass('ui-state-disabled')
            }
        },
        setup: function(prefix) {
            // Find ui elements.
            const uinput = $('#' + prefix + '-username')
            const pinput = $('#' + prefix + '-password')
            const submit = $('#' + prefix + '-submit')
            const failmsg = $('#' + prefix + 'failmsg')
            const onblur = function() {
                let username = uinput.val();
                let pwd = pinput.val();
                let disabled = username.length == 0 || pwd.length == 0
                RUBSurveyAuth.disable(submit, disabled)
                failmsg.hide()
                return !disabled
            }
            uinput.blur(onblur)
            pinput.blur(onblur)
            pinput.keydown(function(e) {
                if (e.which == 9) {
                    if (onblur()) {
                        submit.focus()
                    }
                    e.preventDefault()
                }
            })
            onblur()
        },
        submit: function(prefix) {
            // Find ui elements.
            const form = $('#' + prefix + '-form');
            const uinput = $('#' + prefix + '-username')
            const pinput = $('#' + prefix + '-password')
            const username = uinput.val();
            const pwd = pinput.val();
            if (username == '' || pwd == '') {
                return false;
            }
            form.submit()
        }
    }
}();