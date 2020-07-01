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
            var uinput = $('#' + prefix + '-username')
            var pinput = $('#' + prefix + '-password')
            var submit = $('#' + prefix + '-submit')
            var failmsg = $('#' + prefix + 'failmsg')
            var onChange = function() {
                var username = uinput.val();
                var pwd = pinput.val();
                var disabled = username.length == 0 || pwd.length == 0
                RUBSurveyAuth.disable(submit, disabled)
                failmsg.hide()
            }
            uinput.on('keypress', onChange)
            pinput.on('keypress', onChange)
            onChange()
        },
        submit: function(prefix) {
            // Find ui elements.
            var form = $('#' + prefix + '-form');
            var uinput = $('#' + prefix + '-username')
            var pinput = $('#' + prefix + '-password')
            var username = uinput.val();
            var pwd = pinput.val();
            if (username == '' || pwd == '') {
                return false;
            }
            form.submit()
        }
    }
}();