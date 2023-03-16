var RUBSurveyAuth = function() {
    return {
        disable: function(btn, disabled) {
            if (disabled) {
                btn.prop('disabled', true);
                btn.addClass('ui-button-disabled');
                btn.addClass('ui-state-disabled');
            }
            else {
                btn.prop('disabled', false);
                btn.removeClass('ui-button-disabled');
                btn.removeClass('ui-state-disabled');
            }
        },
        setup: function(prefix) {
            // Find ui elements.
            var uinput = $('#' + prefix + '-username');
            var pinput = $('#' + prefix + '-password');
            var submit = $('#' + prefix + '-submit');
            var failmsg = $('#' + prefix + 'failmsg');
            var onChange = function() {
                var username = uinput.val();
                var pwd = pinput.val();
                var disabled = username.length == 0 || pwd.length == 0;
                RUBSurveyAuth.disable(submit, disabled);
                failmsg.hide();
            }
            var onEnter = function() {
                if (submit.prop('disabled')) {
                    var username = uinput.val();
                    var pwd = pinput.val();
                    if (username != '' && pwd != '') {
                        RUBSurveyAuth.disable(submit, false);
                    }
                }
            }
            submit.parent().on('mouseenter', onEnter);
            uinput.on('keypress paste blur', onChange);
            pinput.on('keypress paste blur', onChange);
            onChange()
        },
        submit: function(prefix) {
            // Find ui elements.
            var form = $('#' + prefix + '-form');
            var uinput = $('#' + prefix + '-username');
            var pinput = $('#' + prefix + '-password');
            var username = uinput.val();
            var pwd = pinput.val();
            if (username == '' || pwd == '') {
                return false;
            }
            form.trigger('submit');
        }
    }
}();