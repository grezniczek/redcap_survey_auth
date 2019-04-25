var RUBSurveyAuth = function() {
    return {
        disable(btn, disabled) {
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
            const uinput = $(`#${prefix}-username`)
            const pinput = $(`#${prefix}-password`)
            const submit = $(`#${prefix}-submit`)
            const failmsg = $(`#${prefix}-failmsg`)
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
        verify: function(prefix) {
            // Find ui elements.
            const form = $(`#${prefix}-form`);
            const uinput = $(`#${prefix}-username`)
            const pinput = $(`#${prefix}-password`)
            const submit = $(`#${prefix}-submit`)
            const failmsg = $(`#${prefix}-failmsg`)
            const submitNormal = $(`#${prefix}-submit-normal-tpl`).html()
            const submitBusy =  $(`#${prefix}-submit-busy-tpl`).html()

            const username = uinput.val();
            const pwd = pinput.val();
            if (username == '' || pwd == '') {
                failmsg.show();
                return false;
            }

            const queryUrl = form.attr('data-queryurl')
            const debug = form.attr('data-debug') == "1"
            console.log("Verifying credentials ...")

            // Update UI while querying server.
            failmsg.hide()
            uinput.prop('disabled', true)
            pinput.prop('disabled', true)
            RUBSurveyAuth.disable(submit, true)
            submit.html(submitBusy);

            // Query the surver
            $.ajax({
                url: queryUrl,
                type: 'POST',
                data: JSON.stringify({ 
                    username: username, 
                    password: pwd,
                    blob: form.attr('data-blob'),
                }),
                dataType: 'json'
            })
            .done(function(data, textStatus, jqXHR) {
                if (debug) {
                    console.log('Successfully executed SurveyAuth server request:')
                    console.log(data)
                }
                if (data.success) {
                    if (debug) console.log(`Redirecting to ${data.target}`)
                    document.location.href = data.target
                }
                else {
                    failmsg.html(data.error)
                    failmsg.show()
                    if (data.lockout != undefined) {
                        window.setTimeout(function() {
                            submit.html(submitNormal);
                        })
                        window.setTimeout(function() {
                            failmsg.hide()
                            uinput.prop('disabled', false)
                            pinput.prop('disabled', false)
                            RUBSurveyAuth.disable(submit, false)
                            uinput.focus()
                        }, data.lockout)
                    }
                    else {
                        uinput.prop('disabled', false)
                        pinput.prop('disabled', false)
                        RUBSurveyAuth.disable(submit, false)
                        setTimeout(function() {
                            submit.html(submitNormal);
                            uinput.focus()
                        })
                    }
                }
            })
            .fail(function(jqXHR, textStatus, errorThrown) {
                failmsg.html(errorThrown)
                failmsg.show()
                uinput.prop('disabled', false)
                pinput.prop('disabled', false)
                RUBSurveyAuth.disable(submit, false)
                setTimeout(function() {
                    submit.html(submitNormal);
                    uinput.focus()
                })
                if (debug) {
                    console.log(`SurveyAuth server request failed:`)
                    console.log(errorThrown)
                }
            })
            return false;
        },
    }
}();