var RUBSurveyAuth = function() {
    return {
        verify: function(prefix) {
            // Find ui elements.
            const form = $('#form');
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
            uinput.attr('disabled', true)
            pinput.attr('disabled', true)
            submit.attr('disabled', true)
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
                    failmsg.show()
                    uinput.attr('disabled', false)
                    pinput.attr('disabled', false)
                    submit.attr('disabled', false)
                    setTimeout(function() {
                        submit.html(submitNormal);
                    })
                }
            })
            .fail(function(jqXHR, textStatus, errorThrown) {
                failmsg.show()
                uinput.attr('disabled', false)
                pinput.attr('disabled', false)
                submit.attr('disabled', false)
                setTimeout(function() {
                    submit.html(submitNormal);
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