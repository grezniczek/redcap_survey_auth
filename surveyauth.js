var RUB_SurveyAuth = function() {

    return {

        check: function(prefix, guid) {
            // Find ui elements.
            const div = $(`#${prefix}-${guid}`)

            /*
            const sourceName = div.attr('data-source') || `${prefix}-${guid}-input`
            const record = div.attr('data-record')
            const dateFormat = div.attr('data-dateformat')
            const debug = div.attr('data-debug') == "1"
            const sourceCtrl = $(`input[name='${sourceName}']`)
            const resultDiv = $(`#${prefix}-${guid}-result`)
            const checkBtn = $(`#${prefix}-${guid}-check`)
            const copyBtn = $(`#${prefix}-${guid}-copy`)

            // Clear previously found data.
            jQuery.data(document, `${prefix}-${guid}-result`, null)
            // Set ui state.
            checkBtn.addClass('disabled')
            checkBtn.prop('disabled', 'disabled')
            copyBtn.removeClass('btn-primaryrc')
            copyBtn.addClass('disabled')
            copyBtn.prop('disabled', 'disabled')
            resultDiv.html('<p><img src="data:image/gif;base64,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" alt="..." /></p>')
            // Extract data.
            const caseId = sourceCtrl.val().trim()
            if (debug) console.log(`Checking for '${caseId}'...`)
            const queryUrl = div.attr('data-queryurl')
            // Perform server request.
            if (debug) console.log(`Executing request for ${guid} ...`)
            */

            return $.ajax({
                url: queryUrl,
                type: 'POST',
                data: { username: "test", password: "test" },
                dataType: 'json'
            })
            .done(function(data, textStatus, jqXHR) {
                if (data.error != undefined) {
                    // Show error returned from lookup service.
                    resultDiv.html(`<p class="error">${data.error}</p>`)
                }
                else {
                    // Show result.
                }
                if (debug) {
                    console.log(`Successfully executed request for ${guid}.`)
                    console.log(data)
                }
            })
            .fail(function(jqXHR, textStatus, errorThrown) {
                resultDiv.html(`<p>An error occured while communicating with the server:<br><b class="error">${errorThrown}</b></p>`)
                if (debug) {
                    console.log(`Failed request for ${guid}:`)
                    console.log(errorThrown)
                }
            })
        },

        setup: function(prefix, guid, field) { 
            const content = $(`#${prefix}-${guid}-tpl`).prop("content")
    
            // Move div into place.
            var dest = $(`#label-${field}`)
            if (dest.prop('id') != `label-${field}`) {
                dest = $(`#${field}-tr td`)
                dest.append(content)
            } else {
                dest.after(content)
            }
            // Find ui elements.
            const div = $(`#${prefix}-${guid}`)
            const debug = div.attr('data-debug') == '1'

            if (debug) console.log(`Setting up SurveyAuth in field '${field}' (${prefix}-${guid})`)

            // Set tab index and visibility.

            // Hook up click handlers (need to return false to prevent REDCap from reloading the form).
            checkBtn.click(function() {
                RUB_SurveyAuth.check(prefix, guid, sourceCtrl)
                return false
            })
        }
    }
}();