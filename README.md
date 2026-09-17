# Survey Auth

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.TBD.svg)](https://doi.org/10.5281/zenodo.TBD)

Survey Auth is a REDCap External Module that adds session-bound authentication to protected surveys and public dashboards and reports. It supports Custom credentials, REDCap Table authentication, REDCap-configured LDAP, and superuser-configured Other LDAP; scoped, expiring authorization; optional authentication-metadata writes; and optional Multi-Language Management (MLM) survey-login translations.

## Purpose / Use Case

In some cases it is useful to present a data-entry form, public dashboard, or public report without exposing the REDCap user interface, while still identifying the person entering or viewing data. Those users do not need project membership or a REDCap account.

Possible use cases may be incident reports, internal orders/reports or requests for goods or services, etc.

## Effect

When protection is enabled for a survey (public or non-public), public dashboard, or public report, users must authenticate before accessing it. Successful login redirects directly to the protected resource.

![Screenshot](images/surveyauth.png)

Authentication can use project-configured Custom credentials, REDCap's user table, LDAP directories configured in REDCap, and—when enabled by a REDCap superuser—additional project-specific LDAP directories.

## Requirements

This development checkout targets REDCap master and uses External Modules Framework version 12. Compatibility with older REDCap releases has not been verified for these changes.

## Installation

Participant login requires JavaScript and uses the EM Framework’s AJAX route under `/surveys/`. Direct `/external_modules/` access is not required on the survey host; the framework’s survey AJAX route must be available.

- Clone this repository into `<redcap-root>/modules/redcap_survey_auth_v<version-number>`, or obtain it from the Consortium REDCap Repo via the Control Center.
- Go to Control Center > Technical / Developer Tools > External Modules and enable REDCap Survey Auth.
- Enable the module for each project that needs survey authentication. Configure at least one authentication method before adding `@SURVEY-AUTH` to a survey instrument or enabling dashboard/report protection. A protected resource with no enabled authentication method rejects every login.
- For development checkouts, use the directory name `redcap_survey_auth_v9.9.9`.

## Configuration

### System-Level Settings

- **Lockout time:** The time, in whole minutes, that a user is denied further login attempts based on the client IP address reported to PHP. It defaults to 5 minutes; set it to 0 to disable lockouts. The project-level Lockout count determines the threshold (default: 3). Failed-attempt counts are shared by client IP across projects using this module and stored in bounded hash buckets. Attempts made while locked out do not extend the deadline, and successful authentication clears that IP's failed-attempt count. When lockouts are enabled, password checks are serialized per IP across projects and sessions so concurrent attempts cannot exceed the configured threshold. A request that cannot obtain the per-IP lock within five seconds fails without checking its password.

### Project-Level Settings

- **Logging:** Determines which authentication attempts the module records in the project log. Only REDCap superusers can change this setting. It does not disable REDCap's own page-view or data-change logging.
  - _None:_ No module authentication log entries will be produced.
  - _Failed attempts only:_ Log entries will be produced for failed login attempts only.
  - _Successful attempts:_ Log entries will be produced for successful logins.
  - _All:_ Log entries will be produced for both types of events.

- **Allow writing:** When this is enabled, the module writes the authentication values selected by the `@SURVEY-AUTH` parameters to the survey response before forwarding the user to the survey. For a public survey, it creates a response when those values need to be written; for an existing response, it writes to that response. Without a mapped value or `success` parameter, this setting creates no record. When disabled, the module writes no authentication metadata, although REDCap can still save ordinary survey responses after authorization. Authentication attempts are logged according to the Logging setting independently of Allow writing; survey-authentication log entries include the submitted username, survey, instance, and outcome.

- **Text displayed above username/password fields:** Optionally enter a prompt for the survey user. This is the only participant-facing setting that permits REDCap-supported formatting; `filter_tags()` removes unsafe HTML before display. The same filtering applies to its MLM translations. All other labels and messages are displayed as plain text.

- **Username label:** The label to be displayed for the username text box. Defaults to 'Username'.

- **Password label:** The label to be displayed for the password box. Defaults to 'Password'.

- **Submit label:** The label to be displayed on the submit button. Defaults to 'Submit'.

- **Fail message:** A message displayed when authentication fails or is denied. Defaults to 'Invalid username and/or password or access denied.'.

- **Lockout count:** Sets the number of failed login attempts that will trigger a lockout. Set to 0 to disable lockout. Default = 3.

- **Lockout message:** A message displayed after too many failed login attempts. Defaults to 'Too many failed login attempts. Please try again later.'.

- **Technical error message:** A message displayed when a technical error prevents completion of authentication. Defaults to 'A technical error prevented completion of the authentication process. Please notify the system administrator.'.

- **Authentication methods:** Any of the following methods can be used for authentication. Authentication is attempted in this order: Custom > Table > Other LDAP > LDAP, stopping at the first successful method.

  - **Table:** REDCap verifies the username and password against its user table. Suspended accounts are denied.

  - **LDAP:** Uses the LDAP directory configuration supplied by REDCap. If REDCap has more than one configured LDAP directory, they are tried in REDCap's configured order.

  - **Other LDAP:** Only REDCap superusers can enable or configure this method because its JSON can contain service-account credentials and controls outbound directory connections. Provide any number of LDAP connection info as a JSON array. The order of processing will be as provided in the array. Use the connection and search parameters shown below, adapting the server, service account, base DN, and filters to your directory. The LDAP extension must be available in PHP.

    Example:

    ```JSON
    [
        {
            "url": "ldap://ldap.example.org",
            "port": 389,
            "version": 3,
            "binddn": "cn=redcap,ou=services,dc=example,dc=org",
            "basedn": "dc=example,dc=org",
            "bindpw": "bindpassword",
            "attributes": [],
            "userattr": "samAccountName",
            "userfilter": "(objectCategory=person)",
            "start_tls": true,
            "referrals": false
        }
    ]
    ```

    This example uses LDAP v3 with StartTLS; the server must support it and PHP must trust its certificate. LDAP v3 is also the default when `version` is omitted. If `start_tls` is true, an incompatible protocol setting or failed TLS negotiation rejects authentication before any bind credentials are sent. Use JSON booleans for `start_tls`.

  - **LDAP Attribute mappings:** Available when either LDAP method is enabled. Enter comma-separated attribute names for email, full name, first name, and last name. Email defaults to `email,mail`, first name to `givenName`, last name to `sn`, and full name has no default. The module uses a full-name value when present; otherwise it combines first and last name.

  - **Fall back to retrieving user information from REDCap's user table when no values are obtained from LDAP attributes:** After successful LDAP authentication, any missing email or full name is filled from the REDCap user table for the submitted username. Values already obtained from LDAP are retained. This does not authenticate against the REDCap table or create a REDCap account.

  - **Custom:** When selected, custom credentials can be entered into a text box. Type one nonempty username/password pair per line, with the first colon as the separator (for example, `UserXY:secret123`; later colons remain part of the password). Usernames are case-insensitive; passwords are case-sensitive. Malformed or blank lines are ignored.

- **Use Allowlist:** When checked, a list of usernames (one username per line) can be entered. Only users in this list will be able to authenticate successfully. Matching is case-insensitive; an enabled empty allowlist denies everyone.

- **Survey Auth login translations (MLM project link):** The **Survey Auth login translations** link is shown when the project has at least one survey with `@SURVEY-AUTH`, MLM is active for the project, and at least one MLM language is project-active. It lets users with project Design rights translate the Survey Auth survey-login text for project-active languages. At runtime, a language is available only when it is also active for that particular protected survey; survey titles and custom-logo alternative text come from MLM's own survey metadata. Dashboard and report login pages are not translated by this feature. See the [MLM companion integration guide](docs/mlm_integration.md) for details.

- **Public Dashboard Access Denied Message:** Allows a custom plain-text message when a public dashboard is configured to deny access from the external survey endpoint. Failed dashboard logins use the Fail message instead.

- **Public Report Access Denied Message:** Allows a custom plain-text message when a public report is configured to deny access from the external survey endpoint. Failed report logins use the Fail message instead.

### @SURVEY-AUTH Action Tag

To enable authentication for a survey, use the **@SURVEY-AUTH** action tag on any field of the survey instrument. Parameters are optional, and there must be at most one such tag per instrument.

```ActionTag
@SURVEY-AUTH(success=value, username=fieldname, email=fieldname, fullname=fieldname, timestamp=fieldname)
```

When _username_, _email_, _fullname_, or _timestamp_ are defined, the corresponding data will be inserted into the specified fields when Allow writing is enabled (timestamp format will match the datetime format of the target field; time-only fields are not supported; the default date format is YMD).

When a value for _success_ is defined, the field with the action tag will be set to this value when Allow writing is enabled; no additional mapping is required. Use @READONLY/@READONLY-SURVEY or @HIDDEN-SURVEY to keep participants from editing the displayed authentication fields. With Allow writing enabled, the module also discards survey-request edits to the authentication fields it populated, including attempts to blank them. This preserves the values already saved at login; ordinary survey answers and staff data-entry edits are unaffected.

### Combining **@SURVEY-AUTH** with **@IF**

The **@SURVEY-AUTH** action tag can be used inside **@IF** action tags. Note that in public surveys, at the time of evaluation, the record does not exist yet, and thus any logic should be restricted to record-independent elements, such as e.g. the [arm-number], [arm-label] or the aggregate smart variables.


## Public Dashboards and Reports

Survey Auth options appear in a separate blue panel when editing an existing public Project Dashboard or an existing Report. Report protection applies when the report is public. Enable the protection switch to require login.

In REDCap installations that use a separate endpoint for surveys, additional options are available:

- The option to require login for both endpoints or only for the (external) survey endpoint or the (internal) REDCap endpoint.
- The option to deny access to public dashboards/reports when accessed via the (external) survey endpoint. The message that is displayed in such a case can be set in the module's project level configuration.

The copy icon beside each endpoint option copies that endpoint’s public report/dashboard link, including its configured base path. The button briefly turns green after a successful copy. Copying a link does not change protection settings or share authorization.

![Protection of Public Dashboards](images/public-dashboard-protection.png)

Endpoint selection uses the configured scheme, hostname, port, and base path. It derives the current origin from PHP's server configuration rather than the client-controlled `Host` header. Reverse proxies must therefore expose the canonical public server name, port, and scheme to PHP. Internal and external URLs can share a hostname if their base paths differ; the more specific matching path takes precedence. Requests matching neither configured endpoint are denied. Denying external access takes precedence over login protection, including for users who already authenticated.

Dashboard copies inherit the source dashboard's SurveyAuth settings. Copies remain private until those settings are saved, and become public only if REDCap's publication rules permit it. REDCap copies reports as non-public; review protection when making a copied report public.

## Authentication sessions

Authorization is stored in the REDCap survey session for the browser making the request. Successful login rotates the session identifier and invalidates the previous identifier while retaining needed session data. This security update invalidates earlier grants and login forms: participants must reopen the resource and sign in again. Sharing a survey, dashboard, or report URL does not share authorization. Old URL authentication tokens and calendar-day dashboard/report session flags are no longer accepted.

- Use one active survey tab at a time. Multiple login tabs can authenticate independently without refreshing after another tab opens. Completing a survey with final Submit makes REDCap destroy the shared survey session, so other tabs must sign in again; unsaved answers are not automatically restored.
- Login forms expire after 10 minutes. Reopen the resource to obtain a fresh form.
- Authorization expires after 30 minutes without authorized activity or 8 hours after login, whichever comes first. REDCap session expiry or loss of the session cookie can end access earlier.
- With **Allow writing** enabled, **Start over** restores the exact authentication values originally written by the module (including the original timestamp), while leaving survey answers cleared. Sessions created before this feature ask for login again before resetting.
- Survey authorization is scoped to the survey response and repeat instance. Public starts are kept separate; Save & Return still requires REDCap's return-code validation and SurveyAuth authorization.
- Dashboard and report authorization is scoped to the individual resource and endpoint. Logging into one does not authorize another.
- Protection-setting changes invalidate existing authorization. Table-authenticated sessions also recheck account suspension and password changes. LDAP credentials are checked at login, not on each subsequent request.

SurveyAuth gates access to survey file routes; REDCap retains responsibility for native file handling after authorization.

## Retired settings

The former **Success message** (`surveyauth_successmsg`) and **Continue label** (`surveyauth_continuelabel`) settings have been removed because successful login redirects immediately. Their saved values are deleted when the module is enabled or changed to this version in Control Center, including values retained in disabled projects. Project enable also cleans up values restored or imported later. Cleanup is safe to repeat.

The earlier token-to-Allow writing migration is retained: a nonempty legacy token enables metadata writing only when Allow writing has no saved value. Explicit choices are preserved, and the legacy token is removed. Rolling back does not restore deleted custom messages or tokens.

## Release History

See [CHANGELOG.md](CHANGELOG.md) for version history and notable changes.

## How to cite this work

Please use the citation generated from [CITATION.cff](CITATION.cff). On [GitHub](https://github.com/grezniczek/redcap_survey_auth), select **Cite this repository** for ready-to-use citation formats.

---

## AI assistance

Development of this project has made extensive use of AI assistance. AI tools, primarily ChatGPT by OpenAI, have been used throughout the development process, including for discussion and refinement of design and architecture, implementation and refactoring of code, debugging and review, and preparation and revision of documentation.

The extent and nature of this assistance vary across the project and are not attributed to individual commits. AI-generated suggestions and contributions are reviewed, adapted, and integrated as part of the normal development process.

Responsibility for the design, implementation, maintenance, and released software remains entirely with the project maintainer.
