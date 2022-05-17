# REDCap Survey Auth

A REDCap External Module that adds authentication to surveys.

See the [changelog](#changelog) for information on release updates.

## Purpose / Use Case

In some cases it may be useful to present users with a data entry form but not confront them with the REDCap user interface, yet still be able to tell who the person entering the data was. This way, they do not need to be members of the project or even have a REDCap account.

Possible use cases may be incident reports, internal orders or requests for goods or services, etc.

## Effect

When enabled for a survey, a login page will be displayed as first page of a survey that the user needs to complete before being able to proceed to the survey (similar to the reCAPTCHA feature introduced in REDCap 8.11).

From version 1.3.0 of this module, this now works for **non-public surveys** in addition to **public surveys**.

![Screenshot](surveyauth.png)

Survey users can be authenticated against REDCap Users (table-based authentication), any number or LDAP servers, and/or against a list or username/password entries provided in the module's project configuration.

## Requirements

REDCap 10.4.1 Standard / REDCap 10.6.1 LTS or newer.

## Installation

- Clone this repo into `<redcap-root>/modules/redcap_survey_auth_v<version-number>`, or
- Obtain this module from the Consortium REDCap Repo via the Control Center.
- Go to Control Center > Technical / Developer Tools > External Modules and enable REDCap Survey Auth.
- Enable the module for each project that needs survey authentication. Be sure to include the action tag @SURVEY-AUTH somewhere in the survey instrument and to configure the module's project settings (authentication is deactivated with the default settings).

## Configuration

### System-Level Settings

- **Lockout time:** The time, in (whole) minutes, a user (based on client IP) is denied further login attempts. Defaults to 5 minutes. Explicitly setting this to 0 (zero) will disable the lockout mechanism. The lockout occurs after 3 failed attempts.

### Project-Level Settings

- **Logging:** Determines the type of logging that occurs.
  - _None:_ No log entries will be produced.
  - _Failed attempts only:_ Log entries will be produced for failed login attempts only.
  - _Successful attempts:_ Log entries will be produced for successful logins.
  - _All:_ Log entries will be produced for both types of events.

- **Allow writing:** When this is enabled, the module can write data (as specified by the action tag parameters) to a (newly created) record before forwarding the user to the survey. Otherwise, no data is written to the record and the user is simply forwarded to the survey after successful authentiation. In any case, authentication is logged to the events table.

- **Text displayed above username/password fields:** Optionally enter some prompt that is displayed to the survey user.

- **Username label:** The label to be displayed for the username text box. Defaults to 'Username'.

- **Password label:** The label to be displayed for the password box. Defaults to 'Password'.

- **Submit label:** The label to be displayed on the submit button. Defaults to 'Submit'.

- **Fail message:** A message that is displayed to the user in case the login fails. Defaults to 'Invalid username and/or password or access denied'.

- **Lockout count:** Sets the number of failed login attempts that will trigger a lockout. Set to 0 to disable lockout. Default = 3.

- **Lockout message:** A message that is displayed to the user in case of too many failed login attempts. Defaults to 'Too many failed login attempts. Please try again later'.

- **Technical error message:** A message that is displayed to the user in case of a technical error that prevents completion of the authentication process. Defaults to 'A technical error prevented completion of the authentication process. Please notify the system administrator'.

- **Success message** and **Continue label:** A message and button label that are displayed to the user after successful authentication. This is only relevant when writing by the module is allowed (see above).

- **Authentication methods:** Any of the following methods can be used for authentication. Note the order, in which authentication is attempted: Custom > Table > Other LDAP > LDAP.

  - **Table:** The REDCap user table is used to look up user/password combinations.

  - **LDAP:** When REDCap is set to use LDAP, this is used for authentication.

  - **Other LDAP:** Provide any number of LDAP connection info as a JSON array. The order of processing will be as provided in the array. See the [PEAR manual for the LDAP auth container](https://pear.php.net/manual/en/package.authentication.auth.storage.ldap.php) for a list of parameters (_debug_ is not supported) or the LDAP configuration in REDCap's `webtoolsl2/ldap` folder.

    Example:

    ```JSON
    [
        {
            "url": "ldap://127.0.0.1",
            "port": 389,
            "version": 3,
            "binddn": "bindUsername",
            "bindpw": "bindpassword",
            "attributes": [],
            "userattr": "samAccountName",
            "userfilter": "(objectCategory=person)",
            "start_tls": false,
            "referrals": false
        }
    ]
    ```

  - **LDAP Attribute mappings:** When LDAP is enabled, custom attribute mappings for email, first, last, and full name can be set. These will be used when attempting to get email and full name of an authenticated user.

  - **Custom:** When selected, custom credentials can be entered into a text box. Type one username-password pair per line, separated by a colon (e.g. `UserXY:secret123`). Usernames are not case-sensitive (passwords are).

- **Use Whitelist:** When checked, a list of usernames (one username per line) can be entered. Only users in this list will be able to authenticate successfully.

### @SURVEY-AUTH Action Tag

To enable authentication for a survey, the **@SURVEY-AUTH** action tag must be used on any field of the survey instrument. There must be at most one action tag per instrument.

```ActionTag
@SURVEY-AUTH(success=value, username=fieldname, email=fieldname, fullname=fieldname, timestamp=fieldname)
```

When _username_, _email_, _fullname_, or _timestamp_ are defined, the respective data will be inserted into to records into the specified fields. Timestamp format will match the datetime format of the target field (time-only fields are not supported; defaults to YMD).

When a value for _success_ is defined, the field with the action tag will be set to this value. If used, the field should be set to @READONLY/@READONLY-SURVEY or @HIDDEN-SURVEY.

## [Changelog](#changelog)

Release | Description
------- | ---------------------
v1.3.1  | Changed the way the url for login form submission is generated.
v1.3.0  | New feature: Login for non-public surveys. Simply add the @SURVEY-AUTH action tag (this must first be enabled in the system settings of the module). Enhancement: The token is not required any longer, but instead replaced by a setting that controls whether the module may write data to a record (during an upgrade, tokens are deleted and write mode set to ON).
v1.2.9  | Updated framework to v6 and updated REDCap version requirements (minimal: 10.4.1 Standard, 10.6.4 LTS).
v1.2.8  | Updated how some urls are constructed. Fixes disabled submit button when login data is entered without user input (e.g., by password managers).
v1.2.7  | Minor enhancements: Browser compatibility fixes, tabbing between inputs. Add option to control lockout.
v1.2.6  | Bug fix: Fixed a bug that prevented the action tag from working properly.
v1.2.5  | Enhancement: Improved strategy to obtain LDAP attributes.
v1.2.4  | Add the option to use custom LDAP mappings for email and full name. Add support for multiple REDCap LDAP configurations.
v1.2.3  | Compatibility fix for older REDCap versions.
v1.2.2  | Fix a regression regarding `disableUserBasedSettingPermissions()` that was added in v1.1.1.
v1.2.1  | Bug fixes, more detailed logging.
v1.2.0  | This version does not perform AJAX requests any more and can operate (with limitations) without providing an API token.
v1.1.1  | Add call to `disableUserBasedSettingPermissions()` in order to support older REDCap versions. Fixed the bug that REDCap's LDAP configuration was not available (the module would only work for explicitly set LDAP configurations).
v1.1.0  | Bugfixes (IE11 compatibility).
v1.0.0  | Initial release.
