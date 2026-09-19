SurveyAuth EM

# Changelog

Release | Description
------- | ---------------------
| 2.2.1 | Furhter ecurity hardening |
| 2.2.0 | Harden security, survey metadata, endpoint classification, custom credentials, action-tag parsing and participant content rendering; MLM translation support. See README for session lifetimes and configuration behavior. |
| 2.1.1 | Bug fix: Dashboard protection and survey endpoint detection failed in some circumstances. |
| 2.1.0 | New feature: Public Reports can be protected with a login. For instances with separate survey endpoint, additonal options are available. |
| 2.0.0 | New feature: Public Dashboards can be protected with a login. For instances with separate survey endpoint, additonal options are available. |
| 1.5.0 | LDAP attributes: Support fallback to REDCap's user table for email and full name. |
| 1.4.5 | Fix a potential LDAP error when using PHP8.1+ |
| 1.4.4 | Critical bug fix: Surveys would be marked as completed before actually getting displayed. This was an unintended side effect of the 1.4.3 "fix". The log leak, for now, cannot be prevent, but the module now immediately sanitizes the `redcap_log_view` table by deleting any such log entries (the delete query is limited to the specific project and instrument). |
| 1.4.3 | Critical security bug fix: REDCap logged the POST request, including the clear-text password, in `redcap_log_view`. Run `DELETE FROM redcap_log_view WHERE miscellaneous LIKE "// POST%[redcap_survey_auth-password]%"` against your database to sanitize the table! |
| 1.4.2 | Bugfix: @SURVEY-AUTH now works in multi-arm projects. Change: Removed system option to turn off @SURVEY-AUTH on non-public surveys. |
| 1.4.1 | Bugfix: @SURVEY-AUTH with @IF works now in public surveys. |
| 1.4.0 | Compatiblity fix: @SURVEY-AUTH can now be used inside @IF; Bugfix: Some JavaScript was missing from the login page; Minimum REDCap version is 12.0.7. |
| 1.3.1 | Changed the way the url for login form submission is generated. |
| 1.3.0 | New feature: Login for non-public surveys. Simply add the @SURVEY-AUTH action tag (this must first be enabled in the system settings of the module). Enhancement: The token is not required any longer, but instead replaced by a setting that controls whether the module may write data to a record (during an upgrade, tokens are deleted and write mode set to ON). |
| 1.2.9 | Updated framework to v6 and updated REDCap version requirements (minimal: 10.4.1 Standard, 10.6.4 LTS). |
| 1.2.8 | Updated how some urls are constructed. Fixes disabled submit button when login data is entered without user input (e.g., by password managers). |
| 1.2.7 | Minor enhancements: Browser compatibility fixes, tabbing between inputs. Add option to control lockout. |
| 1.2.6 | Bug fix: Fixed a bug that prevented the action tag from working properly. |
| 1.2.5 | Enhancement: Improved strategy to obtain LDAP attributes. |
| 1.2.4 | Add the option to use custom LDAP mappings for email and full name. Add support for multiple REDCap LDAP configurations. |
| 1.2.3 | Compatibility fix for older REDCap versions. |
| 1.2.2 | Fix a regression regarding `disableUserBasedSettingPermissions()` that was added in 1.1.1. |
| 1.2.1 | Bug fixes, more detailed logging. |
| 1.2.0 | This version does not perform AJAX requests any more and can operate (with limitations) without providing an API token. |
| 1.1.1 | Add call to `disableUserBasedSettingPermissions()` in order to support older REDCap versions. Fixed the bug that REDCap's LDAP configuration was not available (the module would only work for explicitly set LDAP configurations). |
| 1.1.0 | Bugfixes (IE11 compatibility). |
| 1.0.0 | Initial release. |
