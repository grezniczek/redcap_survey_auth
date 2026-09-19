# Survey Auth companion integration with Multi-Language Management

This document describes the implementation currently used by Survey Auth. It is a module-owned companion feature: it makes configured Survey Auth login text translatable for MLM-enabled surveys without adding an MLM extension point, changing REDCap core, or writing to MLM tables. The separate [proposed MLM External Module extension point](MLM_EM_Integration.md) is informational only and is not a dependency of this feature.

## Scope and access

The **Survey Auth login translations** project link is a dedicated editor rather than another large group of module settings. It is displayed when all of the following are true:

- Survey Auth is enabled in the project;
- MLM is active for the project;
- at least one survey contains a potentially applicable `@SURVEY-AUTH` tag; and
- at least one MLM language is project-active.

The link does not depend on a project-active language being enabled for a particular protected survey. That permits preparation of translations before survey activation. At runtime, however, a language is usable only when it is active for the exact protected survey instrument.

Direct access enforces the same project design-rights requirement as the normal project-link baseline. The editor changes only presentation strings; it does not expose or edit authentication backend configuration or credentials.

## Module-owned translation data and editor

Survey Auth stores only its own overrides in the versioned project setting `surveyauth_mlm_login_translations`. The reference value remains the ordinary Survey Auth setting or a fixed participant-facing default. An entry records its `value` and the SHA-256 `source_hash` of the reference string, allowing the editor to mark a translation whose source has changed. Blank overrides are omitted so ordinary fallback applies.

The store is limited to 2 MiB. Each plain-text item is limited to 4 KiB and the HTML-capable instructions item to 32 KiB. Unknown keys, malformed versions, invalid hashes, and overlong stored values are ignored on read. Survey Auth never writes to `redcap_multilanguage_*` tables.

The editor lists all project-active MLM languages and provides one autosizing textarea per item. The participant-visible Survey Auth items are:

- login heading and instructions;
- username, password, and submit labels;
- invalid-login, lockout, and technical-error messages; and
- cookie-required, expired-login, browser-communication, JavaScript-required, Start over reauthentication, and unsaved-submission messages.

There is no language-selector label item. The survey title and custom survey-logo alternative text are already MLM survey metadata items (`survey-title` and `survey-logo_alt_text`), so Survey Auth does not duplicate them.

## Runtime behavior

For a protected survey request, Survey Auth constructs a `REDCap\Context` from its trusted login scope: project, survey, event, instrument, record/response where known, and instance. It uses MLM's current-language resolution, then confirms that the selected language is active for that instrument. A configured MLM fallback is used only if it too is active for that instrument; otherwise the reference Survey Auth string is used.

The login page receives a small catalogue for only the eligible languages. Its Bootstrap-styled language buttons persist the established MLM survey cookie and update the module's own markup, survey title, custom-logo `alt` text, HTML `lang`, and `dir` for RTL. It does not load the full field-translation payload or initialize a second core survey translator. When no language is active for the protected survey, Survey Auth renders its normal reference-language login page.

Failed AJAX logins return a stable Survey Auth error key where possible, allowing the browser to resolve it from the current trusted catalogue. Server-resolved messages use the stored scope and MLM cookie, never a submitted language ID or submitted translation text.

This feature is survey-only. Dashboard and report login strings retain their existing configuration until separately designed.

## Safety properties

Translations affect display only. They do not influence action-tag detection, authentication dispatch, CSRF/context validation, lockout accounting, session rotation, grant content, or policy revision.

Only the instructions item permits intentional HTML and it passes through REDCap's `filter_tags()` allowlist before rendering. All other translation values, survey titles, and logo alternative text are rendered as text in their respective output context.

## Verification and outstanding acceptance

Focused regression coverage exercises project-link eligibility, language/instrument eligibility, selected/fallback/reference resolution, title and logo metadata resolution, bounded storage, stale source hashes, selector cookie behavior, RTL, and the translation editor's autosizing/tabs. The wider login/session suites cover the unchanged authorization behavior.

PID 87 remains the browser-acceptance project. Configure at least two active languages for a tagged survey, supply one complete and one incomplete translation, then verify language switching, fallback, RTL where relevant, successful and failed login, lockout, session expiry, Start over, return flow, and the no-JavaScript message. Use only synthetic credentials and restore temporary project configuration afterwards.

## Relationship to a future core extension

The companion is independently shippable and remains the active Survey Auth design. If a reusable core/EM Framework provider registry is later accepted, Survey Auth could add a read adapter and an explicitly authorized one-time import of these module-owned overrides. That future work must not alter or block the companion described here.
