# Maintenance guide for agents and contributors

Read the [implementation guide](implementation.md) and relevant source before changing behavior. Follow repository and user instructions for the current task. This document describes maintenance expectations, not authorization to access live projects or organizational directories.

## Working conventions

- Prefer explicit `$module->framework` helpers. Inspect the installed framework's documentation and implementation before using an API. Keep SQL parameterized and scoped to the intended module/project.
- In a REDCap checkout, consult `Classes/Hooks.php`, `Classes/System.php`, `Surveys/index.php`, `Classes/REDCap.php`, and the EM Framework's `docs/hooks.md` and relevant API docs. Find these in the maintainer's checkout; do not assume a particular machine path.
- Follow the framework i18n guide when introducing language strings. Escape dynamic HTML values; do not bypass interpolation escaping for untrusted text.
- Keep test fixtures synthetic. Do not put installation credentials, real participant data, local hostnames, session cookies, or captured private pages into committed artifacts.

## Invariants to preserve

1. Authorization must precede survey writes and completion side effects. The save/completion hooks manage already-authorized state; they cannot substitute for the early gate.
2. Resolve response/resource identity using trusted core context and stored records. Navigation parameters alone must not confer authorization or expand its scope.
3. Keep credentials on the dedicated login endpoint. Preserve framework and session CSRF checks, session-name verification, current-policy validation, and same-origin redirects.
4. Keep grants scoped and expiring. Changes to return, repeat, completion or file routes must not authorize unrelated responses, tabs, resources or endpoints.
5. Block expired submissions explicitly. Do not add automatic answer/upload replay without discussing its scope and establishing isolation, bounded storage and single-use processing.
6. Let REDCap own native file handling after authorization. Avoid duplicating its storage and ownership policies in the module.
7. Preserve dashboard-copy publication ordering and core permissions. Verify core behavior again when its copy controller or transaction handling changes.
8. Publish identity attributes only from an accepted backend. Preserve exact credential checks, Table-account revalidation, LDAP encoding/casing and backend order.
9. Treat lockout mutations as one synchronized operation. Do not replace primary reads with replica reads or use client-supplied forwarded chains as counter keys.
10. Keep migrations repeatable and state-based, including disabled projects and retries after partial completion. Preserve explicit settings choices; document destructive cleanup and rollback effects.

## Standalone regression suite

Run from the module root. Each suite runs in its own PHP process because fixtures define REDCap/framework classes and functions. The simulated LDAP suite needs `php -n` to avoid conflicts with a real LDAP extension.

```sh
set -eu
for test in tests/*regressions.php; do
    case "$test" in
        tests/ldap-regressions.php) php -n "$test" ;;
        *) php "$test" ;;
    esac
done
```

These suites do not need a REDCap bootstrap, database, credentials or web server. The maintained suites cover:

| Area changed | Relevant suites in `tests/` |
| --- | --- |
| Action tags and selector routing | `security-regressions.php` |
| Survey scopes, return and completion | `session-regressions.php` |
| File-route authorization boundary | `file-scope-regressions.php` |
| Dashboard/report grant lifecycle | `public-resource-regressions.php` |
| Endpoint configuration and classification | `endpoint-settings-regressions.php` |
| Dashboard copying and publication | `dashboard-copy-regressions.php` |
| Login rendering and branding | `login-branding-regressions.php` |
| Authentication event contents and modes | `authentication-logging-regressions.php` |
| Metadata saves and repeat structures | `metadata-write-regressions.php` |
| Table login and grant revocation | `table-account-regressions.php` |
| Lockout expiry and synchronization | `lockout-regressions.php`, `lockout-storage-regressions.php` |
| LDAP dispatch and result isolation | `ldap-regressions.php` |
| Retired settings and migration retries | `settings-migration-regressions.php` |

For runtime changes, run the focused suite while developing and all standalone suites before completion. Add behavioral assertions for the failure being fixed, not just assertions that reproduce the implementation. Where useful, temporarily reintroduce the defect in an isolated copy and verify the new test fails. Do not mutate the live checkout for that check.

Also check syntax and configuration:

```sh
set -eu
for file in *.php classes/*.php html/*.php tests/*.php; do
    php -l "$file"
done
php -r 'json_decode(file_get_contents("config.json"), true, 512, JSON_THROW_ON_ERROR);'
git diff --check
```

For documentation-only work, validate links and configuration text/structure as appropriate; live tests are unnecessary. For configuration changes, verify setting keys, defaults, branching logic and migration effects, not merely JSON syntax.

## Real LDAP integration

Follow the [disposable LDAP test instructions](../tests/fixtures/ldap-live/README.md). The container runs OpenLDAP and PHP's real LDAP extension with synthetic accounts and StartTLS. It publishes no ports; package installation needs network access. Do not run its package-installation/setup script directly on the host.

Run this test after LDAP transport, encoding, mapping or group changes. The REDCap fallback database query is simulated, and the directory is OpenLDAP. Passing it does not certify Active Directory, organizational directory policy, production certificates or the deployment's configured REDCap LDAP chain. Report those limits explicitly.

## REDCap integration and browser acceptance

Use a maintainer-designated test project and synthetic records. Establish what settings/data a test changes, restore temporary settings, and remove only fixtures created by the test. Avoid leaving credentials in command output or captured artifacts. Run independent tests concurrently only when their shared settings and records cannot interfere.

Choose live checks according to the change:

| Workflow | Required observations |
| --- | --- |
| Initial and continuation survey submissions | Unauthorized requests cause no writes/completion; authorized navigation and public-to-private continuation work with Allow writing on/off |
| Return, repeats and multiple tabs | Core return-code behavior remains intact; response/instance scopes stay distinct; completion retires the correct grant |
| Expiry and account/policy changes | Writes are blocked after expiry/revocation; the user gets the unsaved-submission message; no unintended replay occurs |
| Dashboard/report login and copying | Both configured origins apply the intended policy; a fresh browser requires its own login; copied dashboards inherit settings before publication |
| Files | Protected routes require authorization; authorized requests retain REDCap's expected native behavior |
| Credential handling | Synthetic password markers stay out of authentication/page-view logs and redirects; invalid CSRF/context submissions are rejected |
| UI | Keyboard, native submission, mobile layout and password-manager entry work; HTTP checks alone do not establish interactive usability |
| Settings migration | System/project enable clean retired values, including disabled-project data; repeat runs and explicit writing choices behave correctly |

For same-host path layouts and reverse proxies, test the actual configured routing and scheme/host handling. Do not equate fixture URL classification with deployed proxy verification. Do not assume login helpers reproduce every policy in REDCap's staff login flow.

## Review and handoff

Explain the behavior changed, why it changed, the checks run and their limits. Distinguish source inspection, simulated tests, real LDAP tests, HTTP integration and interactive browser testing. Record remaining acceptance work without describing it as completed.

Update implementation/user documentation when behavior changes, and the changelog when appropriate. Suggest a scoped commit message and the highest-value next slice; do not invent more work if the request is complete. Review the intended file list before staging or publishing so only public documentation and synthetic fixtures are included.
