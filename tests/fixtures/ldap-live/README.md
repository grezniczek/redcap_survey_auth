# Disposable LDAP integration test

This test uses Debian Bookworm, PHP's real LDAP extension, and OpenLDAP with a locally generated certificate. It creates synthetic users only. No REDCap database or organizational directory is used; the REDCap attribute-fallback query is simulated.

From the module directory, run:

```sh
docker run --rm --name surveyauth-ldap-integration \
  --mount "type=bind,source=$PWD,target=/workspace,readonly" \
  debian:bookworm-slim sh /workspace/tests/fixtures/ldap-live/setup.sh
```

No ports are published. Package installation requires network access. The container and generated directory/certificate are removed on exit; the base image remains cached. Fixture passwords are public test values. Use this script only in a disposable container: it installs packages and writes under `/tmp`.

The default checks exercise the unchanged Other LDAP transport: StartTLS with explicit or omitted LDAP v3, rejection of LDAP v2 with requested StartTLS, correct and incorrect credentials, group membership, UTF-8 usernames, LDAP attribute casing, literal filter metacharacters, and attribute fallback after successful binding. They do not certify Active Directory, deployment certificates, or REDCap's configured LDAP directories.

## Installed REDCap LDAP driver revisions

The core LDAP adapter also needs checks against real REDCap drivers. Export the required files from a licensed local Git checkout to a temporary directory, then mount it read-only as `/core`:

```sh
core_fixture=$(python3 tests/fixtures/ldap-live/export-core.py /path/to/redcap-checkout)
docker run --rm --name surveyauth-core-ldap-integration \
  --mount "type=bind,source=$PWD,target=/workspace,readonly" \
  --mount "type=bind,source=$core_fixture,target=/core,readonly" \
  debian:bookworm-slim sh /workspace/tests/fixtures/ldap-live/setup.sh
```

The exporter defaults to 16.0.0 and 17.5.6, covering both driver revisions found in the compatibility investigation. Additional numeric tags can follow the checkout argument. It reads the four PEAR files and the `utf8_encode_rc`/`isinteger` helpers directly from those tags. It does not bootstrap REDCap, read installation credentials, or copy core source into this repository. Delete the printed temporary fixture directory after testing.

With `/core` mounted, setup runs the existing Other LDAP checks followed by `ldap-core-integration.php` in a separate PHP process per tag. It also rejects an untrusted certificate in a separate process per tag. The adapter checks include port and host precedence, both attribute formats, failed-attempt attribute isolation, directory order, group checks, NUL/empty credentials, pre-connection TLS validation, sanitized operational errors, table fallback, base-DN behavior, and session/request isolation. LDAP listeners use ports 1389/389 and LDAPS uses 636 inside the disposable container; no host ports are published. These checks use PHP 8.2 on Debian Bookworm and do not establish compatibility with other PHP runtimes or organizational directories.
