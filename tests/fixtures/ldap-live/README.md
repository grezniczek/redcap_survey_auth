# Disposable LDAP integration test

This test uses Debian Bookworm, PHP's real LDAP extension, and OpenLDAP with a locally generated certificate. It creates synthetic users only. No REDCap database or organizational directory is used; the REDCap attribute-fallback query is simulated.

From the module directory, run:

```sh
docker run --rm --name surveyauth-ldap-integration \
  --mount "type=bind,source=$PWD,target=/workspace,readonly" \
  debian:bookworm-slim sh /workspace/tests/fixtures/ldap-live/setup.sh
```

No ports are published. Package installation requires network access. The container and generated directory/certificate are removed on exit; the base image remains cached. Fixture passwords are public test values. Use this script only in a disposable container: it installs packages and writes under `/tmp`.

The checks cover StartTLS, correct and incorrect credentials, group membership, UTF-8 usernames, LDAP attribute casing, literal filter metacharacters, and attribute fallback after successful binding. They do not certify Active Directory, deployment certificates, or REDCap's configured LDAP directories.
