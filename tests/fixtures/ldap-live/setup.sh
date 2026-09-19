#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends slapd ldap-utils php-cli php-ldap openssl ca-certificates > /tmp/ldap-install.log 2>&1
mkdir -p /tmp/ldap-data
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout /tmp/ldap.key -out /tmp/ldap.crt -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 > /tmp/ldap-cert.log 2>&1
cat > /tmp/slapd.conf <<'EOF'
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile /tmp/slapd.pid
argsfile /tmp/slapd.args
modulepath /usr/lib/ldap
moduleload back_mdb
TLSCertificateFile /tmp/ldap.crt
TLSCertificateKeyFile /tmp/ldap.key
database mdb
maxsize 10485760
suffix "dc=test"
rootdn "cn=admin,dc=test"
rootpw fixture-admin
directory /tmp/ldap-data
access to * by * read
EOF
slapadd -f /tmp/slapd.conf -l /workspace/tests/fixtures/ldap-live/users.ldif
slapd -f /tmp/slapd.conf -h 'ldap://127.0.0.1:1389/'
export LDAPTLS_CACERT=/tmp/ldap.crt
ldapwhoami -x -ZZ -H ldap://127.0.0.1:1389 -D cn=admin,dc=test -w fixture-admin
php /workspace/tests/ldap-integration.php
