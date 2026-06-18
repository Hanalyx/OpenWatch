#!/usr/bin/env bash
# Full package-manager upgrade test. Runs INSIDE a rockylinux:9 container
# with the OLD and NEW openwatch RPMs mounted at /rpms/old and /rpms/new.
#
# It proves the real upgrade path: install the OLD package, stand up a
# database, roll it back one migration to simulate a prior version, then
# `rpm -U` the NEW package and confirm the package's %post scriptlet (with
# $1=2) migrated the DB to head and took a pre-upgrade backup — with a
# systemctl shim standing in for systemd (no init in the container).
#
# Migration-number-agnostic: the host driver derives the current head
# migration's goose version_id (HEAD_VER) and its `-- +goose Down` SQL
# (HEAD_DOWN) from the source tree and passes them in via the environment, so
# this test does not hardcode any migration number or table name and survives
# every new migration. It asserts the upgrade advanced the schema by exactly
# the head migration (HEAD_VER-1 -> HEAD_VER), took a backup, and stop/started
# the service.
#
# Invoke from the host via packaging/tests/run-upgrade-container-test.sh.
set -euo pipefail

: "${HEAD_VER:?HEAD_VER must be passed in (head migration goose version_id)}"
: "${HEAD_DOWN:?HEAD_DOWN must be passed in (head migration -- +goose Down SQL)}"
PREV_VER=$((HEAD_VER - 1))

echo "### prerequisites"
dnf install -y -q postgresql-server postgresql openssl findutils >/dev/null

echo "### start postgres (no systemd)"
PGDATA=/var/lib/pgsql/data
mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql
su postgres -c "initdb -D $PGDATA" >/dev/null
su postgres -c "pg_ctl -D $PGDATA -o '-c listen_addresses=127.0.0.1 -p 55432' -l /tmp/pg.log -w start" \
    || { echo '--- pg log ---'; cat /tmp/pg.log; exit 1; }
su postgres -c "psql -p 55432 -q -c \"CREATE USER ow PASSWORD 'ow' SUPERUSER;\""
su postgres -c "createdb -p 55432 -O ow owdb"
DSN="postgres://ow:ow@127.0.0.1:55432/owdb?sslmode=disable"  # pragma: allowlist secret  (throwaway container-local Postgres)

echo "### systemctl shim (records the helper's stop/start)"
# Overwrite the real systemctl: there is no systemd init in the container, and
# RPM scriptlets run with a restricted PATH (/sbin:/bin:/usr/sbin:/usr/bin)
# that excludes /usr/local/bin, so the shim must live in /usr/bin to be seen.
printf '#!/bin/sh\necho "$@" >> /tmp/systemctl.log\nexit 0\n' > /usr/bin/systemctl
chmod +x /usr/bin/systemctl
: > /tmp/systemctl.log

echo "### install OLD package (release 1)"
rpm -i --nodeps /rpms/old/openwatch-*.rpm
echo "OPENWATCH_DATABASE_DSN=$DSN" > /etc/openwatch/secrets.env

# Simulate an operator who replaced the demo TLS cert with their own. It MUST
# survive the upgrade — including the transition from a release that shipped
# the cert in its payload (the cert/key are %ghost in current packages, so rpm
# must not reclaim the operator's file). release-package-build C-05 / AC-22.
echo "OPERATOR-TLS-CERT-SENTINEL-DO-NOT-CLOBBER" > /etc/openwatch/tls/cert.pem
echo "OPERATOR-TLS-KEY-SENTINEL"                 > /etc/openwatch/tls/key.pem

echo "### bring DB to head, then roll back the head migration ($HEAD_VER) to simulate the prior version"
set -a; . /etc/openwatch/secrets.env; set +a
openwatch migrate >/dev/null
# Reverse exactly the head migration using its own `-- +goose Down` SQL, then
# forget its goose bookkeeping row so the NEW package's %post re-applies it.
PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -q -c "$HEAD_DOWN"
PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -q \
    -c "DELETE FROM goose_db_version WHERE version_id=$HEAD_VER;"
before=$(PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -tAc 'SELECT max(version_id) FROM goose_db_version')
echo "BEFORE upgrade: version=$before (expected prior=$PREV_VER, head=$HEAD_VER)"
: > /tmp/systemctl.log

echo "### UPGRADE: rpm -U the NEW package (release 2) — triggers %post with \$1=2"
rpm -U --nodeps /rpms/new/openwatch-*.rpm

echo "### results"
after=$(PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -tAc 'SELECT max(version_id) FROM goose_db_version')
echo "AFTER  upgrade: version=$after (expected head=$HEAD_VER)"
echo "systemctl during upgrade: $(tr '\n' ',' < /tmp/systemctl.log)"
echo "backups: $(ls /var/lib/openwatch/backups/ 2>/dev/null || echo none)"

echo "### assertions"
fail=0
[ "$before" = "$PREV_VER" ] || { echo "FAIL: pre-upgrade version $before != prior $PREV_VER"; fail=1; }
[ "$after" = "$HEAD_VER" ]  || { echo "FAIL: post-upgrade version $after != head $HEAD_VER (migration did not apply)"; fail=1; }
ls /var/lib/openwatch/backups/openwatch-pre-upgrade-*.sql >/dev/null 2>&1 || { echo "FAIL: no pre-upgrade backup"; fail=1; }
grep -q "stop openwatch.service"  /tmp/systemctl.log || { echo "FAIL: service not stopped"; fail=1; }
grep -q "start openwatch.service" /tmp/systemctl.log || { echo "FAIL: service not restarted"; fail=1; }
grep -q "OPERATOR-TLS-CERT-SENTINEL-DO-NOT-CLOBBER" /etc/openwatch/tls/cert.pem 2>/dev/null \
    || { echo "FAIL: operator TLS cert was NOT preserved across the upgrade (cert.pem=$(head -1 /etc/openwatch/tls/cert.pem 2>/dev/null || echo MISSING))"; fail=1; }
grep -q "OPERATOR-TLS-KEY-SENTINEL" /etc/openwatch/tls/key.pem 2>/dev/null \
    || { echo "FAIL: operator TLS key was NOT preserved across the upgrade"; fail=1; }
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS - the package upgrade migrated $PREV_VER -> $HEAD_VER with a backup, a stop/start, and preserved the operator TLS cert"
else
    echo "RESULT: FAIL"
    exit 1
fi
