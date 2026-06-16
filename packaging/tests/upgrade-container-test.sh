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
# Invoke from the host via packaging/tests/run-upgrade-container-test.sh.
set -euo pipefail

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
DSN="postgres://ow:ow@127.0.0.1:55432/owdb?sslmode=disable"

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

echo "### bring DB to head, then roll back migration 0035 to simulate the prior version"
set -a; . /etc/openwatch/secrets.env; set +a
openwatch migrate >/dev/null
PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -q \
    -c "DROP TABLE IF EXISTS host_connection_profile CASCADE; DELETE FROM goose_db_version WHERE version_id=35;"
before=$(PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -tAc 'SELECT max(version_id) FROM goose_db_version')
hcp_before=$(PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -tAc "SELECT to_regclass('host_connection_profile')")
echo "BEFORE upgrade: version=$before host_connection_profile=${hcp_before:-<absent>}"
: > /tmp/systemctl.log

echo "### UPGRADE: rpm -U the NEW package (release 2) — triggers %post with \$1=2"
rpm -U --nodeps /rpms/new/openwatch-*.rpm

echo "### results"
after=$(PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -tAc 'SELECT max(version_id) FROM goose_db_version')
hcp_after=$(PGPASSWORD=ow psql -h 127.0.0.1 -p 55432 -U ow -d owdb -tAc "SELECT to_regclass('host_connection_profile')")
echo "AFTER  upgrade: version=$after host_connection_profile=${hcp_after:-<absent>}"
echo "systemctl during upgrade: $(tr '\n' ',' < /tmp/systemctl.log)"
echo "backups: $(ls /var/lib/openwatch/backups/ 2>/dev/null || echo none)"

echo "### assertions"
fail=0
[ "$before" = "34" ] || { echo "FAIL: pre-upgrade version != 34"; fail=1; }
[ "$after" = "35" ]  || { echo "FAIL: post-upgrade version != 35 (migration did not apply)"; fail=1; }
[ "$hcp_after" = "host_connection_profile" ] || { echo "FAIL: 0035 table not created by the upgrade"; fail=1; }
ls /var/lib/openwatch/backups/openwatch-pre-upgrade-*.sql >/dev/null 2>&1 || { echo "FAIL: no pre-upgrade backup"; fail=1; }
grep -q "stop openwatch.service"  /tmp/systemctl.log || { echo "FAIL: service not stopped"; fail=1; }
grep -q "start openwatch.service" /tmp/systemctl.log || { echo "FAIL: service not restarted"; fail=1; }
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS - the package upgrade migrated 34 -> 35 with a backup and a stop/start"
else
    echo "RESULT: FAIL"
    exit 1
fi
