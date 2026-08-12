#!/usr/bin/env bash
# Runs INSIDE a systemd container. Installs the previous GA, provisions it by
# hand, then upgrades to the candidate with both packages in one transaction
# and proves the result is a serving instance on the SAME database.
#
# Gate evidence for release/gates.toml U2.
#
# This is a different claim from the existing upgrade test, which builds two
# synthetic releases of the same version, shims systemctl, and proves the
# scriptlet mechanism (gate U1). This one runs the real published previous GA
# against the real candidate under real systemd, which is what an operator
# actually does.
#
# The previous GA is provisioned by hand because it has to be: `openwatch
# setup` did not exist in v0.6.0. Every upgrading operator therefore has an
# install built from the manual procedure, which is what this reproduces.
#
# Expects, from the driver:
#   OLD_DIR    directory holding the previous GA packages
#   NEW_DIR    directory holding the candidate packages
#   PKG_KIND   deb | rpm
#   OLD_VER    the previous GA version string, e.g. 0.6.0
#   NEW_VER    the candidate version string, e.g. 0.7.0
set -euo pipefail

: "${OLD_DIR:?}" "${NEW_DIR:?}" "${PKG_KIND:?}" "${OLD_VER:?}" "${NEW_VER:?}"

# A failure with no diagnostics is a failure someone has to reproduce by hand,
# and this runs in CI where nobody can attach to the container.
diagnose() {
    echo "--- systemctl status openwatch ---" >&2
    systemctl status openwatch --no-pager 2>&1 | head -20 >&2 || true
    echo "--- journalctl -u openwatch ---" >&2
    journalctl -u openwatch -n 30 --no-pager 2>&1 | tail -30 >&2 || true
}
fail() { echo "FAIL: $*" >&2; diagnose; exit 1; }

# curl exits non-zero when nothing is listening, and under set -e that kills
# the script with curl's status before any assertion runs, which reads as a
# harness crash rather than a product failure. Capture, then judge.
health() { curl -sk --max-time 20 https://127.0.0.1:8443/api/v1/health 2>/dev/null || true; }

echo ">> waiting for systemd"
for _ in $(seq 1 60); do
    case "$(systemctl is-system-running 2>/dev/null || true)" in
        running|degraded) break ;;
    esac
    sleep 1
done

# Not quiet. The package manager's quiet mode also suppresses scriptlet
# output, so a %post failure reduces to "Error in POSTIN scriptlet" with no
# reason, which is the least actionable message in the whole pipeline.
install_pkgs() {
    if [ "$PKG_KIND" = deb ]; then
        apt-get install -y "$1"/openwatch_*.deb "$1"/kensa-rules_*.deb
    else
        dnf install -y "$1"/openwatch-*.rpm "$1"/kensa-rules-*.rpm
    fi
}

# Deliberately the distribution default, even though it is below the floor
# setup now enforces. That floor governs what setup BUILDS; this test is about
# what already exists in the field, and v0.6.0 accepted PostgreSQL 13, so real
# installs are running it. Provisioning a supported version here would test a
# state few upgrading operators are actually in.
echo ">> installing PostgreSQL and the previous GA ($OLD_VER)"
if [ "$PKG_KIND" = deb ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl ca-certificates postgresql postgresql-contrib >/dev/null
else
    # Not curl: the RHEL-family images ship curl-minimal, which provides the
    # binary and conflicts with the full package.
    command -v curl >/dev/null || dnf install -y -q curl >/dev/null
    dnf install -y -q postgresql-server postgresql-contrib >/dev/null
    [ -f /var/lib/pgsql/data/PG_VERSION ] || postgresql-setup --initdb >/dev/null
fi
systemctl enable --now postgresql >/dev/null 2>&1 || fail "postgresql did not start"
for _ in $(seq 1 30); do runuser -u postgres -- psql -tAqc 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done

install_pkgs "$OLD_DIR"
openwatch --version | head -1

# Provision by hand: this is the manual procedure the v0.6.0 guide documented,
# and the state every upgrading operator is actually in.
echo ">> provisioning the previous GA by hand (setup did not exist in $OLD_VER)"
runuser -u postgres -- psql -tAqc \
    "SET password_encryption='scram-sha-256'; CREATE ROLE openwatch WITH LOGIN PASSWORD 'u2pass';"  # pragma: allowlist secret
runuser -u postgres -- psql -tAqc "CREATE DATABASE openwatch OWNER openwatch;"
HBA="$(runuser -u postgres -- psql -tAqc 'SHOW hba_file')"
printf 'host openwatch openwatch 127.0.0.1/32 scram-sha-256\nhost openwatch openwatch ::1/128 scram-sha-256\n%s\n' \
    "$(cat "$HBA")" > "$HBA.new" && mv "$HBA.new" "$HBA"
chown postgres:postgres "$HBA"; chmod 640 "$HBA"
systemctl reload postgresql
mkdir -p /etc/openwatch
DSN="postgres://openwatch:u2pass@127.0.0.1:5432/openwatch?sslmode=disable"  # pragma: allowlist secret
echo "OPENWATCH_DATABASE_DSN=$DSN" > /etc/openwatch/secrets.env
chgrp openwatch /etc/openwatch/secrets.env && chmod 640 /etc/openwatch/secrets.env
OPENWATCH_DATABASE_DSN="$DSN" openwatch migrate >/dev/null || fail "migrating the previous GA failed"

before="$(runuser -u postgres -- psql -d openwatch -tAqc 'SELECT max(version_id) FROM goose_db_version')"
echo "   schema before upgrade: $before"

# A marker in the database itself. If the upgrade drops and recreates rather
# than migrating in place, this vanishes -- which is the difference between an
# upgrade and a reinstall that happens to end up healthy.
#
# Created as the APPLICATION role, not the superuser. The pre-upgrade backup
# runs pg_dump as openwatch, and a table owned by postgres makes it fail with
# "permission denied for table u2_marker" -- the harness breaking the upgrade
# it is trying to observe, and reading exactly like a product defect.
PGPASSWORD=u2pass psql -h 127.0.0.1 -U openwatch -d openwatch -tAqc \
    "CREATE TABLE u2_marker(note text); INSERT INTO u2_marker VALUES ('survived-from-$OLD_VER');" >/dev/null

systemctl enable --now openwatch >/dev/null 2>&1 || fail "the previous GA service did not start"
for _ in $(seq 1 30); do
    curl -sk --max-time 5 https://127.0.0.1:8443/api/v1/health 2>/dev/null | grep -q db_connected && break
    sleep 2
done
old_health="$(health)"
echo "   $OLD_VER health: $old_health"
case "$old_health" in
    *"\"version\":\"$OLD_VER\""*) ;;
    *) fail "the previous GA is not serving $OLD_VER: $old_health" ;;
esac

echo ">> upgrading to the candidate ($NEW_VER), both packages in one transaction"
install_pkgs "$NEW_DIR"

echo ">> asserting the upgrade"
for _ in $(seq 1 45); do
    curl -sk --max-time 5 https://127.0.0.1:8443/api/v1/health 2>/dev/null | grep -q db_connected && break
    sleep 2
done
new_health="$(health)"
echo "   $NEW_VER health: $new_health"
case "$new_health" in
    *'"db_connected":true'*) ;;
    *) fail "the service is not serving after the upgrade: $new_health" ;;
esac
case "$new_health" in
    *"\"version\":\"$NEW_VER\""*) ;;
    *) fail "still reporting the old version after the upgrade: $new_health" ;;
esac

after="$(runuser -u postgres -- psql -d openwatch -tAqc 'SELECT max(version_id) FROM goose_db_version')"
echo "   schema after upgrade: $after"
[ "$after" -gt "$before" ] || fail "the schema did not advance ($before -> $after)"

marker="$(PGPASSWORD=u2pass psql -h 127.0.0.1 -U openwatch -d openwatch -tAqc 'SELECT note FROM u2_marker' 2>/dev/null || true)"
[ "$marker" = "survived-from-$OLD_VER" ] || \
    fail "the pre-upgrade marker is gone; the database was replaced, not migrated"

# The scriptlet takes a pg_dump before migrating. Without it a failed migration
# on a real fleet has no way back.
ls /var/lib/openwatch/backups/* >/dev/null 2>&1 || \
    fail "no pre-upgrade backup was taken"
echo "   backup: $(ls /var/lib/openwatch/backups/ | head -1)"

systemctl is-active --quiet openwatch || fail "the service is not active after the upgrade"
echo ">> OK: $OLD_VER upgraded to $NEW_VER in place, schema advanced, data preserved"
