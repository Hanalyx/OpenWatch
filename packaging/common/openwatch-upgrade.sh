#!/usr/bin/env bash
# Apply pending OpenWatch DB migrations during a package UPGRADE, with an
# auto-backup restore point and a fail-safe service state. Invoked by the
# RPM %post / DEB postinst ONLY on upgrade (never on a fresh install — a
# fresh install has no database yet).
#
# Sequence (single-instance appliance model):
#   1. confirm the DB is reachable + already initialized (else skip, warn)
#   2. stop the service  -> never run the old binary against a new schema
#   3. `openwatch migrate --backup-dir`  -> pg_dump restore point, then apply
#      (each migration is transactional; a failure rolls back atomically)
#   4. success -> start the service
#      failure -> leave it STOPPED, print the restore path, exit non-zero so
#                 the package manager surfaces that the upgrade needs attention
#
# NOT `set -e`: we handle each failure explicitly to control the fail mode.
set -uo pipefail

# Config/secrets paths default to the production locations; the env
# overrides exist ONLY so the e2e test can point them at a scratch fixture.
CONF="${OPENWATCH_UPGRADE_CONF:-/etc/openwatch/upgrade.conf}"
AUTO_BACKUP=yes
BACKUP_DIR=/var/lib/openwatch/backups
# shellcheck source=/dev/null
[ -f "$CONF" ] && . "$CONF"

# The migrate command reads the same config the service does; load the DB
# secret the systemd unit normally injects so a root scriptlet can connect.
SECRETS="${OPENWATCH_SECRETS_ENV:-/etc/openwatch/secrets.env}"
if [ -f "$SECRETS" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$SECRETS"
    set +a
fi

log() { echo "openwatch upgrade: $*"; }
err() { echo "openwatch upgrade: $*" >&2; }

if ! command -v openwatch >/dev/null 2>&1; then
    err "openwatch binary not found; skipping auto-migrate."
    exit 0
fi

# DB reachable + initialized? `migrate --status` exits 0 when it can connect.
# If not (DB down / not yet provisioned), do NOT fail the package — warn and
# let the operator migrate manually once the DB is up.
if ! openwatch migrate --status >/dev/null 2>&1; then
    err "database not reachable — migrations were NOT applied."
    err "once the database is up, run:  openwatch migrate  &&  systemctl restart openwatch"
    exit 0
fi

log "stopping service for migration"
systemctl stop openwatch.service >/dev/null 2>&1 || :

args=()
if [ "${AUTO_BACKUP:-yes}" = "yes" ]; then
    args+=(--backup-dir "$BACKUP_DIR")
fi

if openwatch migrate "${args[@]}"; then
    log "migration succeeded; starting service"
    systemctl start openwatch.service >/dev/null 2>&1 || :
    exit 0
fi

# Fail-safe: migration failed (and rolled back — DDL is transactional). Leave
# the service stopped rather than run the new binary against an un-migrated
# schema, and tell the operator exactly how to recover.
err "MIGRATION FAILED. The openwatch service has been left STOPPED to avoid"
err "running against an un-migrated schema. Your data is intact (each"
err "migration runs in a transaction and rolled back)."
if [ "${AUTO_BACKUP:-yes}" = "yes" ]; then
    err "A pre-migration backup is in ${BACKUP_DIR}/ . To restore if needed:"
    err "    psql \"\$OPENWATCH_DATABASE_DSN\" < ${BACKUP_DIR}/openwatch-pre-upgrade-*.sql"
fi
err "After resolving the cause:  openwatch migrate  &&  systemctl start openwatch"
exit 1
