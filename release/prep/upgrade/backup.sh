# shellcheck shell=sh
# Step 1 (release-upgrade-steps): a fresh database dump, proven readable.
# Inputs: OW_DUMP (optional; the dump path to create). By default the name
# carries the host's own UTC time, so no time is typed.
: "${OW_DUMP:=$R/var/backups/openwatch/openwatch_$(date -u +%Y%m%dT%H%M%SZ).dump}"
step "backup directory" install -d -m 0700 "$(dirname "$OW_DUMP")"
step "dump does not exist yet" test ! -e "$OW_DUMP"
step "pg_dump" with_dsn sh -c 'exec pg_dump "$OPENWATCH_DATABASE_DSN" --format=custom --file="$1"' sh "$OW_DUMP"
step "pg_restore --list" pg_restore --list "$OW_DUMP"
step "dump digest" sha256sum -- "$OW_DUMP"
step "dump listing" ls -la -- "$OW_DUMP"
echo "BACKUP DONE: $OW_DUMP"
