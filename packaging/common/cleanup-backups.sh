#!/usr/bin/env bash
# Prune old OpenWatch pre-upgrade database dumps. Run by the
# openwatch-backup-cleanup.timer. Keeps the most recent dump ALWAYS (so the
# last restore point is never lost) and deletes the rest older than
# BACKUP_RETENTION_DAYS.
set -uo pipefail

CONF=/etc/openwatch/upgrade.conf
BACKUP_DIR=/var/lib/openwatch/backups
BACKUP_RETENTION_DAYS=30
# shellcheck source=/dev/null
[ -f "$CONF" ] && . "$CONF"

[ -d "$BACKUP_DIR" ] || exit 0

# Newest first, so index 0 is the one we always keep. Dump filenames are
# package-controlled (openwatch-pre-upgrade-<ver>-<stamp>.sql, no spaces or
# newlines), so the ls-based sort is safe here.
# shellcheck disable=SC2012
mapfile -t dumps < <(ls -1t "$BACKUP_DIR"/openwatch-pre-upgrade-*.sql 2>/dev/null || true)
[ "${#dumps[@]}" -gt 1 ] || exit 0

idx=0
for f in "${dumps[@]}"; do
    if [ "$idx" -eq 0 ]; then
        idx=1
        continue # always keep the most recent dump
    fi
    if [ -n "$(find "$f" -maxdepth 0 -mtime "+${BACKUP_RETENTION_DAYS}" 2>/dev/null)" ]; then
        rm -f "$f" && echo "openwatch backup-cleanup: pruned $f"
    fi
done
