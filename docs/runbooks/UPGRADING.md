# Upgrading OpenWatch

OpenWatch upgrades are **one command**. The package post-install scriptlet
applies any pending database migrations automatically — taking a backup
restore point first — and restarts the service.

```bash
# RHEL / CentOS / Rocky / Alma / Fedora
sudo dnf update -y 'openwatch*' 'kensa-rules*'

# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade openwatch kensa-rules
```

That's it. On a single-instance install this is all an operator needs to do.

## What happens automatically (on upgrade)

The scriptlet runs **only on upgrade**, never on a fresh install, and does:

1. **Checks the database is reachable.** If it isn't, migrations are skipped
   with a warning (the upgrade doesn't fail) — run `openwatch migrate`
   manually once the DB is back, then `systemctl restart openwatch`.
2. **Stops the service** — so the new binary never runs against an old schema
   and vice versa.
3. **Backs up the database** with `pg_dump` to `/var/lib/openwatch/backups/`
   (this is your restore point; the password is passed to `pg_dump` via the
   environment, never on the command line).
4. **Applies pending migrations.** Each migration runs in a transaction, so a
   failure rolls back atomically — your data is never left half-migrated.
5. **On success → starts the service** on the new version.
   **On failure → leaves the service stopped**, prints the restore path, and
   exits non-zero so `dnf`/`apt` flag that the upgrade needs attention.

### Pre-flight (optional)

See what would change before upgrading:

```bash
sudo openwatch migrate --status
# -> "up to date — no migrations pending"  OR  "PENDING: N migration(s) ..."
```

## If a migration fails

The service is left **stopped** and your data is intact (the failed migration
rolled back). Recover with:

```bash
# 1. read the error in the dnf/apt output or:  journalctl -u openwatch
# 2. fix the cause, then re-apply:
sudo openwatch migrate
sudo systemctl start openwatch
# on Debian, also clear the half-configured state:
sudo dpkg --configure -a
```

### Restoring from the pre-upgrade backup (last resort)

```bash
ls -t /var/lib/openwatch/backups/      # newest dump first
sudo systemctl stop openwatch
# DSN is in /etc/openwatch/secrets.env (OPENWATCH_DATABASE_DSN)
psql "$OPENWATCH_DATABASE_DSN" < /var/lib/openwatch/backups/openwatch-pre-upgrade-<...>.sql
```

## Backups: location, retention, opt-out

- Dumps live in `/var/lib/openwatch/backups/`.
- A systemd timer (`openwatch-backup-cleanup.timer`, runs daily) prunes dumps
  older than `BACKUP_RETENTION_DAYS` (default 30) but **always keeps the most
  recent one**, so you never lose your last restore point.
- Tune behavior in `/etc/openwatch/upgrade.conf`:
  - `AUTO_BACKUP=yes|no` — set `no` only if you run your own verified
    pre-upgrade backups.
  - `BACKUP_DIR`, `BACKUP_RETENTION_DAYS`.

## Scope and limits

- **App schema migrations: automatic and safe** (this document).
- **Minor PostgreSQL / dependency updates**: handled by `dnf`/`apt` itself via
  package dependencies — nothing extra to do.
- **PostgreSQL MAJOR-version upgrade** (e.g. 15 → 16): **NOT** performed by the
  OpenWatch scriptlet. That is a data-directory migration (`pg_upgrade` or
  dump/restore) that needs both server versions and must be operator-supervised
  — doing it silently from a package upgrade risks the whole database. Plan it
  separately, with its own backup.
- **Brief downtime** during the migrate step is expected (the appliance model).
  Multi-instance / zero-downtime upgrades are out of scope.
