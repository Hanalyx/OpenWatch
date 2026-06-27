# Upgrade procedure

**Last updated:** 2026-06-25 · **Applies to:** OpenWatch v0.2.0-rc series (Go single-binary)

This guide covers upgrading an OpenWatch deployment to a newer version. OpenWatch
ships as a single Go binary (`/usr/bin/openwatch`) that serves both the REST API
and the embedded web UI over HTTPS on port 8443, managed by the `openwatch.service`
systemd unit and backed by PostgreSQL. There is no container runtime, no separate
web tier, and no Redis/Celery to coordinate, so an upgrade is: install the new
package, apply migrations, restart the service.

There are two paths. The **automatic** path (below) is one command: the package
scriptlet backs up and migrates the database and restarts the service. The
**controlled (manual)** path gives you a step at a time and is the right choice
for production change windows. Both are documented here.

For first-time install and configuration, see the
[installation guide](INSTALLATION.md). For the database backup and restore
commands referenced below, see the [backup and recovery guide](BACKUP_RECOVERY.md). For
migration mechanics, see the [database migrations guide](DATABASE_MIGRATIONS.md).

> Version note: the current release line is a pre-release (the `0.2.0-rc`
> series). Treat upgrades between pre-release builds as potentially breaking and
> always back up first.

## Quick upgrade (automatic, recommended)

On a single-instance install an upgrade is **one command**. The package
post-install scriptlet applies any pending database migrations automatically —
taking a backup restore point first—and restarts the service.

```bash
# RHEL / CentOS / Rocky / Alma / Fedora
sudo dnf update -y 'openwatch*' 'kensa-rules*'

# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade openwatch kensa-rules
```

### What happens automatically (on upgrade)

The scriptlet runs **only on upgrade**, never on a fresh install, and does:

1. **Checks the database is reachable.** If it isn't, migrations are skipped
   with a warning (the upgrade doesn't fail)—run `openwatch migrate` manually
   once the DB is back, then `systemctl restart openwatch`.
2. **Stops the service**—so the new binary never runs against an old schema.
3. **Backs up the database** with `pg_dump` to `/var/lib/openwatch/backups/`
   (your restore point; the password is passed via the environment, never on the
   command line).
4. **Applies pending migrations.** Each runs in a transaction, so a failure
   rolls back atomically—data is never left half-migrated.
5. **On success → starts the service** on the new version.
   **On failure → leaves the service stopped**, prints the restore path, and
   exits non-zero so `dnf`/`apt` flag that the upgrade needs attention.

Preview what would change before upgrading:

```bash
sudo openwatch migrate --status
# -> "up to date — no migrations pending"  OR  "PENDING: N migration(s) ..."
```

### If an automatic migration fails

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

To restore the pre-upgrade dump instead, see [Rollback](#rollback).

### Backups: location, retention, opt-out

- Dumps live in `/var/lib/openwatch/backups/`.
- A systemd timer (`openwatch-backup-cleanup.timer`, daily) prunes dumps older
  than `BACKUP_RETENTION_DAYS` (default 30) but **always keeps the most recent
  one**, so you never lose your last restore point.
- Tune in `/etc/openwatch/upgrade.conf`: `AUTO_BACKUP=yes|no` (set `no` only if
  you run your own verified pre-upgrade backups), `BACKUP_DIR`,
  `BACKUP_RETENTION_DAYS`.

## Controlled (manual) upgrade

The remaining sections are the manual, step-at-a-time path—for production
change windows, multi-step validation, or when `AUTO_BACKUP=no`.

## Before you upgrade

Run through this checklist on the running host:

- [ ] Read the release notes for the target version.
- [ ] Confirm the service is healthy:
      `curl -k https://localhost:8443/api/v1/health`
      (expect `{"status":"healthy","db_connected":true,"version":"<version>"}`).
- [ ] Record the current version: `openwatch --version`.
- [ ] Record the current migration version (printed at the end of
      `openwatch migrate`, or query `goose_db_version`—see
      [Record the migration version](#record-the-migration-version)).
- [ ] Take a full PostgreSQL backup (see the [backup and recovery guide](BACKUP_RECOVERY.md)).
- [ ] Back up `/etc/openwatch/` (config, `secrets.env`, and `tls/`).
- [ ] Confirm free disk space with `df -h /var/lib/openwatch /var`.
- [ ] Schedule a maintenance window and notify users.

### Record the migration version

Migrations are tracked in the `goose_db_version` table. Capture the current
version so you know what the database looked like before the upgrade:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
  psql "$OPENWATCH_DATABASE_DSN" \
  -c "SELECT max(version_id) FROM goose_db_version;"
```

## How migrations work

`openwatch migrate` applies every pending up-migration using goose, then prints the resulting version and the
list of migration files. The command is idempotent: it applies only migrations
not yet recorded in `goose_db_version`, so it is safe to re-run.

There is no down-migration or `downgrade` subcommand. Migrations are forward-only.
To revert a schema change you restore the pre-upgrade database backup (see
[Rollback](#rollback)). Plan upgrades accordingly: the database backup is your
rollback path, not a reverse migration.

## Standard upgrade

These steps assume the OpenWatch user is `openwatch` and the database DSN is in
`/etc/openwatch/secrets.env` as `OPENWATCH_DATABASE_DSN`, matching the install
guide.

### Step 1—Back up the database

Take a fresh dump immediately before the upgrade (commands in
the [backup and recovery guide](BACKUP_RECOVERY.md)). Do not skip this: it is the only
rollback path for schema changes.

### Step 2—Stop the service

```bash
sudo systemctl stop openwatch
```

Stopping the service quiesces the API, the embedded worker loops, and the
PostgreSQL-native job queue before the schema changes.

### Step 3—Install the new package

On RHEL-family hosts (RPM):

```bash
sudo dnf upgrade ./openwatch-<new-version>.<arch>.rpm
```

On Debian/Ubuntu hosts (DEB):

```bash
sudo apt install ./openwatch_<new-version>_<arch>.deb
```

Both packages replace `/usr/bin/openwatch`, refresh the systemd unit, and run
`systemctl daemon-reload` in their post-install scripts. The config files under
`/etc/openwatch/` are marked as config files and are not overwritten on upgrade;
review the new package's default `openwatch.toml` against yours for new keys.

Confirm the binary version:

```bash
openwatch --version
```

### Step 4—Validate the resolved config

Catch missing or renamed config keys before starting the server:

```bash
sudo -u openwatch openwatch --config /etc/openwatch/openwatch.toml check-config
```

This prints the resolved configuration with secrets redacted and exits non-zero
if validation fails. Config layering, highest precedence first: CLI flags > env
vars (`OPENWATCH_<SECTION>_<KEY>`) > the TOML file > built-in defaults.

### Step 5—Apply migrations

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
  openwatch --config /etc/openwatch/openwatch.toml migrate
```

The command prints the current version, the count of migration files, and each
filename, then `migrations applied`. If it fails, the service is still stopped —
fix the cause or restore the backup (see [Rollback](#rollback)) before starting.

### Step 6—Start the service

```bash
sudo systemctl start openwatch
sudo systemctl status openwatch
```

### Step 7—Verify the upgrade

```bash
# Health and reported version.
curl -k https://localhost:8443/api/v1/health
curl -k https://localhost:8443/api/v1/version

# Watch the structured logs for the startup line and any errors.
sudo journalctl -u openwatch -n 100 --no-pager

# Confirm the database is reachable from the host.
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
  psql "$OPENWATCH_DATABASE_DSN" -c "SELECT 1;"
```

The `version` field in both `/api/v1/health` and `/api/v1/version` should report
the new version. Sign in at `https://<host>:8443/` and confirm the UI loads.

## Rollback

Because migrations are forward-only, rolling back a release that changed the
schema means restoring the pre-upgrade database backup and reinstalling the
previous package.

### Code-only rollback (no migration ran)

If the upgrade failed before Step 5, or the target version applied no new
migrations, reinstall the previous package and restart:

```bash
sudo systemctl stop openwatch
# RHEL family:
sudo dnf install ./openwatch-<old-version>.<arch>.rpm
# Debian/Ubuntu:
sudo apt install ./openwatch_<old-version>_<arch>.deb
sudo systemctl start openwatch
curl -k https://localhost:8443/api/v1/health
```

### Full rollback (migrations ran)

If Step 5 applied new migrations, restore the pre-upgrade database backup, then
reinstall the previous binary:

```bash
# 1. Stop the service.
sudo systemctl stop openwatch

# 2. Restore the pre-upgrade database dump
#    (exact pg_restore/psql commands: BACKUP_RECOVERY.md).

# 3. Reinstall the previous package (see Code-only rollback above).

# 4. Start and verify.
sudo systemctl start openwatch
curl -k https://localhost:8443/api/v1/health
```

Keep the pre-upgrade dump until you have validated the upgrade in production
(at least several days).

## Updating Kensa compliance rules

Kensa is the SSH-based compliance engine, integrated as a Go dependency; its native YAML rules are compiled into the `openwatch`
binary. Rules therefore travel with
the binary—installing a new OpenWatch package is what updates the bundled
rule set. There is no separate rule-pull or out-of-band rule-sync step. For the
Kensa/OpenWatch responsibility boundary, see
the Kensa scanning engine.

## Upgrading PostgreSQL

PostgreSQL is provisioned and operated independently of the OpenWatch package
(see the [installation guide](INSTALLATION.md)). A **PostgreSQL major-version upgrade**
(for example 15 to 16) is **never** performed by the OpenWatch package scriptlet—it is
a data-directory migration (`pg_upgrade` or dump/restore) that needs both server
versions and must be operator-supervised; doing it silently from a package
upgrade would risk the whole database. Plan it separately, with its own backup:
follow your distribution's procedure, stop `openwatch.service` first so no
connections are open, then start it again afterward and run the
[verification](#step-7--verify-the-upgrade) checks. (Minor PostgreSQL and
dependency updates are handled by `dnf`/`apt` via package dependencies—nothing
extra to do.)

## Troubleshooting

### Service fails to start after upgrade

```bash
sudo systemctl status openwatch
sudo journalctl -u openwatch -n 200 --no-pager
```

Common causes:

- Invalid or incomplete config—run
  `sudo -u openwatch openwatch --config /etc/openwatch/openwatch.toml check-config`.
- Missing database secret—confirm `/etc/openwatch/secrets.env` defines
  `OPENWATCH_DATABASE_DSN`.
- Missing signing/encryption key material—the server refuses to start without
  `[identity].jwt_private_key` and `[identity].credential_key_file`; the log line
  names the missing key.
- Schema not migrated—run Step 5.

### `migrate` fails

Re-run the command and read the error. The most common cause is the database
being unreachable or the DSN being wrong; verify with
`psql "$OPENWATCH_DATABASE_DSN" -c "SELECT 1;"`. Because migrations are
idempotent, a partial run can be retried after the underlying issue is fixed. If
the schema is in an unexpected state, restore the pre-upgrade backup.

### Health endpoint returns 503

A 503 from `/api/v1/health` means the service started but a dependency is
unhealthy—typically the database. Check `db_connected` in the response body
and confirm PostgreSQL is running and reachable.

## Post-upgrade checklist

- [ ] `/api/v1/health` returns `healthy` with `db_connected:true`.
- [ ] `/api/v1/version` reports the new version.
- [ ] `journalctl -u openwatch` shows a clean startup and no recurring errors.
- [ ] An administrator can sign in at `https://<host>:8443/`.
- [ ] A compliance scan completes end to end.
- [ ] The upgrade is recorded in your change log.
- [ ] The pre-upgrade backup is retained through the validation period.
