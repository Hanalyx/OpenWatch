# Upgrade procedure

**Last updated:** 2026-07-30 · **Applies to:** OpenWatch v0.8.0 (Eyrie)

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
[installation guide](../guides/INSTALLATION.md). For the database backup and restore
commands referenced below, see the [backup and recovery guide](BACKUP_RECOVERY.md). For
migration mechanics, see the [database migrations guide](DATABASE_MIGRATIONS.md).

> Always back up before upgrading; the upgrade path runs database migrations
> automatically. Check the version you are on with `openwatch --version` before
> you start, and again afterwards.

## Quick upgrade (automatic, recommended)

On a single-instance install an upgrade is **one command**. The package
post-install scriptlet applies any pending database migrations automatically, taking a backup restore point first, and restarts the service.

```bash
# RHEL / CentOS / Rocky / Alma / Fedora
sudo dnf update -y 'openwatch*' 'kensa-rules*'

# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade openwatch kensa-rules
```

### What happens automatically (on upgrade)

The scriptlet runs **only on upgrade**, never on a fresh install, and does:

1. **Checks the database is reachable.** If it isn't, migrations are skipped
   with a warning (the upgrade doesn't fail): run `openwatch migrate` manually
   once the DB is back, then `systemctl restart openwatch`.
2. **Stops the service**: so the new binary never runs against an old schema.
3. **Backs up the database** with `pg_dump` to `/var/lib/openwatch/backups/`
   (your restore point; the password is passed via the environment, never on the
   command line).
4. **Applies pending migrations.** Each runs in a transaction, so a failure
   rolls back atomically: data is never left half-migrated.
5. **On success → starts the service** on the new version.
   **On failure → leaves the service stopped**, prints the restore path, and
   exits non-zero so `dnf`/`apt` flag that the upgrade needs attention.

Preview what would change before upgrading:

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch migrate --status'
# -> "up to date — no migrations pending"  OR  "PENDING: N migration(s) ..."
```

### If an automatic migration fails

The service is left **stopped** and your data is intact (the failed migration
rolled back). Recover with:

```bash
# 1. read the error in the dnf/apt output or:  journalctl -u openwatch
# 2. fix the cause, then re-apply:
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch migrate'
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

The remaining sections are the step-at-a-time path for production change
windows and multi-step validation. Read this first, because it changes what
"manual" means here:

**Installing the package is the migration.** The RPM and DEB post-install
scriptlets run `/usr/lib/openwatch/openwatch-upgrade.sh` on every upgrade.
It stops the service, writes the pre-upgrade dump, applies migrations, and
starts the service, all inside the package transaction. `AUTO_BACKUP=no`
disables only the dump. There is no setting that defers the migration or the
restart to a later step. Verified on a rockylinux:9 host upgraded from 0.7.1
to 0.8.0-rc.3: with the service stopped by hand before `dnf install`, the
schema was at the new version and the service was `active` the moment `dnf`
returned, before any later step ran.

So the transaction boundary is Step 3. Everything before it is preparation
you control; everything after it is verification of a migration that has
already happened. A rollback decision is made from the observed schema
version (`openwatch migrate --status`), never from which step you reached.
If your change process requires a migration that runs as a separate,
approved action, that needs a control the scriptlet does not have today;
raise it as a product request rather than expecting the steps below to
provide it.

## Before you upgrade

Run through this checklist on the running host:

- [ ] Read the release notes for the target version.
- [ ] Confirm the service is healthy:
      `curl -k https://localhost:8443/api/v1/health`
      (expect `{"status":"healthy","db_connected":true,"version":"<version>"}`).
- [ ] Record the current version: `openwatch --version`.
- [ ] Record the current migration version (printed at the end of
      `openwatch migrate`, or query `goose_db_version`: see
      [Record the migration version](#record-the-migration-version)).
- [ ] Take a full PostgreSQL backup (see the [backup and recovery guide](BACKUP_RECOVERY.md)).
- [ ] Back up `/etc/openwatch/` (config, `secrets.env`, and `tls/`).
- [ ] Confirm free disk space with `df -h /var/lib/openwatch /var`.
- [ ] Schedule a maintenance window and notify users.

### Record the migration version

Migrations are tracked in the `goose_db_version` table. Capture the current
version so you know what the database looked like before the upgrade:

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
  psql "$OPENWATCH_DATABASE_DSN" -c "SELECT max(version_id) FROM goose_db_version;"'
```

## How migrations work

`openwatch migrate` applies every pending up-migration using goose, then prints the resulting version and the
list of migration files. The command is idempotent: it applies only migrations
not yet recorded in `goose_db_version`, so it is safe to re-run.

There is no down-migration or `downgrade` subcommand. Migrations are forward-only.
To revert a schema change you restore the pre-upgrade database backup (see
[Rollback](#rollback)). Plan upgrades accordingly: the database backup is your
rollback path, not a reverse migration.

### Migrations that lock a table

A migration that changes an existing column's type rewrites the whole table and
holds an ACCESS EXCLUSIVE lock while it does. Reads and writes of that table
block until it finishes. Adding a column or an index to a large table can also
take real time, so measure rather than assume.

Plan for the downtime. The service is stopped during a standard upgrade anyway
(Step 2), so the practical question is how long Step 5 takes.

| Migration | Table | Why it locks |
|---|---|---|
| 0062 | `posture_snapshots` | `score_pct` changes from `REAL` to `numeric(4,1)`. A compliance score is shown to one decimal and `REAL` cannot hold one. |

`posture_snapshots` holds one row per host, per day, per framework series, so
the rewrite time scales with fleet size times how much history you keep. To
estimate before you upgrade:

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
  psql "$OPENWATCH_DATABASE_DSN" -c "SELECT count(*) AS rows,
             pg_size_pretty(pg_total_relation_size('\''posture_snapshots'\'')) AS size
        FROM posture_snapshots;"'
```

How long the rewrite takes depends on the row count, the indexes, your storage,
WAL settings, and what else the database is doing. There is no row count that
predicts it. **Time the migration against a restored copy of your own database
before you upgrade production**, and schedule a maintenance window based on what
you measure. The hourly posture rollup simply runs late afterward; nothing is
lost.

## Standard upgrade

These steps assume the OpenWatch user is `openwatch` and the database DSN is in
`/etc/openwatch/secrets.env` as `OPENWATCH_DATABASE_DSN`, matching the install
guide.

### Step 1: Back up the database

Take a fresh dump immediately before the upgrade (commands in
the [backup and recovery guide](BACKUP_RECOVERY.md)). Do not skip this: it is the only
rollback path for schema changes.

### Step 2: Stop the service and record the state you can roll back to

```bash
sudo systemctl stop openwatch
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch migrate --status'
```

Stopping the service quiesces the API, the embedded worker loops, and the
PostgreSQL-native job queue. The scriptlet stops it again anyway; doing it
here means the last writes happen before your Step 1 backup is taken, not
after. Write down the migration version `migrate --status` prints: it is the
number that decides which rollback applies later.

### Step 3: Install the new package

On RHEL-family hosts (RPM):

```bash
sudo dnf upgrade ./openwatch-<new-version>.<arch>.rpm
```

On Debian/Ubuntu hosts (DEB):

```bash
sudo apt install ./openwatch_<new-version>_<arch>.deb
```

Both packages replace `/usr/bin/openwatch`, refresh the systemd unit, run
`systemctl daemon-reload`, and then run the upgrade scriptlet: dump (unless
`AUTO_BACKUP=no`), migrate, start. When this command returns, the schema is
at the new version and the service is running, or the scriptlet has left it
stopped and printed the restore path. The config files under `/etc/openwatch/`
are marked as config files and are not overwritten on upgrade; review the
new package's default `openwatch.toml` against yours for new keys.

Confirm the binary, the schema, and the service state:

```bash
openwatch --version
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch migrate --status'
sudo systemctl is-active openwatch
ls -t /var/lib/openwatch/backups/ | head -1     # the pre-upgrade dump the scriptlet wrote
```

### Step 4: Validate the resolved config

Catch missing or renamed config keys before starting the server:

```bash
sudo -u openwatch openwatch --config /etc/openwatch/openwatch.toml check-config
```

This prints the resolved configuration with secrets redacted and exits non-zero
if validation fails. Config layering, highest precedence first: CLI flags > env
vars (`OPENWATCH_<SECTION>_<KEY>`) > the TOML file > built-in defaults.

### Step 5: Confirm the migration the scriptlet applied

The scriptlet already ran `openwatch migrate`. Running it again is a safe
no-op and is the check that it finished:

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
  openwatch --config /etc/openwatch/openwatch.toml migrate'
```

It prints the current version and `no migrations to run` when the scriptlet
completed. If instead it applies migrations now, the scriptlet did not finish
(it leaves the service stopped and prints the restore path when a migration
fails); read `journalctl -u openwatch` and the `dnf`/`apt` output before
going on.

### Step 6: Confirm the service is up

The scriptlet started it. If it is not active, the scriptlet stopped on a
failed migration: do not start it by hand against an unfinished schema; go to
[Rollback](#rollback).

```bash
sudo systemctl status openwatch
```

### Step 7: Verify the upgrade

```bash
# Health and reported version.
curl -k https://localhost:8443/api/v1/health
curl -k https://localhost:8443/api/v1/version

# Watch the structured logs for the startup line and any errors.
sudo journalctl -u openwatch -n 100 --no-pager

# Confirm the database is reachable from the host, as the service user.
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; psql "$OPENWATCH_DATABASE_DSN" -c "SELECT 1;"'
```

The `version` field in both `/api/v1/health` and `/api/v1/version` should report
the new version. Sign in at `https://<host>:8443/` and confirm the UI loads.

## Rollback

Because migrations are forward-only, rolling back a release that changed the
schema means restoring the pre-upgrade database backup and reinstalling the
previous package.

Which rollback applies is decided by the schema, not by the step you reached:
compare `openwatch migrate --status` now with the version you recorded in
Step 2. Same number, code-only rollback. Higher number, full rollback.

### Code-only rollback (the schema did not advance)

If the target version applied no new migrations (the version recorded in
Step 2 is unchanged), reinstall the previous package. The previous package's
scriptlet runs too, finds nothing to migrate, and starts the service:

```bash
sudo systemctl stop openwatch
# RHEL family:
sudo dnf install ./openwatch-<old-version>.<arch>.rpm
# Debian/Ubuntu:
sudo apt install ./openwatch_<old-version>_<arch>.deb
sudo systemctl start openwatch
curl -k https://localhost:8443/api/v1/health
```

### Full rollback (the schema advanced)

If the schema version is higher than the one recorded in Step 2, the new
binary's migrations ran during Step 3. Restore the pre-upgrade database dump
(the scriptlet's, in `/var/lib/openwatch/backups/`, or your Step 1 dump),
then reinstall the previous binary:

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

Kensa is two things with two versions. The engine is a Go dependency compiled
into the `openwatch` binary; `GET /api/v1/version` reports it in the `kensa`
field. The rules are the separate `kensa-rules` package, installed at
`/usr/share/kensa/rules` and loaded from there when the service starts. The
`openwatch` package depends on `kensa-rules` but does not pin its version, so
upgrading one does not upgrade the other.

To update the rules, upgrade the package and restart the service so it loads
the new corpus:

```bash
sudo dnf upgrade kensa-rules        # apt: sudo apt install --only-upgrade kensa-rules
sudo systemctl restart openwatch
rpm -q kensa-rules                  # apt: dpkg -s kensa-rules | grep Version
```

There is no rule-pull or rule-sync step, and no rule is compiled into the
binary. See [Scanning and compliance](../guides/SCANNING_AND_COMPLIANCE.md)
for how OpenWatch invokes Kensa during a scan.

## Upgrading PostgreSQL

PostgreSQL is provisioned and operated independently of the OpenWatch package
(see the [installation guide](../guides/INSTALLATION.md)). A **PostgreSQL major-version upgrade**
(for example 15 to 16) is **never** performed by the OpenWatch package scriptlet. It is
a data-directory migration (`pg_upgrade` or dump/restore) that needs both server
versions and must be operator-supervised; doing it silently from a package
upgrade would risk the whole database. Plan it separately, with its own backup:
follow your distribution's procedure, stop `openwatch.service` first so no
connections are open, then start it again afterward and run the
[verification](#step-7-verify-the-upgrade) checks. (Minor PostgreSQL and
dependency updates are handled by `dnf`/`apt` via package dependencies: nothing
extra to do.)

## Troubleshooting

### Service fails to start after upgrade

```bash
sudo systemctl status openwatch
sudo journalctl -u openwatch -n 200 --no-pager
```

Common causes:

- Invalid or incomplete config: run
  `sudo -u openwatch openwatch --config /etc/openwatch/openwatch.toml check-config`.
- Missing database secret: confirm `/etc/openwatch/secrets.env` defines
  `OPENWATCH_DATABASE_DSN`.
- Missing signing/encryption key material. The server refuses to start without
  `[identity].jwt_private_key` and `[identity].credential_key_file`; the log line
  names the missing key.
- Schema not migrated: run Step 5.

### `migrate` fails

Re-run the command and read the error. The most common cause is the database
being unreachable or the DSN being wrong; verify with
`psql "$OPENWATCH_DATABASE_DSN" -c "SELECT 1;"`. Because migrations are
idempotent, a partial run can be retried after the underlying issue is fixed. If
the schema is in an unexpected state, restore the pre-upgrade backup.

### Health endpoint returns 503

A 503 from `/api/v1/health` means the service started and cannot reach its
database. The body is the standard error envelope, not the health object:

```json
{"error":{"code":"server.unavailable","fault":"server","human_message":"database is not reachable","retryable":true}}
```

There is no `db_connected` field in it; that field appears only on a 200.
Confirm PostgreSQL is running and that the DSN in `/etc/openwatch/secrets.env`
still names a reachable server with the right password.

## Post-upgrade checklist

- [ ] `/api/v1/health` returns `healthy` with `db_connected:true`.
- [ ] `/api/v1/version` reports the new version.
- [ ] `journalctl -u openwatch` shows a clean startup and no recurring errors.
- [ ] An administrator can sign in at `https://<host>:8443/`.
- [ ] A compliance scan completes end to end.
- [ ] The upgrade is recorded in your change log.
- [ ] The pre-upgrade backup is retained through the validation period.
