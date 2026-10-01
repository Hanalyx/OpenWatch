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

> **Before you start**
> - **You need:** the [Before you upgrade](#before-you-upgrade) checklist done, including the full backup.
> - **Run as:** a sudo-capable administrator; the package scriptlet runs the migration as the service user.
> - **What changes:** the installed packages, the database schema (migrated inside the package transaction), and the service (stopped and started by the scriptlet).
> - **Verify with:** `openwatch --version` showing the new version and `/api/v1/health` returning `200`.
> - **Recover by:** [Rollback](#rollback): decided from the observed schema version, not from which step you reached.

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
   command line). The file is plain SQL, named
   `openwatch-pre-upgrade-<version being installed>-<UTC stamp>.sql`, and it
   carries no ownership or privilege statements. Restore it with `psql` as
   shown in [Full rollback](#full-rollback-the-schema-advanced); `pg_restore`
   cannot read it.
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

> **Before you start**
> - **You need:** the same checklist, a maintenance window, and the understanding that installing the package is the migration.
> - **Run as:** a sudo-capable administrator for the package and service steps; the `openwatch` service user with `secrets.env` loaded for `migrate --status`.
> - **What changes:** the same things as the quick upgrade; the extra steps observe, they do not defer the migration.
> - **Verify with:** the post-upgrade checklist at the end of this guide.
> - **Recover by:** [Rollback](#rollback).

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
- [ ] Create an API token with the `viewer` role (it has `scan:read`) and
      store it in a file only root can read. A rollback needs a token that
      existed **before** the upgrade: see [The API token](#the-api-token).
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
scriptlet runs too, finds nothing to migrate, and starts the service.

If the upgrade also installed a newer `kensa-rules`, roll it back in the same
command. The package manager refuses an `openwatch` whose engine is older
than the installed corpus, and changes nothing:

```bash
sudo systemctl stop openwatch
# RHEL family:
sudo dnf install ./openwatch-<old-version>.<arch>.rpm ./kensa-rules-<old-kensa-version>.noarch.rpm
# Debian/Ubuntu:
sudo apt install --allow-downgrades ./openwatch_<old-version>_<arch>.deb ./kensa-rules_<old-kensa-version>_all.deb
sudo systemctl start openwatch
curl -k https://localhost:8443/api/v1/health
```

### Full rollback (the schema advanced)

If the schema version is higher than the one recorded in Step 2, the new
binary's migrations ran during Step 3. You restore the pre-upgrade dump into
a new, empty database and then reinstall both previous packages.

> **Before you start**
> - **You need:** the scriptlet's dump for this upgrade in `/var/lib/openwatch/backups/`, the migration version you recorded in Step 2, both previous packages (`openwatch` and `kensa-rules`) as files on this host, and the API token you stored **before the upgrade** (see [The API token](#the-api-token)).
> - **Run as:** root, in a root shell (`sudo -i`). The blocks use `runuser` to act as `postgres`.
> - **What changes:** the current database is renamed to `openwatch_pre_rollback` and kept. A new `openwatch` database holds the restored dump. The previous packages are installed and the service restarts.
> - **Verify with:** the block's last line, `ROLLED BACK`, then the checks after it.
> - **Recover by:** [If the block stops](#if-the-block-stops). No block drops a database.

These steps use the scriptlet's dump. If you restore your own Step 1 dump
instead, use the commands that match its format: a custom-format `.dump`
restores with `pg_restore` as in the
[backup and recovery guide](BACKUP_RECOVERY.md).

The blocks assume PostgreSQL runs on this host, as `openwatch setup`
provisions it, so `postgres` can connect over the local socket. For an
external server, run the same SQL with an account that can create databases.

Three facts about the scriptlet's dump decide how it is restored:

- **It is plain SQL.** `pg_restore` refuses it. Restore it with `psql`.
- **It has no `DROP` or `CREATE DATABASE`.** Loading it into the current
  database fails on objects that already exist, so it goes into a new one.
- **It has no ownership statements.** Every object belongs to the role that
  runs the restore. Restoring as `postgres` without `SET ROLE openwatch`
  leaves the tables owned by `postgres`, and the service cannot migrate them
  later.

#### The API token

The block proves the rule library loaded by calling `GET /api/v1/rules`,
which needs a token with the `scan:read` permission. The built-in `viewer`
role has it.

**Create the token before you upgrade.** The rollback restores the database
as it was when the dump was taken, so it knows only the tokens that existed
then. A token created after the upgrade stops working the moment the restore
finishes, and the block then stops in step 6.

Create one with a `viewer` role while the previous version still runs, and
store it in a file only root can read:

```bash
# Sign in as an administrator first; $ADMIN_TOKEN is that session's token.
curl -sk -X POST https://localhost:8443/api/v1/tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid)" \
  -d '{"name":"rollback-check","role_id":"viewer"}'
# Copy the "token" value (it starts with owk_), then store it:
sudo sh -c 'umask 077; cat > /root/openwatch-rollback.token'
# paste the token, press Enter, then Ctrl-D
sudo ls -l /root/openwatch-rollback.token     # -rw------- root root
```

The response shows the token once. Revoke it after you have validated the
upgrade, or after a rollback.

#### The rollback block

List the dumps, then fill in the five values at the top of the block. The
dump's name carries the version you are rolling back FROM. Use absolute paths
for the package files. If you changed the listen port from `8443`, change
`URL` too.

```bash
ls -l /var/lib/openwatch/backups/
```

The block stops at the first failed check and changes nothing after it. It
installs the previous packages only after the dump, the restore, the
migration version and the ownership have all checked out. It then restarts
the service and proves the rule library loaded. When it stops, it says which
phase it stopped in and which recovery applies:

```bash
(
  set -euo pipefail
  DUMP='/var/lib/openwatch/backups/openwatch-pre-upgrade-<new-version>-<stamp>.sql'
  EXPECTED='<migration-version-from-step-2>'
  OLD_OPENWATCH='<absolute-path-to-previous-openwatch-package>'
  OLD_KENSA='<absolute-path-to-previous-kensa-rules-package>'
  TOKEN_FILE='<root-only-file-holding-an-owk-token-with-scan-read>'
  URL=https://localhost:8443
  ASIDE=openwatch_pre_rollback
  PSQL=(runuser -u postgres -- psql -X -q -tA -v ON_ERROR_STOP=1)
  PHASE=inputs
  on_stop() {
    echo "STOPPED at line $1, phase: $PHASE." >&2
    case "$PHASE" in
      inputs)
        echo "Nothing was changed. The service was not stopped." >&2 ;;
      database)
        echo "Package installation had NOT begun. Run the block under" >&2
        echo "'Recover before package installation'." >&2 ;;
      packages)
        echo "Package installation HAD begun. No database was swapped back." >&2
        systemctl stop openwatch || echo "Could not stop openwatch; stop it yourself." >&2
        echo "Inspect the packages, then run the matching block under" >&2
        echo "'Recover after package installation began'." >&2 ;;
    esac
  }
  trap 'on_stop $LINENO' ERR

  echo "1. checking the inputs"
  case "$DUMP $EXPECTED $OLD_OPENWATCH $OLD_KENSA $TOKEN_FILE" in
    *'<'*) echo "fill in the five values at the top first" >&2; false ;;
  esac
  [[ "$EXPECTED" =~ ^[0-9]+$ ]]
  test -r "$DUMP"
  test -r "$OLD_OPENWATCH"
  test -r "$OLD_KENSA"
  TOKEN=$(cat "$TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]
  HEAD=$(head -n 5 "$DUMP")
  [[ "$HEAD" == *"-- PostgreSQL database dump"* ]]
  TAIL=$(tail -n 5 "$DUMP")
  [[ "$TAIL" == *"-- PostgreSQL database dump complete"* ]]
  TAKEN=$("${PSQL[@]}" -c "SELECT count(*) FROM pg_database WHERE datname = '$ASIDE'")
  [ "$TAKEN" = 0 ]

  echo "2. stopping the service and setting the current database aside"
  PHASE=database
  systemctl stop openwatch
  OPEN=$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'openwatch'")
  if [ "$OPEN" != 0 ]; then
    echo "still connected to openwatch:" >&2
    "${PSQL[@]}" -c "SELECT pid, backend_type, usename, application_name, client_addr
        FROM pg_stat_activity WHERE datname = 'openwatch'" >&2 || :
    false
  fi
  "${PSQL[@]}" -c "ALTER DATABASE openwatch RENAME TO $ASIDE"
  runuser -u postgres -- createdb -O openwatch openwatch

  echo "3. restoring the dump as the openwatch role, in one transaction"
  "${PSQL[@]}" -1 -d openwatch -c 'SET ROLE openwatch' -f - < "$DUMP"

  echo "4. checking the migration version and ownership"
  GOT=$("${PSQL[@]}" -d openwatch -c 'SELECT max(version_id) FROM goose_db_version')
  [ "$GOT" = "$EXPECTED" ]
  FOREIGN=$("${PSQL[@]}" -d openwatch -c "SELECT count(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND pg_get_userbyid(c.relowner) <> 'openwatch'")
  [ "$FOREIGN" = 0 ]

  echo "5. installing the previous packages"
  PHASE=packages
  if command -v dnf >/dev/null; then
    dnf install -y "$OLD_OPENWATCH" "$OLD_KENSA"
  else
    apt-get install -y --allow-downgrades "$OLD_OPENWATCH" "$OLD_KENSA"
  fi

  echo "6. restarting the service and proving the rule library loaded"
  SINCE=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart openwatch
  READY=no
  DEADLINE=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if curl -skf --connect-timeout 3 --max-time 5 -o /dev/null "$URL/api/v1/health"; then READY=yes; break; fi
    sleep 2
  done
  [ "$READY" = yes ]
  LOG=$(journalctl -u openwatch --since "$SINCE" --no-pager -o cat)
  [[ "$LOG" != *"kensa scan wiring unavailable"* ]]
  [[ "$LOG" != *"kensa rule library unavailable"* ]]
  RULES=$(curl -sk --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' -K - "$URL/api/v1/rules" <<<"header = \"Authorization: Bearer $TOKEN\"")
  [ "$RULES" = 200 ]
  trap - ERR
  echo "ROLLED BACK: schema $GOT restored, previous packages installed, rule library loaded"
)
```

Each check fails the block rather than printing a warning for you to notice:

| Step | Check | Stops when |
|---|---|---|
| 1 | Inputs | a value is still a placeholder, `EXPECTED` is not a number, a file is missing or unreadable, or the token file does not hold an `owk_` token |
| 1 | Dump | the file lacks the `pg_dump` header or the `dump complete` line a finished dump ends with |
| 1 | Aside name | `openwatch_pre_rollback` already exists from an earlier attempt |
| 2 | Connections | anything is still connected to `openwatch` after the service stops. The block lists those sessions before it stops |
| 2 | Rename and create | the rename or the new database fails |
| 3 | Restore | `psql` hits any error. The whole restore rolls back, and the new database stays empty |
| 4 | Version | the restored schema is not the version you recorded in Step 2 |
| 4 | Ownership | any table, index or sequence in `public` belongs to a role other than `openwatch` |
| 5 | Packages | the package manager fails |
| 6 | Health | the service does not answer `/api/v1/health` in time (see [How long the checks wait](#how-long-the-checks-wait)) |
| 6 | Rule library | the journal since the restart says `kensa scan wiring unavailable` or `kensa rule library unavailable`, or `GET /api/v1/rules` does not answer `200` |

The package manager's own scriptlet runs during step 5 as an upgrade. It
takes another dump, finds no migrations to run, and starts the service.

**Step 6 restarts the service on purpose** (CP `bugs/OW-094`). The scriptlet
starts the service inside the package transaction. At that moment the newer
`kensa-rules` package's extra rule files are still on disk, because the
package manager removes them only when the transaction finishes. The previous
engine reads the rule library once, at startup. On a real v0.8.0-rc.6 to
v0.7.1 rollback it met a rule it could not load, logged only a warning, and
reported `healthy` while every scan failed. A plain `systemctl start` does
nothing when the service already runs, so the block uses `restart`, then
checks the library directly.

When the block prints `ROLLED BACK`, confirm the result:

```bash
curl -k https://localhost:8443/api/v1/health
openwatch --version
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch migrate --status'
```

`/api/v1/health` reports `healthy` with the previous version, and
`migrate --status` reports no pending migrations. Then run one compliance scan
end to end, as in the [post-upgrade checklist](#post-upgrade-checklist),
before you call the rollback done.

#### How long the checks wait

The rollback block and every recovery block use the same bounds. Every health
and rules request carries `--connect-timeout 3 --max-time 5`, so no single
request can hang. The health wait gives up after at most **67 seconds**: a
60-second deadline, plus one last request of at most 5 seconds and a 2-second
pause. The rules check then gives up after at most **5 seconds**. A block that
stops on either prints its `STOPPED` message.

These bounds apply to the HTTP checks only, not to a whole block.
`systemctl restart`, `journalctl`, and the database and package commands have
their own timing, which these numbers do not bound.

#### If the block stops

The `STOPPED` message names the line and the phase. The phase decides the
recovery. Fix the cause before you run the rollback block again.

| Phase | What it means | What to do |
|---|---|---|
| `inputs` | Step 1. Nothing changed, and the service still runs | Fix the input and run the block again |
| `database` | Steps 2 to 4. No package was touched | Run [Recover before package installation](#recover-before-package-installation) |
| `packages` | Step 5 or 6. The package state may have changed. The block stopped the service and swapped no database | Inspect the packages, then run the matching block under [Recover after package installation began](#recover-after-package-installation-began) |

None of the recovery blocks drops a database. Each checks every name before
it renames anything, and stops without a change when a name is missing or
already taken. Each ends with the same checks as step 6: it restarts the
service, waits for health, reads the journal, and calls `GET /api/v1/rules`.
It prints its success line only after all of them pass, and waits no longer
than the rollback block does (see
[How long the checks wait](#how-long-the-checks-wait)). If a check fails after
the databases are in place, the block stops the service and says so.

The keep-restored and put-back blocks compare the installed version exactly.
They read the second word of the first line of `openwatch --version` and
require it to equal the value you give, so `0.7.10` does not pass for
`0.7.1`, and `0.8.1-rc.2` does not pass for `0.8.1`. Give the version exactly
as that line prints it.

Each recovery block needs a token that works in the database it leaves as
`openwatch`:

| Block | Database it leaves as `openwatch` | A token that works there |
|---|---|---|
| Recover before package installation | the original, newer-version database | the pre-upgrade token, if it was not revoked since, or a token created after the upgrade |
| Keep the restored database | the restored, pre-upgrade database | only a token created before the upgrade: the same one the rollback block used |
| Put the original database back | the original, newer-version database | the pre-upgrade token, if it was not revoked since, or a token created after the upgrade |

A token that is not valid there makes `GET /api/v1/rules` answer `401`, and
the block stops in its `verify` stage with the service stopped. The block
reads the token from the file and never prints it.

##### Recover before package installation

Use this only when the block stopped in phase `database`. It sets the
replacement database aside as `openwatch_failed_restore`, if one was created,
and renames `openwatch_pre_rollback` back to `openwatch`. If the rollback
stopped before the rename, the original is still `openwatch`, and the block
renames nothing. Either way it restarts the service and checks it. The newer
packages are still installed, so the original database matches them. Fill in
the token file:

```bash
(
  set -euo pipefail
  TOKEN_FILE='<root-only-file-holding-an-owk-token-valid-in-the-original-database>'
  URL=https://localhost:8443
  ASIDE=openwatch_pre_rollback
  FAILED=openwatch_failed_restore
  PSQL=(runuser -u postgres -- psql -X -q -tA -v ON_ERROR_STOP=1)
  STAGE=checks
  on_stop() {
    echo "RECOVERY STOPPED at line $1, stage: $STAGE." >&2
    case "$STAGE" in
      checks)
        echo "No database was renamed and the service was not touched." >&2 ;;
      renaming)
        echo "The renames stopped partway. List the databases (runuser -u postgres -- psql -l)" >&2
        echo "before you do anything else." >&2 ;;
      verify)
        echo "The databases are as intended, but the service did not prove it loaded" >&2
        echo "its rule library. It is being stopped. Fix the cause, then restart it and" >&2
        echo "repeat the checks." >&2
        systemctl stop openwatch || echo "Could not stop openwatch; stop it yourself." >&2 ;;
    esac
  }
  trap 'on_stop $LINENO' ERR
  db() { "${PSQL[@]}" -c "SELECT count(*) FROM pg_database WHERE datname = '$1'"; }
  case "$TOKEN_FILE" in
    *'<'*) echo "fill in the value at the top first" >&2; false ;;
  esac
  test -r "$TOKEN_FILE"
  TOKEN=$(cat "$TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]

  HAVE_ASIDE=$(db "$ASIDE")
  HAVE_NEW=$(db openwatch)
  if [ "$HAVE_ASIDE" = 0 ]; then
    # The rollback stopped before the rename: the original never moved.
    [ "$HAVE_NEW" = 1 ] || { echo "neither openwatch nor $ASIDE exists; stop and investigate" >&2; false; }
    echo "$ASIDE does not exist: the original database is still openwatch"
  elif [ "$HAVE_NEW" = 1 ]; then
    FAILED_TAKEN=$(db "$FAILED")
    [ "$FAILED_TAKEN" = 0 ] || { echo "$FAILED is already taken; rename or remove it first" >&2; false; }
  fi

  if [ "$HAVE_ASIDE" = 1 ]; then
    systemctl stop openwatch
    OPEN=$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity
        WHERE datname IN ('openwatch', '$ASIDE')")
    if [ "$OPEN" != 0 ]; then
      echo "still connected to openwatch or $ASIDE:" >&2
      "${PSQL[@]}" -c "SELECT pid, datname, backend_type, usename, application_name, client_addr
          FROM pg_stat_activity WHERE datname IN ('openwatch', '$ASIDE')" >&2 || :
      false
    fi
    STAGE=renaming
    if [ "$HAVE_NEW" = 1 ]; then
      "${PSQL[@]}" -c "ALTER DATABASE openwatch RENAME TO $FAILED"
    fi
    "${PSQL[@]}" -c "ALTER DATABASE $ASIDE RENAME TO openwatch"
  fi

  STAGE=verify
  SINCE=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart openwatch
  READY=no
  DEADLINE=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if curl -skf --connect-timeout 3 --max-time 5 -o /dev/null "$URL/api/v1/health"; then READY=yes; break; fi
    sleep 2
  done
  [ "$READY" = yes ]
  LOG=$(journalctl -u openwatch --since "$SINCE" --no-pager -o cat)
  [[ "$LOG" != *"kensa scan wiring unavailable"* ]]
  [[ "$LOG" != *"kensa rule library unavailable"* ]]
  RULES=$(curl -sk --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' -K - "$URL/api/v1/rules" <<<"header = \"Authorization: Bearer $TOKEN\"")
  [ "$RULES" = 200 ]
  trap - ERR
  echo "RESTORED: the original database is back as openwatch, rule library loaded"
)
```

When it reports `RESTORED`, the service runs the newer version on its own
database, as before the rollback, and its rule library loaded. Run one
compliance scan end to end before you call the recovery complete. Keep
`openwatch_failed_restore` until you know why the rollback stopped, then
remove it.

##### Recover after package installation began

The package transaction may have finished, failed partway, or left the
newer packages in place. Look before you choose a database. The rollback
block has already stopped the service; confirm with `systemctl is-active
openwatch` and stop it if it still runs.

```bash
# RHEL family:
rpm -q openwatch kensa-rules
rpm -V kensa-rules
# Debian/Ubuntu:
dpkg-query -W -f='${Status} ${Version}\n' openwatch kensa-rules
dpkg --audit
# Both:
openwatch --version
```

Then choose by what you see:

| What is installed | Which database to keep | Block |
|---|---|---|
| The **previous** `openwatch` and `kensa-rules`, with `rpm -V` silent (DEB: both `install ok installed`, `dpkg --audit` silent) | the restored database, now `openwatch` | [Keep the restored database](#keep-the-restored-database) |
| The **newer** `openwatch` still | the original, now `openwatch_pre_rollback` | [Put the original database back](#put-the-original-database-back) |
| Anything half-installed: a package missing, a failed `rpm -V`, a status other than `install ok installed`, or output from `dpkg --audit` | neither yet | Fix the package state first, with the package manager's own recovery (`dnf history`, `dpkg --configure -a`). Then inspect again |

###### Keep the restored database

The previous version is installed. This block checks that, and that the
package state is clean, then restarts the service on the restored database
and proves the rule library loaded. Fill in the previous version, as
`openwatch --version` prints it, the migration version from Step 2, and the
token file. The token must have been created before the upgrade:

```bash
(
  set -euo pipefail
  OLD_VERSION='<previous-version-as-openwatch-version-prints-it>'
  EXPECTED='<migration-version-from-step-2>'
  TOKEN_FILE='<root-only-file-holding-an-owk-token-created-before-the-upgrade>'
  URL=https://localhost:8443
  PSQL=(runuser -u postgres -- psql -X -q -tA -v ON_ERROR_STOP=1)
  STAGE=checks
  on_stop() {
    echo "RECOVERY STOPPED at line $1, stage: $STAGE." >&2
    case "$STAGE" in
      checks)
        echo "Nothing was changed. No database was renamed." >&2 ;;
      verify)
        echo "The restored database is kept as openwatch, but the service did not prove" >&2
        echo "it loaded its rule library. It is being stopped. Fix the cause, then" >&2
        echo "restart it and repeat the checks." >&2
        systemctl stop openwatch || echo "Could not stop openwatch; stop it yourself." >&2 ;;
    esac
  }
  trap 'on_stop $LINENO' ERR
  case "$OLD_VERSION $EXPECTED $TOKEN_FILE" in
    *'<'*) echo "fill in the three values at the top first" >&2; false ;;
  esac
  test -r "$TOKEN_FILE"
  TOKEN=$(cat "$TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]

  VERSION_OUT=$(openwatch --version)
  read -r NAME INSTALLED EXTRA <<<"${VERSION_OUT%%$'\n'*}"
  [ "$NAME" = openwatch ]
  [ -z "$EXTRA" ]
  [ "$INSTALLED" = "$OLD_VERSION" ] || { echo "installed openwatch is $INSTALLED, not $OLD_VERSION" >&2; false; }
  if command -v dnf >/dev/null; then
    VERIFY=$(rpm -V kensa-rules)
    [ -z "$VERIFY" ]
  else
    AUDIT=$(dpkg --audit)
    [ -z "$AUDIT" ]
  fi
  HAVE=$("${PSQL[@]}" -c "SELECT count(*) FROM pg_database WHERE datname = 'openwatch'")
  [ "$HAVE" = 1 ]
  GOT=$("${PSQL[@]}" -d openwatch -c 'SELECT max(version_id) FROM goose_db_version')
  [ "$GOT" = "$EXPECTED" ]

  STAGE=verify
  SINCE=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart openwatch
  READY=no
  DEADLINE=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if curl -skf --connect-timeout 3 --max-time 5 -o /dev/null "$URL/api/v1/health"; then READY=yes; break; fi
    sleep 2
  done
  [ "$READY" = yes ]
  LOG=$(journalctl -u openwatch --since "$SINCE" --no-pager -o cat)
  [[ "$LOG" != *"kensa scan wiring unavailable"* ]]
  [[ "$LOG" != *"kensa rule library unavailable"* ]]
  RULES=$(curl -sk --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' -K - "$URL/api/v1/rules" <<<"header = \"Authorization: Bearer $TOKEN\"")
  [ "$RULES" = 200 ]
  trap - ERR
  echo "KEPT: the restored database, schema $GOT, runs with openwatch $OLD_VERSION, rule library loaded"
)
```

When it reports `KEPT`, run one compliance scan end to end before you call
the recovery complete.

###### Put the original database back

The newer version is still installed. This block checks that, sets the
restored database aside as `openwatch_failed_restore`, renames the original
back, and proves the rule library loaded. Fill in the newer version, as
`openwatch --version` prints it, and the token file:

```bash
(
  set -euo pipefail
  NEW_VERSION='<newer-version-as-openwatch-version-prints-it>'
  TOKEN_FILE='<root-only-file-holding-an-owk-token-valid-in-the-original-database>'
  URL=https://localhost:8443
  ASIDE=openwatch_pre_rollback
  FAILED=openwatch_failed_restore
  PSQL=(runuser -u postgres -- psql -X -q -tA -v ON_ERROR_STOP=1)
  STAGE=checks
  on_stop() {
    echo "RECOVERY STOPPED at line $1, stage: $STAGE." >&2
    case "$STAGE" in
      checks)
        echo "No database was renamed and the service was not touched." >&2 ;;
      renaming)
        echo "The renames stopped partway. List the databases (runuser -u postgres -- psql -l)" >&2
        echo "before you do anything else." >&2 ;;
      verify)
        echo "The databases are as intended, but the service did not prove it loaded" >&2
        echo "its rule library. It is being stopped. Fix the cause, then restart it and" >&2
        echo "repeat the checks." >&2
        systemctl stop openwatch || echo "Could not stop openwatch; stop it yourself." >&2 ;;
    esac
  }
  trap 'on_stop $LINENO' ERR
  db() { "${PSQL[@]}" -c "SELECT count(*) FROM pg_database WHERE datname = '$1'"; }
  case "$NEW_VERSION $TOKEN_FILE" in
    *'<'*) echo "fill in the two values at the top first" >&2; false ;;
  esac
  test -r "$TOKEN_FILE"
  TOKEN=$(cat "$TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]

  VERSION_OUT=$(openwatch --version)
  read -r NAME INSTALLED EXTRA <<<"${VERSION_OUT%%$'\n'*}"
  [ "$NAME" = openwatch ]
  [ -z "$EXTRA" ]
  [ "$INSTALLED" = "$NEW_VERSION" ] || { echo "installed openwatch is $INSTALLED, not $NEW_VERSION" >&2; false; }
  HAVE_ASIDE=$(db "$ASIDE")
  [ "$HAVE_ASIDE" = 1 ] || { echo "$ASIDE does not exist: nothing to put back" >&2; false; }
  HAVE_NEW=$(db openwatch)
  if [ "$HAVE_NEW" = 1 ]; then
    FAILED_TAKEN=$(db "$FAILED")
    [ "$FAILED_TAKEN" = 0 ] || { echo "$FAILED is already taken; rename or remove it first" >&2; false; }
  fi

  systemctl stop openwatch
  OPEN=$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity
      WHERE datname IN ('openwatch', '$ASIDE')")
  if [ "$OPEN" != 0 ]; then
    echo "still connected to openwatch or $ASIDE:" >&2
    "${PSQL[@]}" -c "SELECT pid, datname, backend_type, usename, application_name, client_addr
        FROM pg_stat_activity WHERE datname IN ('openwatch', '$ASIDE')" >&2 || :
    false
  fi
  STAGE=renaming
  if [ "$HAVE_NEW" = 1 ]; then
    "${PSQL[@]}" -c "ALTER DATABASE openwatch RENAME TO $FAILED"
  fi
  "${PSQL[@]}" -c "ALTER DATABASE $ASIDE RENAME TO openwatch"

  STAGE=verify
  SINCE=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart openwatch
  READY=no
  DEADLINE=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if curl -skf --connect-timeout 3 --max-time 5 -o /dev/null "$URL/api/v1/health"; then READY=yes; break; fi
    sleep 2
  done
  [ "$READY" = yes ]
  LOG=$(journalctl -u openwatch --since "$SINCE" --no-pager -o cat)
  [[ "$LOG" != *"kensa scan wiring unavailable"* ]]
  [[ "$LOG" != *"kensa rule library unavailable"* ]]
  RULES=$(curl -sk --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' -K - "$URL/api/v1/rules" <<<"header = \"Authorization: Bearer $TOKEN\"")
  [ "$RULES" = 200 ]
  trap - ERR
  echo "RESTORED: the original database is back as openwatch, with openwatch $NEW_VERSION, rule library loaded"
)
```

When it reports `RESTORED`, the service runs the newer version on its own
database, as before the rollback, and its rule library loaded. Run one
compliance scan end to end before you call the recovery complete. Keep
`openwatch_failed_restore` until you know why the rollback stopped, then
remove it.

#### What was tested, and what was not

The rollback block and all three recovery blocks run in a test
(`TestUpgrade_FullRollbackRunbookBlock`). The test extracts each block from
this page and runs it against a real PostgreSQL 16 server, with a schema built
by the repository's own migrations and a dump taken with the scriptlet's
`pg_dump` flags. It injects failures at each phase: a missing or truncated
dump, a failed restore, a wrong version, a foreign-owned object, a failed
`createdb`, a taken recovery name, a failed package transaction and a failed
rule-library check. Each recovery block is also run with a health timeout,
each journal warning, and a `/api/v1/rules` answer of `503` and of `401`. It
must stop without its success line and leave the databases as intended. Each
of the four blocks is run with a health request and a rules request that
hang, and must stop within the bounds in
[How long the checks wait](#how-long-the-checks-wait). The keep-restored and
put-back blocks are run with near-miss versions (`0.7.10` for `0.7.1`, and a
pre-release against its final release) and must refuse them before they touch
the service or a database.

The package manager, `systemctl`, `journalctl`, `curl`, `rpm`, `dpkg` and
`openwatch --version` are stand-ins that record what they were asked to do.
The `curl` stand-in honors `--max-time` the way `curl` does, so the test proves
each block passes the flag and stops on a timeout, but not that a real `curl`
enforces it.
The restore itself runs the same way on every distribution. The Debian and
Ubuntu path was not run against real packages: the test proves only that the
blocks pick `apt-get` and `dpkg --audit` when `dnf` is absent. The RHEL
restore was run by hand on a real host on 2026-09-30, with the same restore
commands. The restart-and-load problem step 6 guards against was observed on
that host. The test checks that the blocks stop on a warning, a timeout or a
non-`200` answer, not how a real service behaves.

Keep `openwatch_pre_rollback` and the pre-upgrade dump until you have
validated the rollback, then remove them to reclaim the space. Keep the
pre-upgrade dump of a successful upgrade until you have validated that
upgrade in production (at least several days).

## Updating Kensa compliance rules

Kensa is two things with two versions. The engine is a Go dependency compiled
into the `openwatch` binary; `GET /api/v1/version` reports it in the `kensa`
field. The rules are the separate `kensa-rules` package, installed at
`/usr/share/kensa/rules` and loaded from there when the service starts. The
`openwatch` package depends on `kensa-rules` but does not pin its version, so
upgrading one does not upgrade the other.

A corpus needs an engine at least as new as itself. The `openwatch` package
declares the Kensa engine it contains, and `kensa-rules` requires at least
its own version. This is the boundary tested today: the engine in rc.5 and
earlier cannot load the 0.10.0 corpus, and the service would start with every
scan failing. The 0.10.0 engine loads the 0.9.0 corpus, so upgrading
`openwatch` alone is allowed.

A rules-only upgrade onto an older `openwatch` is refused, and nothing is
changed: `dnf`, `rpm -U` and `apt` refuse it from the dependency, and a bare
`dpkg -i` is refused by the package's own check before any file is replaced.
Upgrade both packages in one transaction instead. With `dpkg -i`, list
`openwatch` first; if the rules package is listed first it is refused, and
`openwatch` alone is upgraded, which is a working pair. Run the command again
to finish.

### What this check does not cover

The check travels with the `kensa-rules` package that OpenWatch builds and
publishes with each release. Kensa also publishes a package named
`kensa-rules`, from its own releases, with the same install path. **Kensa's
package does not carry this check**, and nothing in `openwatch` refuses it:
`openwatch` depends on the name `kensa-rules`, which either package
satisfies. If a host has a Kensa package repository configured, or someone
installs a `kensa-rules` file from a Kensa release, the package manager can
put Kensa's corpus in place of OpenWatch's with no refusal.

- **On `openwatch` 0.8.0-rc.5 or earlier**, which declares no engine, no
  `kensa-rules` package of either origin is checked. A 0.10.0 or newer
  corpus from any source makes every scan fail.
- **On this release**, OpenWatch's own `kensa-rules` is checked as described
  above. Whether a Kensa-published corpus loads depends on its version and is
  not checked.

This is a stated limit, not a protection. To stay inside what is tested,
install `kensa-rules` only from the OpenWatch release that matches your
`openwatch`, and do not configure a Kensa package repository on an OpenWatch
host. To see which package is installed, look for the engine requirement,
which only OpenWatch's package carries from this release on:

```bash
rpm -q --requires kensa-rules | grep openwatch-kensa-engine   # apt: dpkg -s kensa-rules | grep openwatch-kensa-engine
```

No output means the installed package is Kensa's, or OpenWatch's from before
this release. To put OpenWatch's package back, reinstall it from the matching
release (`sudo dnf install ./kensa-rules-<version>.noarch.rpm`; use
`reinstall` in place of `install` when the same version is installed, and
`downgrade` when a higher one is; on Debian,
`sudo apt install --reinstall --allow-downgrades ./kensa-rules_<version>_all.deb`),
then restart the service.

### A corpus newer than the engine

If a corpus newer than the engine is on disk anyway (installed with
`rpm --nodeps` or `dpkg --force-depends`, or from a Kensa package), every
scan fails. Either install
the matching `openwatch`
(`sudo dpkg -i ./openwatch_<new-version>_<arch>.deb && sudo dpkg --configure -a`,
or `sudo dnf install ./openwatch-<new-version>.<arch>.rpm`) or put the previous
rules back (`sudo dpkg -i ./kensa-rules_<old-version>_all.deb`, or
`sudo dnf downgrade ./kensa-rules-<old-version>.noarch.rpm`), then restart the
service. On Debian, plain `apt install` refuses to start from that broken
state; `dpkg -i` followed by `dpkg --configure -a` works.

A newer corpus arrives with the OpenWatch release that links a matching
engine. To update the rules, install both packages from that release in one
transaction, as in the upgrade steps above, and restart the service so it
loads the new corpus:

```bash
sudo dnf install ./openwatch-<version>.<arch>.rpm ./kensa-rules-<kensa-version>.noarch.rpm
# apt: sudo apt install ./openwatch_<version>_<arch>.deb ./kensa-rules_<kensa-version>_all.deb
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
