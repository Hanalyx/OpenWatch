# Database migration guide

**Last updated:** 2026-06-25 · **Applies to:** OpenWatch v0.3.0 (Go single-binary)

This guide covers how OpenWatch's PostgreSQL schema is versioned, how migrations
are applied in production, and how to add a new migration. OpenWatch is a single
Go binary (`/usr/bin/openwatch`) that serves the REST API and the embedded React
UI over HTTPS on port 8443. It uses PostgreSQL only—there is no MongoDB, Redis,
Celery, Alembic, or container runtime involved in migrations.

For end-to-end install and configuration, see the
[install guide](INSTALLATION.md). This
document focuses specifically on the migration mechanism.

## How migrations work

Migrations are plain SQL files embedded into the `openwatch` binary at build
time. The applier is [`pressly/goose`](https://github.com/pressly/goose) running
in SQL-flavor mode.

| Aspect | Value |
|--------|-------|
| Database | PostgreSQL (UUID primary keys on most tables) |
| Migration tool | `goose` v3 (SQL flavor), embedded into the binary |
| File naming | `NNNN_description.sql` (zero-padded ascending integer) |
| Version table | `goose_db_version` (created and managed by goose) |
| CLI entry point | `openwatch migrate` |

Because the SQL files are compiled into the binary, the version of the schema a
binary expects always travels with that binary. There is no separate migration
package to install or path to configure at runtime.

Each migration file has an up section and a down section, delimited by goose
annotations:

```sql
-- +goose Up
CREATE TABLE example (...);

-- +goose Down
DROP TABLE IF EXISTS example;
```

The applier only ever runs the `Up` direction. The `Down` blocks exist for
completeness and local development; OpenWatch does not expose a rollback
subcommand (see [Rollback](#rollback)).

## Applying migrations in production

Run the `migrate` subcommand. It connects with the configured database DSN,
applies every pending `Up` migration, and prints the resulting schema version.

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate
```

The DSN comes from `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env` (or
`[database].dsn` in `/etc/openwatch/openwatch.toml`). The command times out after
10 minutes, applies migrations idempotently (goose skips versions already recorded
in `goose_db_version`), and prints the version transition:

```
migrations applied — version 47 -> 48
```

When the schema is already current it reports that no migrations were pending
(the version is unchanged). A failure aborts before changing the version.

Run `openwatch migrate` after every package upgrade and before starting (or
restarting) the service, so the schema matches the binary. The systemd unit runs
`openwatch serve` and does not run migrations on boot—`serve` and `migrate` are
separate subcommands.

A typical upgrade sequence:

```bash
sudo systemctl stop openwatch
sudo dnf upgrade openwatch          # or: sudo apt install --only-upgrade openwatch
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
sudo systemctl start openwatch
```

## Checking the current schema version

The `migrate` subcommand prints the current version after applying. To check the
schema state **without applying anything**, pass `--status`. It reports the
current version and whether any migrations are pending, and makes no changes:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate --status
```

To inspect the version table directly with `psql`:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c \
  "SELECT version_id, is_applied, tstamp FROM goose_db_version ORDER BY id DESC LIMIT 5;"
```

The highest `version_id` with `is_applied = true` is the current schema version.
That number corresponds to the `NNNN` prefix of the last applied migration file.

## Adding a new migration

1. Create a new migration file named with the next ascending
   integer, for example `0023_add_scan_findings.sql`. Migration order is driven
   by the filename prefix, not by dates.

2. Write the `Up` and `Down` blocks using goose annotations:

   ```sql
   -- +goose Up
   CREATE TABLE scan_findings (
       id          UUID         PRIMARY KEY,
       host_id     UUID         NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
       rule_id     TEXT         NOT NULL,
       status      TEXT         NOT NULL CHECK (status IN ('pass','fail','skipped','error')),
       created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
   );
   CREATE INDEX idx_scan_findings_host ON scan_findings (host_id);

   -- +goose Down
   DROP INDEX IF EXISTS idx_scan_findings_host;
   DROP TABLE IF EXISTS scan_findings;
   ```

3. Follow the conventions already in the tree:
   - Use `UUID` primary keys for new tables.
   - Add indexes for foreign keys and common query columns.
   - Make `Down` reverse `Up` exactly, dropping indexes before tables and using
     `IF EXISTS` guards.
   - Reference the owning behavioral spec in a comment when one exists, following
     the convention in existing migration files.

4. Never edit a migration that has already shipped or been applied to a shared
   database. goose records each applied version; changing an applied file does
   not re-run it and leaves environments inconsistent. Add a new migration
   instead.

5. Verify locally by building the binary, running the database test suite, and
   applying the migration against a local development PostgreSQL:

   ```bash
   openwatch migrate          # against a local dev PostgreSQL
   ```

   The database test suite exercises the embedded migration set; run it before
   committing.

## Rollback

There is no `openwatch migrate down` subcommand. The applier only runs the `Up`
direction. The supported recovery path for a bad migration in production is
restore-from-backup, not an automated downgrade.

Plan accordingly:

- Back up the database before applying migrations on a production system (see
  [Backup before migrating](#backup-before-migrating)).
- For schema mistakes, prefer a new forward migration that corrects the prior
  one over any manual `DROP`.
- The `Down` blocks in each file are for local development and may be applied by
  hand with the `goose` CLI against a disposable database; they are not part of
  the production workflow.

> Roadmap / not yet implemented: a first-class rollback subcommand
> (`openwatch migrate down`) and a dry-run SQL preview are not present in the
> current binary. Do not assume they exist.

## Backup before migrating

The `migrate` subcommand can take the pre-migration backup for you: pass
`--backup-dir <dir>` and it writes a logical dump into that directory before
applying any pending migration. This is the recommended path on production
upgrades:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate --backup-dir /var/backups/openwatch
```

To take the backup yourself instead, use `pg_dump` before applying migrations to
any environment you cannot afford to lose:

```bash
pg_dump "$OPENWATCH_DATABASE_DSN" \
  --format=custom \
  --file="openwatch_$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Restore with `pg_restore` against a clean database if a migration must be
reverted:

```bash
pg_restore --clean --if-exists --dbname "$OPENWATCH_DATABASE_DSN" \
  openwatch_20260610T120000Z.dump
```

Run `pg_dump`/`pg_restore` from the host (or a PostgreSQL client package)—there
is no container to `exec` into.

## Troubleshooting

### `migrate` fails to connect

Symptom: `openwatch migrate: connect postgres://…: …`.

- Confirm PostgreSQL is reachable and the DSN is correct:

  ```bash
  psql "$OPENWATCH_DATABASE_DSN" -c "SELECT 1;"
  ```

- Confirm `OPENWATCH_DATABASE_DSN` is set in `/etc/openwatch/secrets.env` and
  uses the form `postgres://user:pass@host:port/db?sslmode=…`.
- Validate the resolved config without touching the database:

  ```bash
  sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
      openwatch check-config
  ```

### A migration fails partway

Symptom: `openwatch migrate: up: …` referencing a specific SQL error.

goose runs each migration in order and records a version only after it succeeds,
so a failure leaves the database at the last fully-applied version. To recover:

1. Read the error and inspect the current version:

   ```bash
   psql "$OPENWATCH_DATABASE_DSN" -c \
     "SELECT version_id, is_applied FROM goose_db_version ORDER BY id DESC LIMIT 5;"
   ```

2. Fix the offending migration file (only if it has never shipped) or write a
   corrective forward migration.

3. Re-run `openwatch migrate`. Already-applied versions are skipped.

If the schema was left in an inconsistent state by a partially-executed
statement, restore from the pre-migration backup.

### Service starts but behaves as if the schema is old

Confirm the binary version and the applied schema version line up:

```bash
openwatch --version
psql "$OPENWATCH_DATABASE_DSN" -c \
  "SELECT max(version_id) FROM goose_db_version WHERE is_applied;"
```

If the version is behind the binary, run `openwatch migrate` and restart:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
sudo systemctl restart openwatch
journalctl -u openwatch -n 50 --no-pager
```

## Reference

| Item | Reference |
|------|-----------|
| Migration files | Embedded in the `openwatch` binary |
| `migrate` subcommand | `openwatch migrate` |
| Check status, apply nothing | `openwatch migrate --status` |
| Auto-backup before applying | `openwatch migrate --backup-dir <dir>` |
| Config layering and DSN | [Install guide](INSTALLATION.md) |
| systemd unit | `openwatch.service` |
| Install and upgrade flow | [Install guide](INSTALLATION.md) |

OpenWatch's compliance engine, Kensa, runs SSH-based checks against native YAML
rules. There is no separate scan-content schema in this
database.
