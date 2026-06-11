# Database migration guide

This guide covers how OpenWatch's PostgreSQL schema is versioned, how migrations
are applied in production, and how to add a new migration. OpenWatch is a single
Go binary (`/usr/bin/openwatch`) that serves the REST API and the embedded React
UI over HTTPS on port 8443. It uses PostgreSQL only — there is no MongoDB, Redis,
Celery, Alembic, or container runtime involved in migrations.

For end-to-end install and configuration, see
[`docs/engineering/install_guide.md`](../engineering/install_guide.md). This
document focuses specifically on the migration mechanism.

## How migrations work

Migrations are plain SQL files embedded into the `openwatch` binary at build
time. The applier is [`pressly/goose`](https://github.com/pressly/goose) running
in SQL-flavor mode.

| Aspect | Value |
|--------|-------|
| Database | PostgreSQL (UUID primary keys on most tables) |
| Migration tool | `goose` v3 (SQL flavor), embedded via `go:embed` |
| Migration directory | `internal/db/migrations/*.sql` |
| File naming | `NNNN_description.sql` (zero-padded ascending integer) |
| Version table | `goose_db_version` (created and managed by goose) |
| Applier code | `internal/db/migrations/runner.go` (`Apply`, `Status`) |
| CLI entry point | `openwatch migrate` (`cmd/openwatch/main.go`, `cmdMigrate`) |

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

The applier (`migrations.Apply`) only ever runs the `Up` direction
(`goose.UpContext`). The `Down` blocks exist for completeness and local
development; OpenWatch does not expose a rollback subcommand (see
[Rollback](#rollback)).

## Applying migrations in production

Run the `migrate` subcommand. It connects with the configured database DSN,
applies every pending `Up` migration, and prints the resulting version and the
list of embedded migration files.

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate
```

The DSN comes from `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env` (or
`[database].dsn` in `/etc/openwatch/openwatch.toml`). The command times out after
60 seconds, applies migrations idempotently (goose skips versions already recorded
in `goose_db_version`), and reports output like:

```
applying migrations against postgres://openwatch:***@127.0.0.1:5432/openwatch ...
  current version: 22
  migration files: 22
    - 0001_initial.sql
    - 0002_audit_events_taxonomy.sql
    ...
migrations applied
```

Run `openwatch migrate` after every package upgrade and before starting (or
restarting) the service, so the schema matches the binary. The systemd unit
(`/usr/lib/systemd/system/openwatch.service`, `ExecStart=/usr/bin/openwatch serve`)
does not run migrations on boot — `serve` and `migrate` are separate subcommands.

A typical upgrade sequence:

```bash
sudo systemctl stop openwatch
sudo dnf upgrade openwatch          # or: sudo apt install --only-upgrade openwatch
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
sudo systemctl start openwatch
```

## Checking the current schema version

The `migrate` subcommand prints the current version after applying. To inspect
the version table directly with `psql`:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c \
  "SELECT version_id, is_applied, tstamp FROM goose_db_version ORDER BY id DESC LIMIT 5;"
```

The highest `version_id` with `is_applied = true` is the current schema version.
That number corresponds to the `NNNN` prefix of the last applied migration file.

## Adding a new migration

1. Create a new file in `internal/db/migrations/` named with the next ascending
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
   - Reference the owning behavioral spec in a comment when one exists (see
     existing files such as `0012_transaction_log.sql`).

4. Never edit a migration that has already shipped or been applied to a shared
   database. goose records each applied version; changing an applied file does
   not re-run it and leaves environments inconsistent. Add a new migration
   instead.

5. Verify locally:

   ```bash
   go build ./...
   go test ./internal/db/...
   openwatch migrate          # against a local dev PostgreSQL
   ```

   The `internal/db/` package includes tests that exercise the embedded
   migration set; run them before committing.

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

Take a logical backup with `pg_dump` before applying migrations to any
environment you cannot afford to lose:

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

Run `pg_dump`/`pg_restore` from the host (or a PostgreSQL client package) — there
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

| Item | Location |
|------|----------|
| Migration files | `internal/db/migrations/*.sql` |
| Applier (`Apply`, `Status`, `List`) | `internal/db/migrations/runner.go`, `embed.go` |
| `migrate` subcommand | `cmd/openwatch/main.go` (`cmdMigrate`) |
| Config layering and DSN | `internal/config/`, `docs/engineering/install_guide.md` |
| systemd unit | `packaging/common/openwatch.service` |
| Install and upgrade flow | `docs/engineering/install_guide.md` |
| Compliance engine boundary | `docs/KENSA_OPENWATCH_BOUNDARY.md` |

OpenWatch's compliance engine, Kensa, runs SSH-based checks against native YAML
rules; OpenSCAP, `oscap`, XCCDF, and OVAL are not used and have no schema in this
database.
