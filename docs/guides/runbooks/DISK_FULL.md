# Runbook: disk space issues

**Severity**: P1 - High
**Last updated**: 2026-06-26
**Owner**: Platform engineering
**Estimated resolution time**: 10-30 minutes

This runbook covers a full or nearly full disk on a host running OpenWatch as a
native package (single Go binary on systemd) with a PostgreSQL database. There is
no container runtime, no Redis, and no Celery—OpenWatch is one binary,
`/usr/bin/openwatch`, that serves the REST API and the embedded UI over HTTPS on
port `8443`. Background jobs run through a PostgreSQL-native queue, so a full disk
manifests as PostgreSQL write failures and a failing health probe rather than
container or volume errors.

For install and configuration layout, see the
[install guide](../INSTALLATION.md).

---

## Where OpenWatch writes to disk

| Path | Owner | Contents | Growth |
|------|-------|----------|--------|
| PostgreSQL data directory | PostgreSQL package | All OpenWatch data (`audit_events`, `transactions`, `host_rule_state`, `job_queue`, host intelligence, etc.) | Primary growth driver |
| systemd journal | `systemd-journald` | All `openwatch.service` stdout/stderr (JSON logs) | Bounded by journal config |
| `/var/lib/openwatch` | `openwatch` | Service state (mode `0750`) | Low |
| `/var/log/openwatch` | `openwatch` | Reserved log directory (mode `0750`) | Low; OpenWatch logs to the journal, not files |
| `/etc/openwatch` | `root`/`openwatch` | Config, TLS, keys, license | Static |

The OpenWatch binary logs JSON to stdout/stderr, which systemd routes to the
journal (`StandardOutput=journal`, `StandardError=journal`). It does not write
its own application log files by default, so most disk growth is in PostgreSQL
and the journal.

The PostgreSQL data directory location depends on how PostgreSQL was installed
(for example `/var/lib/pgsql/data` on RPM-based systems or
`/var/lib/postgresql/<version>/main` on Debian/Ubuntu). The default connection
string is `postgres://openwatch@localhost/openwatch`; an external database is
configured through `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env`.

---

## Symptoms

- The health probe returns `503` or `db_connected: false`:
  `curl -sk https://localhost:8443/api/v1/health`.
- `journalctl -u openwatch` shows PostgreSQL write errors such as
  `could not extend file` or `No space left on device`.
- Scans queued through the job queue never complete; the `worker` process logs
  database errors.
- New logins or writes fail while reads still work (PostgreSQL has stopped
  accepting writes).

---

## Diagnosis

### Step 1: Check filesystem usage

```bash
df -h
```

Identify which filesystem is full. Pay attention to the mount that holds the
PostgreSQL data directory and the mount that holds `/var/log/journal`.

### Step 2: Find the largest directories

```bash
sudo du -xh --max-depth=1 /var 2>/dev/null | sort -rh | head -20
```

This isolates whether the PostgreSQL data directory, the journal, or something
unrelated is consuming the space.

### Step 3: Check the systemd journal size

```bash
journalctl --disk-usage
```

If the journal is large, it is a fast, safe target to reclaim (see Resolution
path A).

### Step 4: Check the OpenWatch service state

```bash
systemctl status openwatch
journalctl -u openwatch -n 100 --no-pager
```

Confirm whether the binary is up and whether it is logging PostgreSQL write
failures.

### Step 5: Check the database size

Connect with `psql` (adjust user, database, and host to match your
`OPENWATCH_DATABASE_DSN`):

```bash
psql -U openwatch -d openwatch -c "SELECT pg_size_pretty(pg_database_size('openwatch')) AS database_size;"
```

Table-level breakdown of the largest tables:

```bash
psql -U openwatch -d openwatch -c "
SELECT schemaname || '.' || relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 15;"
```

The tables most likely to be large are `audit_events`, `transactions`,
`idempotency_keys`, `job_queue`, and the host intelligence tables. Verify the
table names against your database before acting on any specific table.

---

## Resolution

Reclaim space starting with the safest, fastest options. The goal is at least
15-20% free space on every affected filesystem.

### Path A: Vacuum the systemd journal (safe, fast)

```bash
# Keep only the last 2 days of journal
sudo journalctl --vacuum-time=2d

# Or cap the journal at a fixed size
sudo journalctl --vacuum-size=500M
```

To make the cap permanent, set `SystemMaxUse=` in
`/etc/systemd/journald.conf` and restart `systemd-journald`.

### Path B: Reclaim space inside PostgreSQL

`VACUUM` reclaims space from dead rows for reuse within the database. `VACUUM
FULL` returns space to the operating system but takes an exclusive lock on the
table—run it only in a maintenance window.

```bash
# Reuse space within the database (no exclusive lock)
psql -U openwatch -d openwatch -c "VACUUM (VERBOSE, ANALYZE);"
```

If a specific large table needs to return space to the OS (maintenance window
only—confirm the table exists first):

```bash
psql -U openwatch -d openwatch -c "VACUUM FULL VERBOSE audit_events;"
```

`VACUUM FULL` needs temporary free space roughly equal to the table size. On a
disk that is already full, free space with path A or C before attempting it.

### Path C: Apply retention to large tables

OpenWatch does not ship an automated retention or pruning job today (see
"Not yet implemented" below). If a table such as `audit_events` has grown beyond
your retention requirement, delete old rows manually, then vacuum. Confirm the
column names against your database before running a delete, and take a backup
first if the data is subject to a compliance retention policy.

```bash
# Example only — verify the table and timestamp column exist before running.
psql -U openwatch -d openwatch -c "
DELETE FROM audit_events WHERE occurred_at < now() - interval '365 days';
VACUUM ANALYZE audit_events;"
```

Audit records are compliance-relevant (typically retained one year or longer for
FedRAMP). Do not delete audit data without confirming the retention policy.

### Path D: Expand the filesystem

If no data can be safely removed, grow the underlying volume (cloud disk resize,
LVM extend, or add a disk) and expand the filesystem. This is the correct action
when the database is legitimately large rather than bloated.

---

## Recovery verification

### 1. Disk has adequate free space

```bash
df -h
```

Target at least 15-20% free on every affected filesystem.

### 2. PostgreSQL accepts writes

```bash
psql -U openwatch -d openwatch -c "
CREATE TEMP TABLE disk_test (val text);
INSERT INTO disk_test VALUES ('write_test');
DROP TABLE disk_test;
SELECT 'write_ok' AS status;"
```

### 3. The service is healthy

```bash
systemctl status openwatch
curl -sk https://localhost:8443/api/v1/health
```

A healthy response is HTTP `200` with a body of
`{"status":"healthy","db_connected":true,"version":"..."}`. A `503` or
`db_connected: false` means PostgreSQL is still not writable.

### 4. Migrations are current (if you restarted after recovery)

```bash
sudo -u openwatch /usr/bin/openwatch migrate --config /etc/openwatch/openwatch.toml
```

This is idempotent: it applies any pending migrations and prints the current
schema version.

---

## Escalation

Escalate if any of the following are true:

- The disk is full and no safe cleanup option frees meaningful space.
- PostgreSQL reports data corruption after a disk-full event.
- The volume is on a filesystem that cannot be expanded.
- Audit data was deleted unintentionally.

Include when escalating:

- Output of `df -h` and `du -xh --max-depth=1 /var | sort -rh | head`.
- Output of `journalctl --disk-usage`.
- Database size and the largest tables from the diagnosis queries.
- The last 100 lines of `journalctl -u openwatch`.

---

## Prevention

### Bound the journal

OpenWatch logs to the systemd journal, so an unbounded journal is the most common
self-inflicted disk-fill. Set a cap in `/etc/systemd/journald.conf`:

```ini
[Journal]
SystemMaxUse=1G
```

Restart `systemd-journald` after changing it.

### Monitor disk usage

Use your existing host monitoring (for example a `node_exporter` filesystem
alert or a cron check on `df`) to alert before the disk fills. OpenWatch does not
expose its own filesystem metrics endpoint—see below.

### Plan database growth

Size the PostgreSQL volume for expected growth and review the largest tables
(diagnosis Step 5) periodically. The `transactions` table uses a write-on-change
model and the `host_rule_state` table holds one row per host and rule, so both
stay bounded; `audit_events` grows monotonically and should be the focus of any
retention planning.

---

## Not yet implemented

OpenWatch is currently `v0.2.0-rc.17`, a pre-release. The following do not exist in
the current code and must not be relied on:

- **Automated retention / pruning jobs** for `audit_events` or other tables.
  Cleanup is manual (path C). This is roadmap work.
- **A Prometheus or metrics endpoint** exposing disk or database size. Use host-
  level monitoring instead. The only built-in HTTP probe is
  `GET /api/v1/health`, which reports liveness and database connectivity, not
  capacity.
- **A backup or restore command in the `openwatch` CLI.** Use standard PostgreSQL
  tooling (`pg_dump` / `pg_basebackup`) for backups. The CLI subcommands are
  `serve`, `worker`, `migrate`, `create-admin`, and `check-config`.
