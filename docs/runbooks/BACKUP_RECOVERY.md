# Backup and recovery

**Last updated:** 2026-07-30 · **Applies to:** OpenWatch v0.8.0 (Eyrie)

This guide covers backup, restore, and disaster recovery for an OpenWatch
deployment. OpenWatch is a single Go binary (`/usr/bin/openwatch`) that serves
the REST API and the embedded React UI over HTTPS on port `8443`, backed by
PostgreSQL and managed by `systemd`. There is no container runtime, no Redis,
and no separate web tier to back up.

For install and first-run setup, see
[Installation](../guides/INSTALLATION.md). This
document assumes the layout that guide produces.

## What you need to back up

Three things must be backed up together, from the same moment, with the
service stopped. A database dump alone is not a complete backup, and neither
is a dump plus the configuration.

| Item | Path | Why it matters | Recoverable without backup? |
|------|------|----------------|-----------------------------|
| PostgreSQL database | external PostgreSQL server | Hosts, scans, transactions, findings, users, roles, encrypted credentials, audit events, job queue, system config | No |
| Remediation rollback store | `/var/lib/openwatch/kensa/` (`remediation.db` plus its `-wal` and `-shm` files) | Kensa's durable capture of each host's pre-change state. A rollback of an executed or staged fix reads it; PostgreSQL holds only the journal of what happened, not the bytes needed to undo it | No: a fix executed before the loss can no longer be rolled back |
| Credential encryption key | `/etc/openwatch/keys/credential.key` | AES-256 key that encrypts stored SSH credentials and MFA secrets in the database | No |
| JWT signing key | `/etc/openwatch/keys/jwt_private.pem` | Signs access tokens; losing it means clients re-authenticate (sessions and refresh tokens are in the database and survive) | Partially |
| Database secret | `/etc/openwatch/secrets.env` | Holds `OPENWATCH_DATABASE_DSN` | No |
| Configuration | `/etc/openwatch/openwatch.toml` | Server, database, and logging settings | Re-creatable by hand |
| TLS certificate and key | `/etc/openwatch/tls/cert.pem`, `/etc/openwatch/tls/key.pem` | Serves HTTPS on `8443` | Re-issuable from your CA |

> The rollback store is easy to forget because nothing in the UI names it. It
> is set by the service unit (`OPENWATCH_KENSA_STORE_PATH`) and required by the
> packaging contract to be durable, and it only matters on the day you need to
> undo a remediation. Copy it with the service stopped so the WAL is quiescent.

> The `credential.key` is the most important non-database item. SSH credentials
> and MFA secrets in the database are encrypted with it. If you restore a
> database dump but lose `credential.key`, those secrets are unrecoverable and
> you must re-enter every host credential. Back up `credential.key` and the
> database together, and store the key with at least the same protection as the
> database.

The default key paths above come from the shipped configuration; confirm yours with
`sudo -u openwatch openwatch check-config`, which prints the resolved
`jwt_private_key` and `credential_key_file` paths.

### What you do not need to back up

- **Application logs.** Logs go to the `systemd` journal (`journalctl -u
  openwatch`); `/var/log/openwatch` exists but the journal is primary. Back up
  the journal only if your retention policy requires it.
- **The job queue.** Background jobs use a PostgreSQL-native queue
  (`SKIP LOCKED`) inside the same database, so the database dump already covers
  it. There is no separate queue store to back up.
- **Compliance scan content.** Kensa rules are native YAML bundled with the
  install; they are not user data.

## Backup procedure

> **Before you start**
> - **You need:** a reachable PostgreSQL server, `/var/backups/openwatch/` created `root 0700`, and a passphrase for the encrypted state archive kept in your secrets manager.
> - **Run as:** root, with `/etc/openwatch/secrets.env` loaded into the shell (`set -a; . /etc/openwatch/secrets.env; set +a`).
> - **What changes:** nothing on the OpenWatch host; it writes a dump and an encrypted archive under `/var/backups/openwatch/`.
> - **Verify with:** `pg_restore --list` on the dump and a test restore into a scratch database, as in [Verify a backup](#verify-a-backup).
> - **Recover by:** deleting a bad backup file; a backup never alters the running service.

OpenWatch connects to an external PostgreSQL instance. Run `pg_dump` against
that server. The DSN is in `/etc/openwatch/secrets.env` as
`OPENWATCH_DATABASE_DSN`.

The examples below write to `/var/backups/openwatch/`. Nothing creates that
directory for you; the package creates only `/var/lib/openwatch/backups/`,
where the upgrade scriptlet writes its own pre-upgrade dump (see the
[upgrade procedure](UPGRADE_PROCEDURE.md)). Create it once, readable by no
one but root:

```bash
sudo install -d -m 0700 /var/backups/openwatch
```

### Who runs these commands

Run the backup and restore commands as **root**. `/etc/openwatch/secrets.env`
is `root:openwatch 0640` and `/var/backups/openwatch/` is `root 0700`, so an
ordinary administrator account can read neither, and the service user cannot
read the backup directory. Root loads the DSN and connects as the `openwatch`
database role it names. Load the file into the environment once per shell:

```bash
sudo -i
set -a; . /etc/openwatch/secrets.env; set +a   # exports OPENWATCH_DATABASE_DSN
```

Every block below assumes that root shell.

### Database dump

Use a compressed custom-format dump. It restores faster and supports selective
restore.

```bash
pg_dump "$OPENWATCH_DATABASE_DSN" \
    --format=custom \
    --file="/var/backups/openwatch/openwatch_$(date -u +%Y%m%dT%H%M%SZ).dump"
```

The timestamp uses UTC (ISO 8601). For a plain-text dump you can inspect, drop
`--format=custom` and redirect to a `.sql` file.

### Configuration, keys and the rollback store

Back up the keys, secrets and the Kensa rollback store alongside the database
dump, from the same moment. These are secrets: store them encrypted and
restrict access. Stop the service first so the SQLite store is not mid-write.

```bash
systemctl stop openwatch
tar czf - \
    /etc/openwatch/keys/ \
    /etc/openwatch/secrets.env \
    /etc/openwatch/openwatch.toml \
    /etc/openwatch/tls/ \
    /var/lib/openwatch/kensa/ \
  | openssl enc -aes-256-cbc -salt -pbkdf2 \
      -out "/var/backups/openwatch/state_$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc"
systemctl start openwatch
```

For a consistent set, take the database dump inside the same stop window.

### Verify a backup

A backup you have not verified is not a backup. List the contents of a dump
without restoring it:

```bash
pg_restore --list /var/backups/openwatch/openwatch_<timestamp>.dump >/dev/null \
  && echo "dump readable"
```

For a stronger check, restore into a throwaway database and compare row counts:

```bash
createdb "$RESTORE_DSN_DB"
pg_restore --dbname="$RESTORE_DSN" --no-owner --no-privileges \
    /var/backups/openwatch/openwatch_<timestamp>.dump
psql "$RESTORE_DSN" -c \
    "SELECT 'hosts' AS t, count(*) FROM hosts
     UNION ALL SELECT 'scan_runs', count(*) FROM scan_runs
     UNION ALL SELECT 'users', count(*) FROM users;"
dropdb "$RESTORE_DSN_DB"
```

Scans live in `scan_runs` and `scan_results`; there is no `scans` table. If a
query names a table your schema does not have, the authoritative list is the
set of migrations the binary applied (`openwatch migrate --status`).

### Scheduling

Run the database dump and the state archive on a schedule that meets your
recovery point objective. A `systemd` timer or `cron` entry that calls a
wrapper script covering both, inside one stop window, is sufficient. The
upgrade scriptlet also leaves a pre-upgrade dump in
`/var/lib/openwatch/backups/` on every package upgrade; that is a restore
point for the schema, not a substitute for this schedule. That dump is plain
SQL, not the custom format this guide's `pg_restore` commands read. Restore it
with the steps in the upgrade procedure's
[Full rollback](UPGRADE_PROCEDURE.md#full-rollback-the-schema-advanced). Apply a
retention policy (for example, `find /var/backups/openwatch -name '*.dump'
-mtime +30 -delete`) and copy backups off-host.

## Restore procedure

> **Before you start**
> - **You need:** the database dump and the state archive from the same backup generation, plus its passphrase.
> - **Run as:** root, with `/etc/openwatch/secrets.env` loaded into the shell.
> - **What changes:** the entire database (`--clean --if-exists` replaces current contents), `credential.key`, and the rollback store; the service is stopped for the duration.
> - **Verify with:** `pg_restore` exit 0, then the checks in [Prove the restored service works](#prove-the-restored-service-works): the rule library loaded and one scan completed. Health alone is not proof. Last, a signed-in check that an executed remediation still offers **Roll back**.
> - **Recover by:** restoring the previous generation the same way; take a fresh dump of the current state first if it has any value.

### Restore the database

1. Stop the service so nothing writes while you restore:

   ```bash
   systemctl stop openwatch
   ```

2. Restore into the OpenWatch database. With a custom-format dump, the
   connection goes in `--dbname` and the dump is the only positional
   argument:

   ```bash
   pg_restore --dbname="$OPENWATCH_DATABASE_DSN" \
       --clean --if-exists --no-owner --no-privileges \
       /var/backups/openwatch/openwatch_<timestamp>.dump
   echo "pg_restore exit $?"
   ```

   The exit status must be 0. `--clean --if-exists` drops existing objects
   first, so the restore replaces current contents. If you restore into a
   fresh, empty database instead, omit those flags.

3. Apply any migrations newer than the dump (a no-op when the schema is
   already current; `migrate --status` tells you):

   ```bash
   openwatch migrate --status
   openwatch migrate
   ```

4. Restore the configuration, keys and rollback store (next section), then
   start the service with the checks in
   [Prove the restored service works](#prove-the-restored-service-works).
   Do not start it with a bare `systemctl start` and a health check: health
   reports `healthy` even when the rule library failed to load and every scan
   fails.

### Restore configuration, keys and the rollback store

Restore `credential.key` and the rollback store from the same backup
generation as the database dump. A mismatched key cannot decrypt stored
credentials; a mismatched store describes host states the database does not
know about.

```bash
systemctl stop openwatch
openssl enc -aes-256-cbc -d -pbkdf2 \
    -in /var/backups/openwatch/state_<timestamp>.tar.gz.enc \
  | tar xzf - -C /

chown openwatch:openwatch /etc/openwatch/keys/credential.key
chmod 0600 /etc/openwatch/keys/credential.key
chown -R openwatch:openwatch /var/lib/openwatch/kensa
```

Then start the service with the checks in
[Prove the restored service works](#prove-the-restored-service-works). After
those pass, sign in, open a host that had an executed remediation, and
confirm its **Roll back** control is still offered. That control is what the
rollback store buys you.

### Prove the restored service works

A `200` from `/api/v1/health` does not prove the service works. On a host
where the Kensa rule library fails to load, the service still starts, health
still answers `healthy`, and every scan and remediation fails. The service
logs that only as a warning (CP `bugs/OW-094`). So a restore is done only
when both blocks below finish:

1. The first block restarts the service and proves it loaded its rule
   library. It prints `VERIFIED` only after every check passes.
2. The second block runs one compliance scan end to end. It prints
   `SCANNED` only when the scan completes with no rule errors.

Each block runs in a subshell with `set -euo pipefail`. Any failed check
stops the block, prints the line it stopped on, and prints no success line.

#### The API tokens

Both blocks call the API with a token passed to `curl` on standard input, so
the token never appears in the process list or the shell history. Neither
block prints it.

| Block | Permission it needs | A built-in role that has it |
|---|---|---|
| Rule library check | `scan:read` | `viewer` |
| Scan check | `host:write` and `scan:read` | `ops_lead`, `security_admin` or `admin` |

The token must be valid in the **restored** database. That means it was
created before the backup you restored was taken, and not revoked since. A
token created after that backup does not exist in the restored database, and
the API answers `401`. Keep each token in a root-only file, for example:

```bash
( umask 077; printf '%s' 'owk_<the token>' > /root/openwatch-verify.token )
```

Create the tokens while the service is healthy, before you need a restore,
and keep them with the backup plan.

#### Check that the rule library loaded

Fill in the value at the top. The block stops waiting for health after
`HEALTH_WAIT` seconds (120), and gives the `/api/v1/rules` request at most 30
seconds, so it finishes or stops within two and a half minutes. Each request
also has a 5-second connection timeout, so a port that never answers cannot
stall it.

```bash
(
  set -euo pipefail
  TOKEN_FILE='<root-only-file-holding-an-owk-token-valid-in-the-restored-database>'
  URL=https://localhost:8443
  HEALTH_WAIT=120
  trap 'echo "VERIFY STOPPED at line $LINENO. The service did not prove it loaded its rule library. Stopping it." >&2; systemctl stop openwatch || echo "Could not stop openwatch; stop it yourself." >&2' ERR
  case "$TOKEN_FILE" in
    *'<'*) echo "fill in the value at the top first" >&2; false ;;
  esac
  test -r "$TOKEN_FILE"
  TOKEN=$(cat "$TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]

  SINCE=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart openwatch
  READY=no
  END=$((SECONDS + HEALTH_WAIT))
  while [ "$SECONDS" -lt "$END" ]; do
    LEFT=$((END - SECONDS))
    if [ "$LEFT" -gt 10 ]; then LEFT=10; fi
    if curl -skf --connect-timeout 5 --max-time "$LEFT" -o /dev/null "$URL/api/v1/health"; then
      READY=yes
      break
    fi
    if [ $((SECONDS + 2)) -ge "$END" ]; then break; fi
    sleep 2
  done
  [ "$READY" = yes ]
  LOG=$(journalctl -u openwatch --since "$SINCE" --no-pager -o cat)
  [[ "$LOG" != *"kensa scan wiring unavailable"* ]]
  [[ "$LOG" != *"kensa rule library unavailable"* ]]
  RULES=$(curl -sk --connect-timeout 5 --max-time 30 -o /dev/null -w '%{http_code}' -K - "$URL/api/v1/rules" <<<"header = \"Authorization: Bearer $TOKEN\"")
  [ "$RULES" = 200 ]
  trap - ERR
  echo "VERIFIED: openwatch restarted, answered health, and loaded its rule library"
)
```

If the block stops, it stops the service so nothing runs half-working. Read
`journalctl -u openwatch -n 200 --no-pager`. A `load rule corpus` error names
the rule file that failed. Check that the installed `kensa-rules` package
matches the installed `openwatch` (`rpm -q openwatch kensa-rules` and
`rpm -V kensa-rules`, or `dpkg-query -W openwatch kensa-rules` and
`dpkg --audit`). Fix the cause, then run the block again.

#### Run one scan end to end

Pick a host that was reachable before the restore. Its ID is in the UI's host
page URL, or in `GET /api/v1/hosts`. Fill in the two values at the top. The
block starts one on-demand scan, then polls it for up to `SCAN_WAIT` seconds
(900). Each request has a 5-second connection timeout and a 30-second limit.

```bash
(
  set -euo pipefail
  SCAN_TOKEN_FILE='<root-only-file-holding-an-owk-token-with-host-write-and-scan-read>'
  HOST_ID='<id-of-a-host-that-was-reachable-before-the-restore>'
  URL=https://localhost:8443
  SCAN_WAIT=900
  trap 'echo "SCAN CHECK STOPPED at line $LINENO. Do not call the restore complete." >&2' ERR
  case "$SCAN_TOKEN_FILE $HOST_ID" in
    *'<'*) echo "fill in the two values at the top first" >&2; false ;;
  esac
  [[ "$HOST_ID" =~ ^[0-9a-fA-F-]{36}$ ]]
  test -r "$SCAN_TOKEN_FILE"
  TOKEN=$(cat "$SCAN_TOKEN_FILE")
  [[ "$TOKEN" == owk_* ]]
  AUTH="header = \"Authorization: Bearer $TOKEN\""
  KEY=$(cat /proc/sys/kernel/random/uuid)

  RESP=$(curl -sk --connect-timeout 5 --max-time 30 -w '\n%{http_code}' -X POST \
      -H "Idempotency-Key: $KEY" -K - "$URL/api/v1/hosts/$HOST_ID/scans" <<<"$AUTH")
  CODE=${RESP##*$'\n'}
  [ "$CODE" = 202 ]
  SCAN_ID=$(python3 -I -S -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])' <<<"${RESP%$'\n'*}")
  [[ "$SCAN_ID" =~ ^[0-9a-fA-F-]{36}$ ]]

  STATE=unknown
  END=$((SECONDS + SCAN_WAIT))
  while [ "$SECONDS" -lt "$END" ]; do
    BODY=$(curl -skf --connect-timeout 5 --max-time 30 -K - "$URL/api/v1/scans/$SCAN_ID" <<<"$AUTH")
    STATE=$(python3 -I -S -c 'import json,sys; s=json.load(sys.stdin)["scan"]; print(s["status"], s.get("rules_error"))' <<<"$BODY")
    case "$STATE" in
      completed*|failed*) break ;;
    esac
    sleep 10
  done
  [ "$STATE" = "completed 0" ]
  trap - ERR
  echo "SCANNED: scan $SCAN_ID completed with no rule errors"
)
```

A scan that ends `failed`, or completes with rule errors, means the restore is
not done. Read the scan's `failure_reason` in the UI or at
`GET /api/v1/scans/{id}`, and the service journal.

## Disaster recovery (rebuild on a new host)

1. Install the OpenWatch package on the new host (`dnf install` or `apt
   install`) per [Installation](../guides/INSTALLATION.md). This
   creates the `openwatch` user, the binary, `/etc/openwatch/`, and the
   `systemd` unit.
2. Provision PostgreSQL and create the database. The package does not provision
   PostgreSQL.
3. Restore `/etc/openwatch/keys/`, `/etc/openwatch/secrets.env`,
   `/etc/openwatch/openwatch.toml`, `/etc/openwatch/tls/` and
   `/var/lib/openwatch/kensa/` from the encrypted state archive.
4. Restore the database dump into the new PostgreSQL database (see above).
5. Run `openwatch migrate` to apply any pending migrations.
6. Validate config and enable the service at boot:

   ```bash
   sudo -u openwatch openwatch check-config
   sudo systemctl enable openwatch
   ```

7. Start it with the checks in
   [Prove the restored service works](#prove-the-restored-service-works).
   Both blocks must finish before the rebuild is done.

### Recovery objectives

| Scenario | Procedure | Recovery point |
|----------|-----------|----------------|
| Service crash / bad config | Fix config; `openwatch check-config`; then [Prove the restored service works](#prove-the-restored-service-works) | None (no data loss) |
| Database corruption | Restore latest dump; `openwatch migrate` | Last dump |
| Full host loss | Rebuild on new host (above) | Last dump + last key backup |
| Lost `credential.key` | No recovery for stored secrets; re-enter host credentials after restore | Credentials lost |

Measure your actual recovery time against these scenarios; the numbers depend
on database size and your storage.

## Operational runbooks

These cover the common operational alarms for the single binary on `systemd`
with PostgreSQL.

### SERVICE_DOWN: the API is unreachable

```bash
sudo systemctl status openwatch
journalctl -u openwatch -n 100 --no-pager
```

Common causes and checks:

- **Database unreachable.** The log shows `failed to open db pool`. Verify
  `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env` and that PostgreSQL
  is up: `psql "$OPENWATCH_DATABASE_DSN" -c 'SELECT 1;'`.
- **Missing signing or credential key.** The log shows
  `identity.jwt_private_key is empty` or a key-load failure. Confirm the key
  files exist at the paths from `openwatch check-config`.
- **TLS cert or key missing/unreadable.** The log mentions `cert.pem`. Confirm
  `/etc/openwatch/tls/` files exist and the `openwatch` user can read the key.
- **Invalid config.** Run `sudo -u openwatch openwatch check-config`; it
  validates and prints the resolved config with secrets redacted.

After fixing the cause, restart the service with the checks in
[Prove the restored service works](#prove-the-restored-service-works). A
`200` from `/api/v1/health` alone does not show that scans work.

### DISK_FULL: a filesystem is out of space

```bash
df -h
journalctl --disk-usage
du -sh /var/lib/openwatch /var/log/openwatch /var/backups/openwatch 2>/dev/null
```

Likely sources and actions:

- **Journal growth.** Vacuum old logs: `sudo journalctl --vacuum-time=7d` (or
  `--vacuum-size=500M`).
- **Old backups.** Prune per your retention policy under
  `/var/backups/openwatch`.
- **Database growth on the PostgreSQL host.** Inspect with
  `psql "$OPENWATCH_DATABASE_DSN" -c "SELECT pg_size_pretty(pg_database_size(current_database()));"`.
  OpenWatch uses a write-on-change transaction model (one row per host×rule plus
  change records), so steady-state growth is bounded; sudden growth usually
  means the audit-event or job-queue tables. Investigate before deleting
  rows. Do not hand-edit OpenWatch tables.

If the service stopped because the disk filled, free space, then restart it
with the checks in
[Prove the restored service works](#prove-the-restored-service-works).

### HIGH_CPU: the host is CPU-saturated

```bash
top -b -n1 | head -20
systemctl status openwatch
journalctl -u openwatch -n 200 --no-pager | grep -iE 'scheduler|worker|scan'
```

- Confirm whether the `openwatch` process or PostgreSQL is the consumer. Scan
  fan-out and the intelligence/discovery schedulers drive most OpenWatch CPU
  use.
- On the PostgreSQL host, look for expensive queries:
  `psql "$OPENWATCH_DATABASE_DSN" -c "SELECT pid, state, query_start, left(query,80) FROM pg_stat_activity WHERE state <> 'idle' ORDER BY query_start;"`.
- The schedulers honor a maintenance switch. To pause intelligence collection
  while you investigate, an admin can `PUT /api/v1/system/intelligence/config`
  with `maintenance_global=true` (and the discovery equivalent at
  `/api/v1/system/discovery/config`). The startup log notes when either is
  paused.
- As a last resort, `sudo systemctl restart openwatch` clears any runaway
  in-process loop without losing data (queued jobs resume).

### SECURITY_INCIDENT: suspected compromise

1. **Preserve evidence first.** Capture the journal and audit trail before
   changing anything:

   ```bash
   journalctl -u openwatch --since "-24h" > /var/backups/openwatch/incident_journal.txt
   ```

   OpenWatch writes structured audit events (auth, authz, system lifecycle) to
   the database; export the relevant rows for the incident window before any
   restore.

2. **Contain.** Stop the service to halt active sessions and scans:
   `sudo systemctl stop openwatch`. If only network exposure is the concern,
   firewall port `8443` instead.

3. **Rotate secrets.** If a key may be exposed:
   - Rotate the database password and update
     `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env`.
   - Replace the TLS certificate and key in `/etc/openwatch/tls/`.
   - Rotating the JWT signing key (`/etc/openwatch/keys/jwt_private.pem`)
     invalidates all existing sessions and forces re-login.
   - The credential DEK (`/etc/openwatch/keys/credential.key`) cannot be rotated
     by swapping the file alone: stored credentials are encrypted under it. Do
     not replace it without a migration path, or stored host credentials become
     undecryptable.

4. **Review access.** Audit user accounts and role assignments. Roles and
   permissions are defined in
   [User roles](../guides/USER_ROLES.md).

5. **Recover.** If integrity is in doubt, rebuild on a clean host from a
   known-good backup using the disaster-recovery procedure above, then rotate
   all credentials again.

## Not yet implemented

The following are not part of OpenWatch today. Do not script against them.

- **No built-in backup command.** There is no `openwatch backup` or
  `openwatch restore` subcommand (the full list is in the
  [environment reference](../guides/ENVIRONMENT_REFERENCE.md#cli-subcommands)).
  Use `pg_dump`/`pg_restore` and file copies as shown above.
- **No continuous WAL archiving or point-in-time recovery shipped by
  OpenWatch.** If you need PITR, configure it on your PostgreSQL server
  independently; it is a PostgreSQL feature, not an OpenWatch one.
- **No automated off-site replication.** Copying backups off-host is your
  responsibility.

## Reference

| Item | Value |
|------|-------|
| Binary | `/usr/bin/openwatch` |
| Service unit | `openwatch.service` (`User=openwatch`) |
| Config | `/etc/openwatch/openwatch.toml` |
| DB secret | `/etc/openwatch/secrets.env` (`OPENWATCH_DATABASE_DSN`) |
| Encryption keys | `/etc/openwatch/keys/` (`jwt_private.pem`, `credential.key`) |
| TLS | `/etc/openwatch/tls/{cert,key}.pem` |
| Data / logs | `/var/lib/openwatch`, `/var/log/openwatch` (journal is primary) |
| Health probe | `GET https://<host>:8443/api/v1/health` |
| Migrate | `sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch migrate'` |
| Logs | `journalctl -u openwatch -f` |

See also: [Installation](../guides/INSTALLATION.md),
[User roles](../guides/USER_ROLES.md), and the API contract the binary serves at `/api/v1/openapi.yaml`.
