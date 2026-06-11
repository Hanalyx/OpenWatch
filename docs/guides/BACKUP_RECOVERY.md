# Backup and recovery

This guide covers backup, restore, and disaster recovery for an OpenWatch
deployment. OpenWatch is a single Go binary (`/usr/bin/openwatch`) that serves
the REST API and the embedded React UI over HTTPS on port `8443`, backed by
PostgreSQL and managed by `systemd`. There is no container runtime, no Redis,
and no separate web tier to back up.

For install and first-run setup, see
[`docs/engineering/install_guide.md`](../engineering/install_guide.md). This
document assumes the layout that guide produces.

## What you need to back up

Two things must be backed up together. A database dump alone is not a complete
backup.

| Item | Path | Why it matters | Recoverable without backup? |
|------|------|----------------|-----------------------------|
| PostgreSQL database | external PostgreSQL server | Hosts, scans, transactions, findings, users, roles, encrypted credentials, audit events, job queue, system config | No |
| Credential encryption key | `/etc/openwatch/keys/credential.key` | AES-256 key that encrypts stored SSH credentials and MFA secrets in the database | No |
| JWT signing key | `/etc/openwatch/keys/jwt_private.pem` | Signs auth tokens; losing it invalidates all sessions (recoverable by re-issuing) | Partially |
| Database secret | `/etc/openwatch/secrets.env` | Holds `OPENWATCH_DATABASE_DSN` | No |
| Configuration | `/etc/openwatch/openwatch.toml` | Server, database, and logging settings | Re-creatable by hand |
| TLS certificate and key | `/etc/openwatch/tls/cert.pem`, `/etc/openwatch/tls/key.pem` | Serves HTTPS on `8443` | Re-issuable from your CA |

> The `credential.key` is the most important non-database item. SSH credentials
> and MFA secrets in the database are encrypted with it. If you restore a
> database dump but lose `credential.key`, those secrets are unrecoverable and
> you must re-enter every host credential. Back up `credential.key` and the
> database together, and store the key with at least the same protection as the
> database.

The default key paths above come from the shipped configuration
(`internal/config/config.go`); confirm yours with
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

OpenWatch connects to an external PostgreSQL instance. Run `pg_dump` against
that server. The DSN is in `/etc/openwatch/secrets.env` as
`OPENWATCH_DATABASE_DSN`.

### Database dump

Use a compressed custom-format dump. It restores faster and supports selective
restore.

```bash
source /etc/openwatch/secrets.env   # sets OPENWATCH_DATABASE_DSN

pg_dump "$OPENWATCH_DATABASE_DSN" \
    --format=custom \
    --file="/var/backups/openwatch/openwatch_$(date -u +%Y%m%dT%H%M%SZ).dump"
```

The timestamp uses UTC (ISO 8601). For a plain-text dump you can inspect, drop
`--format=custom` and redirect to a `.sql` file.

### Configuration and keys

Back up the encryption keys and secrets alongside the database dump. These are
secrets — store them encrypted and restrict access.

```bash
tar czf - \
    /etc/openwatch/keys/ \
    /etc/openwatch/secrets.env \
    /etc/openwatch/openwatch.toml \
    /etc/openwatch/tls/ \
  | openssl enc -aes-256-cbc -salt -pbkdf2 \
      -out "/var/backups/openwatch/config_$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc"
```

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
     UNION ALL SELECT 'scans', count(*) FROM scans
     UNION ALL SELECT 'users', count(*) FROM users;"
dropdb "$RESTORE_DSN_DB"
```

Confirm table names against your installed schema before relying on them; the
authoritative list is `internal/db/migrations/`.

### Scheduling

Run the database dump and config backup on a schedule that meets your recovery
point objective. A `systemd` timer or `cron` entry that calls a wrapper script
covering both the dump and the encrypted config archive is sufficient. Apply a
retention policy (for example, `find /var/backups/openwatch -name '*.dump'
-mtime +30 -delete`) and copy backups off-host.

## Restore procedure

### Restore the database

1. Stop the service so nothing writes while you restore:

   ```bash
   sudo systemctl stop openwatch
   ```

2. Restore into the OpenWatch database. With a custom-format dump:

   ```bash
   source /etc/openwatch/secrets.env

   pg_restore "$OPENWATCH_DATABASE_DSN" \
       --clean --if-exists --no-owner --no-privileges \
       /var/backups/openwatch/openwatch_<timestamp>.dump
   ```

   `--clean --if-exists` drops existing objects first, so the restore replaces
   current contents. If you restore into a fresh, empty database instead, omit
   those flags.

3. Apply any migrations newer than the dump (safe no-op if the schema is
   already current):

   ```bash
   sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
       openwatch migrate
   ```

4. Start the service and confirm health:

   ```bash
   sudo systemctl start openwatch
   curl -k https://localhost:8443/api/v1/health
   # {"status":"healthy","db_connected":true,"version":"<installed version>"}
   ```

### Restore configuration and keys

Restore `credential.key` from the same backup generation as the database dump.
A mismatched key cannot decrypt stored credentials.

```bash
openssl enc -aes-256-cbc -d -pbkdf2 \
    -in /var/backups/openwatch/config_<timestamp>.tar.gz.enc \
  | sudo tar xzf - -C /

sudo chown -R root:openwatch /etc/openwatch/keys
sudo chmod 0640 /etc/openwatch/keys/credential.key
sudo systemctl restart openwatch
```

## Disaster recovery (rebuild on a new host)

1. Install the OpenWatch package on the new host (`dnf install` or `apt
   install`) per [`install_guide.md`](../engineering/install_guide.md). This
   creates the `openwatch` user, the binary, `/etc/openwatch/`, and the
   `systemd` unit.
2. Provision PostgreSQL and create the database. The package does not provision
   PostgreSQL.
3. Restore `/etc/openwatch/keys/`, `/etc/openwatch/secrets.env`,
   `/etc/openwatch/openwatch.toml`, and `/etc/openwatch/tls/` from the encrypted
   config backup.
4. Restore the database dump into the new PostgreSQL database (see above).
5. Run `openwatch migrate` to apply any pending migrations.
6. Validate config, then start:

   ```bash
   sudo -u openwatch openwatch check-config
   sudo systemctl enable --now openwatch
   curl -k https://localhost:8443/api/v1/health
   ```

### Recovery objectives

| Scenario | Procedure | Recovery point |
|----------|-----------|----------------|
| Service crash / bad config | `systemctl restart openwatch`; fix config; `openwatch check-config` | None (no data loss) |
| Database corruption | Restore latest dump; `openwatch migrate` | Last dump |
| Full host loss | Rebuild on new host (above) | Last dump + last key backup |
| Lost `credential.key` | No recovery for stored secrets; re-enter host credentials after restore | Credentials lost |

Measure your actual recovery time against these scenarios; the numbers depend
on database size and your storage.

## Operational runbooks

These cover the common operational alarms for the single binary on `systemd`
with PostgreSQL.

### SERVICE_DOWN — the API is unreachable

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

After fixing the cause: `sudo systemctl restart openwatch`, then
`curl -k https://localhost:8443/api/v1/health`.

### DISK_FULL — a filesystem is out of space

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
  means the audit-event or job-queue tables. Investigate before deleting rows —
  do not hand-edit OpenWatch tables.

If the service stopped because the disk filled, restart it after freeing space:
`sudo systemctl restart openwatch`.

### HIGH_CPU — the host is CPU-saturated

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

### SECURITY_INCIDENT — suspected compromise

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
     by swapping the file alone — stored credentials are encrypted under it. Do
     not replace it without a migration path, or stored host credentials become
     undecryptable.

4. **Review access.** Audit user accounts and role assignments. Roles and
   permissions are defined in
   [`docs/engineering/rbac_registry.md`](../engineering/rbac_registry.md).

5. **Recover.** If integrity is in doubt, rebuild on a clean host from a
   known-good backup using the disaster-recovery procedure above, then rotate
   all credentials again.

## Not yet implemented

The following are not part of OpenWatch today. Do not script against them.

- **No built-in backup command.** There is no `openwatch backup` or
  `openwatch restore` subcommand. The subcommands are `serve`, `worker`,
  `migrate`, `create-admin`, and `check-config` (`openwatch --help`). Use
  `pg_dump`/`pg_restore` and file copies as shown above.
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
| Migrate | `sudo -u openwatch env $(cat /etc/openwatch/secrets.env \| xargs) openwatch migrate` |
| Logs | `journalctl -u openwatch -f` |

See also: [`install_guide.md`](../engineering/install_guide.md),
[`rbac_registry.md`](../engineering/rbac_registry.md), and the API contract in
[`api/openapi.yaml`](../../api/openapi.yaml).
