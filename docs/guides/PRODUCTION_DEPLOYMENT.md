# Production deployment guide

**Last Updated:** 2026-06-25 · **Applies to:** OpenWatch 0.2.0-rc series (Go single-binary)

This guide covers running OpenWatch in production: a single Go binary that serves
the REST API and the embedded React UI over HTTPS, backed by PostgreSQL, managed
by `systemd`. There is no container runtime, no separate web tier, no Redis, and
no Celery — those belonged to the archived Python stack and are gone.

For first-time install and database provisioning, follow the canonical
[install guide](INSTALLATION.md). This document does **not**
repeat those steps; it focuses on production concerns the install guide only
touches lightly: process layout, TLS, the background worker, backups, upgrades,
and incident runbooks.

> Verify the version you deploy. The current line is a pre-release
> (`0.2.0-rc.14` per `packaging/version.env`), not a GA build. Treat it
> accordingly until a GA tag ships.

---

## Architecture in production

One binary, `/usr/bin/openwatch`, provides every runtime role through
subcommands (`cmd/openwatch/main.go`):

| Subcommand | Role | Long-running |
|------------|------|--------------|
| `serve` | HTTPS API + embedded UI, schedulers (liveness, intelligence, discovery), event bus, alert router | Yes — this is the service unit |
| `worker` | Scan-job claimer/dispatcher loop; drains the PostgreSQL job queue and runs Kensa scans | Yes — optional separate unit |
| `migrate` | Apply pending database migrations, then exit | No |
| `create-admin` | Create the first admin user, then exit | No |
| `check-config` | Validate and print the resolved config (secrets redacted), then exit | No |

The packaged `openwatch.service` runs `openwatch serve`
(`packaging/common/openwatch.service`). The `serve` process also runs the
in-process schedulers, so a minimal single-node deployment needs only that one
unit. The `worker` subcommand exists for separating scan execution onto its own
process or host; it is HTTP-free and shares the same boot prerequisites
(config, DB pool, audit, license, JWT key, credential DEK) as `serve`. There is
no packaged `worker` unit yet — running `worker` as its own service is a manual
step today (write a unit that runs `ExecStart=/usr/bin/openwatch worker`).

| Component | Where | Notes |
|-----------|-------|-------|
| API + UI | `https://<host>:8443/` | UI embedded via `go:embed`; API under `/api/v1/` |
| Database | PostgreSQL 14+ | The only datastore. Not provisioned by the package. |
| Job queue | PostgreSQL table, `SKIP LOCKED` | No external broker. Drained by `serve`/`worker`. |
| Compliance engine | Kensa (Go), in-process | SSH-based, native YAML rules. See [the boundary doc](../KENSA_OPENWATCH_BOUNDARY.md). |


---

## Prerequisites

See the [install guide requirements](INSTALLATION.md#requirements)
for the authoritative list. In short:

- A supported RHEL-family or Debian-family host with `systemd`.
- PostgreSQL 14 or newer, reachable from the OpenWatch host.
- TCP/8443 inbound (API + UI); TCP/22 outbound to every managed host (Kensa scans
  over SSH).
- A CA-signed TLS certificate for any non-loopback use.

---

## Install and first run

Follow the [install guide](INSTALLATION.md) end to end:

1. Install and provision PostgreSQL.
2. Install the signed `.rpm`/`.deb` (verify `SHA256SUMS.asc` against `KEYS` first).
3. Set `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env`.
4. Run `openwatch migrate`.
5. Run `openwatch create-admin --username admin --email you@example.com`.
6. `systemctl enable --now openwatch`.
7. Sign in at `https://<host>:8443/`.

Before starting the service, validate the resolved configuration:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch check-config
```

It prints the effective config with secrets redacted and exits non-zero if the
config is invalid.

---

## Configuration

Config layers, highest precedence first (`cmd/openwatch/main.go`):

1. CLI flags (`--listen`, `--log-level`, `--config`)
2. Environment variables (`OPENWATCH_<SECTION>_<KEY>`)
3. The TOML file (`/etc/openwatch/openwatch.toml`)
4. Built-in defaults

The TOML file has four sections (`internal/config/config.go`,
`packaging/common/openwatch.toml`):

| Section | Key | Default | Purpose |
|---------|-----|---------|---------|
| `[server]` | `listen` | `0.0.0.0:8443` | Bind address and port for API + UI |
| `[server]` | `tls_cert` | `/etc/openwatch/tls/cert.pem` | TLS certificate |
| `[server]` | `tls_key` | `/etc/openwatch/tls/key.pem` | TLS private key |
| `[database]` | `dsn` | — | PostgreSQL DSN (set via `secrets.env` in production) |
| `[database]` | `max_connections` | `25` | Connection-pool ceiling |
| `[logging]` | `level` | `info` | `debug` / `info` / `warn` / `error` |
| `[logging]` | `format` | `json` | `json` / `text` |

Two more values come from `[identity]` and must be set for `serve`/`worker` to
boot — the JWT signing key (`jwt_private_key`) and the credential DEK file
(`credential_key_file`). Without them the process exits at startup rather than
running with a silent fallback (see `cmdServe` in `cmd/openwatch/main.go`).

Keep the database password out of the world-readable TOML by putting the DSN in
`/etc/openwatch/secrets.env`, which the `systemd` unit loads via
`EnvironmentFile`:

```
OPENWATCH_DATABASE_DSN=postgres://openwatch:STRONG_PW@db.internal:5432/openwatch?sslmode=require
```

Set the file to `0640`, owner `root:openwatch`. Use `sslmode=require` or stronger
for any PostgreSQL not on the loopback interface.

---

## TLS

The package ships a self-signed certificate so the service starts out of the box.
Replace it before any non-loopback use:

```bash
sudo cp your-cert.pem /etc/openwatch/tls/cert.pem
sudo cp your-key.pem  /etc/openwatch/tls/key.pem
sudo chown root:openwatch      /etc/openwatch/tls/cert.pem
sudo chown openwatch:openwatch /etc/openwatch/tls/key.pem
sudo chmod 0644 /etc/openwatch/tls/cert.pem
sudo chmod 0600 /etc/openwatch/tls/key.pem
sudo systemctl restart openwatch
```

The server reads the certificate on each TLS handshake, so new connections pick
up a swapped cert without a restart; restart anyway to cover existing keep-alive
connections.

---

## Service hardening

The packaged unit (`packaging/common/openwatch.service`) already applies
`systemd` sandboxing. Keep these in place:

| Directive | Value | Effect |
|-----------|-------|--------|
| `User` / `Group` | `openwatch` | Runs unprivileged |
| `NoNewPrivileges` | `true` | No setuid escalation |
| `ProtectSystem` | `strict` | Read-only filesystem except `ReadWritePaths` |
| `ProtectHome` | `true` | No access to `/home`, `/root` |
| `PrivateTmp` | `true` | Private `/tmp` |
| `ReadWritePaths` | `/var/lib/openwatch /var/log/openwatch` | Only writable paths |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_UNIX` | No raw sockets unless granted |
| `Restart` | `on-failure` (`RestartSec=5s`) | Auto-restart on crash |

If you front OpenWatch with a reverse proxy or load balancer, terminate or
pass through TLS to 8443 — there is no separate HTTP listener to target.

---

## Health, version, and logs

OpenWatch exposes two anonymous endpoints for probes (`api/openapi.yaml`):

```bash
curl -k https://localhost:8443/api/v1/health
# 200 {"status":"healthy","db_connected":true,"version":"..."}
# 503 when the database ping fails (status "degraded"/unavailable)

curl -k https://localhost:8443/api/v1/version
# {"openwatch":"...","kensa":"...","go":"...","commit":"...","build_time":"..."}
```

`/api/v1/health` returns `200` with `db_connected:true` when healthy and `503`
when the database ping inside the handler fails. Use it as your liveness and
readiness probe.

The service logs structured JSON to journald:

```bash
sudo journalctl -u openwatch -f                   # tail live
sudo journalctl -u openwatch --since '5 min ago'  # recent
sudo journalctl -u openwatch -o cat | jq .        # pretty-print
```

> Prometheus-style `/metrics` scraping is **not yet implemented** — there is no
> HTTP metrics endpoint. The in-process connectivity-monitor metrics are exposed
> only through the authenticated `GET /api/v1/system/connectivity/status`
> endpoint, not via an open-text scrape target. For production observability
> today, rely on `/api/v1/health` and the journald logs.

---

## Background scan worker

The `serve` process drains the job queue on its own, so a single-node install
needs nothing extra. To run scan execution as a dedicated process (separate
resource limits, or a separate host), run the `worker` subcommand:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch worker --poll-interval 1s
```

`--poll-interval` controls the empty-queue sleep between dequeue attempts
(`worker.DefaultPollInterval`, 1s default, 5s max — `cmd/openwatch/worker.go`).
The worker needs the same `secrets.env`, JWT key, and credential DEK as `serve`,
because it decrypts host credentials and derives the queue HMAC key from the DEK.
There is no packaged worker unit; if you split it out, model a unit on
`openwatch.service` with `ExecStart=/usr/bin/openwatch worker`.

---

## Upgrades

```bash
# RHEL family
sudo dnf upgrade ./openwatch-<new-version>.rpm

# Debian family
sudo apt install ./openwatch_<new-version>_amd64.deb
```

After the package upgrade:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
sudo systemctl restart openwatch
```

`openwatch migrate` applies any new migrations from
`internal/db/migrations/` and is a safe no-op when the schema is already current.
Restart the service (and the worker, if you run one separately) to load the new
binary. Take a database backup before upgrading (see below). Config under
`/etc/openwatch/` is preserved across package upgrades.

---

## Backup and restore

OpenWatch keeps all durable state in PostgreSQL. Back up the database with the
standard PostgreSQL tooling — there is no OpenWatch-specific backup command.

```bash
# Backup
pg_dump -h 127.0.0.1 -U openwatch -d openwatch -Fc -f openwatch-$(date -u +%Y-%m-%dT%H-%M-%SZ).dump

# Restore into a freshly created, empty database
pg_restore -h 127.0.0.1 -U openwatch -d openwatch --clean --if-exists openwatch-<timestamp>.dump
```

Also back up `/etc/openwatch/` — it holds the TLS material, the JWT signing key,
the credential DEK, and `secrets.env`. Losing the credential DEK makes stored SSH
credentials and MFA secrets unrecoverable. Test restores periodically; a backup
you have never restored is a hypothesis, not a backup.

---

## Operational runbooks

Concise, single-binary runbooks follow. Diagnose with `systemctl`, `journalctl`,
`psql`, `df`, and `top` — not `docker`. The standalone files under
[`docs/runbooks/`](../runbooks/) still describe the archived Python/Docker stack
and are pending a Go-era rewrite; prefer the steps below until they are updated.

### SERVICE_DOWN — service unavailable

Symptoms: `https://<host>:8443/` refuses connections, or `/api/v1/health` times
out or returns `503`.

```bash
sudo systemctl status openwatch
sudo journalctl -u openwatch --since '10 min ago' -p err
curl -k https://localhost:8443/api/v1/health
```

1. If the unit is `failed`/`inactive`, read the journal for the boot error.
   Common causes: malformed `OPENWATCH_DATABASE_DSN`, unreadable TLS cert, or a
   missing `jwt_private_key` / `credential_key_file`.
2. If `/api/v1/health` returns `503` with `db_connected:false`, treat it as a
   database problem (see DATABASE_ISSUES below).
3. Confirm the config is valid, then restart:
   ```bash
   sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch check-config
   sudo systemctl restart openwatch
   ```
4. Verify recovery: `curl -k https://localhost:8443/api/v1/health` returns `200`.

### DATABASE_ISSUES — database connectivity

Symptoms: `/api/v1/health` reports `db_connected:false`; journal shows
`db: ping:` errors.

```bash
sudo systemctl status postgresql
PGPASSWORD=... psql -h 127.0.0.1 -U openwatch -d openwatch -c 'SELECT 1;'
```

1. `connection refused` → PostgreSQL is down: `sudo systemctl restart postgresql`.
2. `password authentication failed` → the DSN in `secrets.env` or `pg_hba.conf`
   is wrong. Recheck both, then `sudo systemctl reload postgresql`.
3. Pool exhaustion under load → raise `[database].max_connections` (and the
   server's `max_connections`), then restart OpenWatch.
4. Re-test with `curl -k https://localhost:8443/api/v1/health`.

### DISK_FULL — disk space exhausted

Symptoms: writes fail; the journal shows `no space left on device`; the service
may crash-loop.

```bash
df -h
sudo du -xh /var/log/openwatch /var/lib/openwatch 2>/dev/null | sort -rh | head
sudo du -xh /var/lib/pgsql /var/lib/postgresql 2>/dev/null | sort -rh | head
```

1. Reclaim journald space if logs dominate:
   ```bash
   sudo journalctl --vacuum-size=500M
   ```
2. If PostgreSQL data is large, check table bloat and run maintenance:
   ```bash
   psql -h 127.0.0.1 -U openwatch -d openwatch -c "\
     SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) AS size \
     FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10;"
   psql -h 127.0.0.1 -U openwatch -d openwatch -c "VACUUM (ANALYZE);"
   ```
3. The transaction-log/write-on-change model bounds growth (`transactions` plus a
   fixed-size `host_rule_state`), so unbounded growth usually means audit/event
   retention or PostgreSQL WAL — not scan results. Investigate before deleting.
4. After freeing space: `sudo systemctl restart openwatch` and re-check `df -h`.

### HIGH_CPU — sustained high CPU

Symptoms: load high; UI/API latency up.

```bash
top -b -n1 | head -20
sudo journalctl -u openwatch --since '15 min ago' | jq -r 'select(.level=="WARN" or .level=="ERROR")'
psql -h 127.0.0.1 -U openwatch -d openwatch -c "\
  SELECT pid, state, wait_event_type, left(query,80) FROM pg_stat_activity \
  WHERE datname='openwatch' ORDER BY state;"
```

1. If `postgres` backends dominate, look for long-running or stuck queries in
   `pg_stat_activity` and for a missing `VACUUM`/`ANALYZE`.
2. If the `openwatch` process dominates, a scan burst or a tight scheduler loop is
   the usual cause. The intelligence and discovery schedulers can be paused
   without a restart by setting `maintenance_global=true`:
   ```bash
   # via the API, as an admin token:
   # PUT /api/v1/system/intelligence/config   {"maintenance_global": true}
   # PUT /api/v1/system/discovery/config      {"maintenance_global": true}
   ```
3. If a separate `worker` is saturating the host, raise `--poll-interval` toward
   its 5s ceiling, or move the worker to its own host.
4. Re-check `top` and API latency after each change; re-enable maintenance flags
   when load normalizes.

### SECURITY_INCIDENT — suspected compromise

1. **Preserve evidence first.** Do not wipe the host. Capture the journal and the
   audit trail:
   ```bash
   sudo journalctl -u openwatch --since '24 hours ago' > /tmp/openwatch-journal.log
   ```
   OpenWatch writes an immutable audit event stream to PostgreSQL (see
   `docs/engineering/audit_event_taxonomy.md`); export the relevant range via the
   audit query API or `psql` before any remediation.
2. **Contain.** Stop accepting traffic without destroying state:
   ```bash
   sudo systemctl stop openwatch
   ```
   Or block 8443 at the firewall if you need the process alive for forensics.
3. **Rotate secrets** in `/etc/openwatch/` — the JWT signing key, credential DEK,
   and database password. Rotating the JWT key invalidates all sessions
   (everyone re-authenticates). Rotating the DEK requires re-encrypting stored
   credentials; plan that change deliberately.
4. **Review access.** Audit admin accounts and roles
   (`docs/engineering/rbac_registry.md`) and revoke anything unexpected.
5. **Restore from a known-good backup** only after the root cause is understood
   (see Backup and restore above).
6. Document the timeline and follow your organization's incident process.

---

## Quick reference

| Item | Value |
|------|-------|
| UI + API | `https://<host>:8443/` (API under `/api/v1/`) |
| Binary | `/usr/bin/openwatch` |
| Service unit | `openwatch.service` (runs `openwatch serve`) |
| Config | `/etc/openwatch/openwatch.toml` |
| DB secret | `/etc/openwatch/secrets.env` (`OPENWATCH_DATABASE_DSN`) |
| TLS | `/etc/openwatch/tls/{cert,key}.pem` |
| Data / logs | `/var/lib/openwatch`, `/var/log/openwatch`, journald |
| User / group | `openwatch:openwatch` |
| Health probe | `GET /api/v1/health` |
| Migrate | `openwatch migrate` |
| Restart | `sudo systemctl restart openwatch` |
| Logs | `journalctl -u openwatch -f` |

---

## See also

- [Install guide](INSTALLATION.md) — canonical install and provisioning.
- [Kensa ↔ OpenWatch boundary](../KENSA_OPENWATCH_BOUNDARY.md) — compliance engine integration.
- [RBAC registry](../engineering/rbac_registry.md) — roles and permissions.
- [API contract](../../api/openapi.yaml) — every endpoint, its permission, and audit events.
- [Releasing runbook](../runbooks/RELEASING.md) — building and signing releases.
