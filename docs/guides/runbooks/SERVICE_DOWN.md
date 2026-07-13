# Runbook: service unavailable

**Severity**: P1 - High
**Last updated**: 2026-06-26
**Owner**: Platform engineering
**Estimated resolution time**: 5-30 minutes (typical)

This runbook covers OpenWatch being unreachable or returning errors when it runs
as a native package: a single Go binary, `/usr/bin/openwatch`, managed by systemd
as the `openwatch.service` unit. That one binary serves the REST API and the
embedded React UI over HTTPS on port `8443`. There is no container runtime, no
separate web tier, no Redis, and no Celery. The most common failure modes are the
service being stopped or crash-looping, a TLS or config error that prevents
startup, or PostgreSQL being unreachable.

For install and configuration layout, see the
[install guide](../INSTALLATION.md).

---

## Architecture at a glance

| Component | What it is | How it runs |
|-----------|------------|-------------|
| API + UI server | `openwatch serve`—HTTPS on `8443`, REST under `/api/v1`, embedded SPA | systemd unit `openwatch.service` (`ExecStart=/usr/bin/openwatch serve --config /etc/openwatch/openwatch.toml`) |
| Scan worker | `openwatch worker`—drains the PostgreSQL job queue and runs Kensa scans | Separate process; not shipped as a packaged unit (see "Scan worker" below) |
| Database | PostgreSQL | Separate service (`postgresql.service`); the unit declares `After=`/`Wants=postgresql.service` |

The `serve` process also runs in-process schedulers (host liveness, OS
intelligence, discovery) and an alert router. Scan jobs, by contrast, are
executed by a separate `openwatch worker` process. Both processes read the same
config and the same database; neither uses a message broker.

Configuration lives under `/etc/openwatch`:

| Path | Contents |
|------|----------|
| `/etc/openwatch/openwatch.toml` | Main config (`[server] listen`, `tls_cert`, `tls_key`, `[database] dsn`, `[logging]`) |
| `/etc/openwatch/secrets.env` | `OPENWATCH_DATABASE_DSN` and other secret env overrides; read by the unit via `EnvironmentFile=` |
| `/etc/openwatch/tls/` | `cert.pem` / `key.pem` for the HTTPS listener |

---

## Symptoms

- The UI at `https://<host>:8443/` does not load or times out.
- The health probe fails or returns `503`:
  `curl -sk https://localhost:8443/api/v1/health`.
- `systemctl status openwatch` shows `failed`, `activating (auto-restart)`, or
  `inactive (dead)`.
- `journalctl -u openwatch` shows a fatal boot error (config invalid, TLS key
  missing, JWT key missing, or DB pool open failure).
- Logins fail or writes error while the process is up—usually PostgreSQL is
  unreachable; the health probe returns `503`.

The health endpoint is anonymous and returns a small JSON body. A healthy
response is HTTP `200` with `{"status":"healthy","db_connected":true,"version":"..."}`
(the `HealthResponse` contract: `status`, `db_connected`, `version` only—there
is no `redis` field; earlier Python-era runbooks that reference one are
obsolete). When the database is unreachable, the endpoint does **not** return
a degraded `HealthResponse` body—it returns HTTP `503` with the standard
`ErrorEnvelope` (`"code": "server.unavailable"`) instead.

---

## Diagnosis

### Step 1: Check the service state

```bash
systemctl status openwatch
```

Note the active state and the most recent log lines. `Restart=on-failure` with
`RestartSec=5s` means a crashing binary appears as `activating (auto-restart)`
and cycles every five seconds.

### Step 2: Check the health probe

```bash
curl -sk https://localhost:8443/api/v1/health
```

| Result | Likely cause |
|--------|--------------|
| HTTP `200`, `db_connected: true` | Server is up; the problem is upstream (TLS trust, reverse proxy, network, DNS) |
| HTTP `503` (`ErrorEnvelope`, code `server.unavailable`) | Server is up but PostgreSQL is unreachable (see path B) |
| Connection refused / no response | Process is not listening—it failed to start or crashed (see path A) |
| TLS error | TLS cert/key problem (see path C) |

The `-k` flag skips certificate verification so the probe works with the
self-signed certificate the package ships by default.

### Step 3: Read the logs

OpenWatch logs structured JSON to stdout/stderr, which systemd routes to the
journal (`StandardOutput=journal`, `StandardError=journal`).

```bash
journalctl -u openwatch -n 200 --no-pager
```

Look for the fatal startup messages emitted before the process exits non-zero:

| Log message | Meaning | Path |
|-------------|---------|------|
| `serve: invalid config` | Config failed validation | C |
| `failed to open db pool` | Cannot reach or authenticate to PostgreSQL | B |
| `identity.jwt_private_key is empty` / `load jwt key failed` | JWT signing key missing or unreadable | C |
| `identity.credential_key_file is empty` / `load credential key failed` | Credential encryption key missing or unreadable | C |
| TLS listen / certificate errors | Cert/key missing or unreadable | C |

### Step 4: Validate the resolved config

`check-config` loads the same config layers the service uses (defaults → TOML →
env → flags), prints the resolved values with secrets redacted, and validates
them. Exit `0` means valid.

```bash
sudo -u openwatch /usr/bin/openwatch --config /etc/openwatch/openwatch.toml check-config
```

### Step 5: Confirm PostgreSQL is reachable

```bash
systemctl status postgresql
psql -U openwatch -d openwatch -c "SELECT 1;"
```

Adjust the user, database, and host to match `OPENWATCH_DATABASE_DSN` in
`/etc/openwatch/secrets.env`.

---

## Resolution

### Path A: Process is down or crash-looping

If the process is not listening, first read why it last exited:

```bash
systemctl status openwatch
journalctl -u openwatch -n 100 --no-pager
```

If it exited cleanly (operator stop, host reboot), start it:

```bash
sudo systemctl start openwatch
```

If it is crash-looping, do not restart it blindly—it will fail again. Identify the
fatal log line from Step 3 and follow the matching path (B for database, C for
config/keys/TLS). After fixing the root cause:

```bash
sudo systemctl restart openwatch
```

### Path B: PostgreSQL unreachable

The binary opens its connection pool at startup and exits non-zero if it cannot
(`failed to open db pool`). A running process that loses the database serves
`503` (`ErrorEnvelope`, code `server.unavailable`) from `/api/v1/health`.

```bash
# Is PostgreSQL running?
systemctl status postgresql

# Can you connect with the service's credentials?
psql -U openwatch -d openwatch -c "SELECT 1;"
```

If PostgreSQL is down, start it, then restart OpenWatch:

```bash
sudo systemctl start postgresql
sudo systemctl restart openwatch
```

If PostgreSQL is up but OpenWatch still cannot connect, the DSN is wrong or
credentials/`pg_hba.conf` reject the service. Check the DSN the service actually
uses (`OPENWATCH_DATABASE_DSN` overrides the TOML `dsn`):

```bash
sudo -u openwatch /usr/bin/openwatch --config /etc/openwatch/openwatch.toml check-config
```

The summary prints the DSN with the password redacted; confirm host, port,
database name, user, and `sslmode` match your PostgreSQL setup.

### Path C: Config, key, or TLS startup failure

These all cause `serve` to exit non-zero during boot.

- **Invalid config**: run `check-config` (Step 4) and fix the reported field in
  `/etc/openwatch/openwatch.toml` or the corresponding `OPENWATCH_<SECTION>_<KEY>`
  env override.
- **Missing TLS cert/key**: confirm `tls_cert` and `tls_key`
  (`/etc/openwatch/tls/cert.pem` and `key.pem` by default) exist and are readable
  by the `openwatch` user.

  ```bash
  sudo ls -l /etc/openwatch/tls/
  ```

- **Missing JWT or credential key**: the log names the missing key and the env
  var that sets it (`OPENWATCH_IDENTITY_JWT_PRIVATE_KEY` /
  `OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE`). Confirm the configured path exists
  and is readable. See the [installation guide](../INSTALLATION.md)
  for how these keys are provisioned.

After correcting the file:

```bash
sudo systemctl restart openwatch
```

### Path D: Schema mismatch after an upgrade

If the binary was upgraded but migrations were not applied, the server can start
but error on queries. Apply pending migrations (idempotent), then restart:

```bash
sudo -u openwatch /usr/bin/openwatch --config /etc/openwatch/openwatch.toml migrate
sudo systemctl restart openwatch
```

### Path E: Disk full

A full disk surfaces as PostgreSQL write failures and a failing health probe.
See the [disk space runbook](DISK_FULL.md).

### Path F: Resource exhaustion (OOM)

If the kernel killed the process, the journal shows a restart with no clean
shutdown line. Check for an OOM kill:

```bash
journalctl -k | grep -i "out of memory\|killed process" | tail -20
```

If OpenWatch was the target, investigate memory pressure on the host (other
processes, PostgreSQL `shared_buffers`/`work_mem` sizing) before relying on the
systemd auto-restart. See the [high CPU runbook](HIGH_CPU.md) for load-related triage.

---

## Scan worker

Scans run in a separate `openwatch worker` process that claims jobs from the
PostgreSQL job queue (`SKIP LOCKED`) and runs Kensa checks. The `serve` process
does not execute scan jobs, so the API and UI can be perfectly healthy while
scans pile up because no worker is running.

The package does not ship a systemd unit for the worker today (only
`openwatch.service`, which runs `serve`). If your deployment runs a worker
(through your own unit, a supervisor, or manually), check and restart it
independently:

```bash
# If you manage the worker with your own systemd unit, e.g. openwatch-worker:
systemctl status openwatch-worker
journalctl -u openwatch-worker -n 100 --no-pager
```

Symptoms of a stalled worker: queued scans never complete and `job_queue` rows
accumulate. Inspect the queue directly:

```bash
psql -U openwatch -d openwatch -c "
SELECT job_type, status, count(*)
FROM job_queue
GROUP BY job_type, status
ORDER BY job_type, status;"
```

The worker is HTTP-free and has no health endpoint of its own; rely on its
journal output and the queue depth above.

---

## Recovery verification

### 1. The service is active

```bash
systemctl status openwatch
```

Expect `active (running)`.

### 2. The health probe is green

```bash
curl -sk https://localhost:8443/api/v1/health
```

Expect HTTP `200` and `{"status":"healthy","db_connected":true,"version":"..."}`.

### 3. The UI loads

```bash
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/
```

Expect `200`. The embedded SPA is served by the same process.

### 4. No fatal errors in the recent log

```bash
journalctl -u openwatch --since "5 minutes ago" | grep -iE "error|fatal" || echo "clean"
```

### 5. Migrations are current

```bash
sudo -u openwatch /usr/bin/openwatch --config /etc/openwatch/openwatch.toml migrate
```

This prints the current schema version and applies nothing if already up to date.

---

## Escalation

Escalate if any of the following are true:

- The service remains down after 15 minutes of troubleshooting.
- The root cause is unclear after reading the journal and validating config.
- PostgreSQL reports data corruption (for example WAL corruption).
- The process crash-loops with no actionable fatal log line.
- The issue recurs within an hour of recovery.

Include when escalating:

- Output of `systemctl status openwatch` and the last 200 journal lines.
- Output of `curl -sk https://localhost:8443/api/v1/health`.
- Output of `openwatch check-config` (secrets are redacted).
- PostgreSQL state (`systemctl status postgresql`, `psql ... "SELECT 1;"`).
- The time the issue was first observed and any preceding change (upgrade,
  config edit, host reboot).

---

## Prevention

- **Let systemd restart the service**: the unit ships `Restart=on-failure` with
  `RestartSec=5s`. Keep these in place so transient failures self-heal.
- **Validate before restart**: run `openwatch check-config` after any edit to
  `/etc/openwatch/openwatch.toml` or `secrets.env` to catch a bad value before it
  takes the service down.
- **Monitor the health probe**: poll `GET /api/v1/health` from your existing host
  monitoring and alert on any non-`200` response.
- **Order startup correctly**: the unit declares `After=`/`Wants=postgresql.service`
  so PostgreSQL starts first on the same host. For an external database, ensure
  network reachability before OpenWatch starts.
- **Bound the journal**: OpenWatch logs to the journal; cap it with
  `SystemMaxUse=` in `/etc/systemd/journald.conf` so logs never fill the disk
  (see the [disk space runbook](DISK_FULL.md)).

---

## Not yet implemented

OpenWatch is currently `v0.2.0`, a pre-release. The following do not exist in
the current code and must not be relied on in this runbook:

- **A packaged systemd unit for the scan worker.** Only `openwatch.service`
  (running `serve`) ships today. Running `openwatch worker` under systemd is the
  operator's responsibility.
- **A Prometheus or metrics endpoint.** The only built-in HTTP probe is
  `GET /api/v1/health`, which reports liveness and database connectivity, not
  metrics. Use host-level monitoring for CPU, memory, and disk.
- **Separate `/livez` / `/readyz` probes.** Liveness and readiness are combined in
  the single `GET /api/v1/health` endpoint.
- **A backup/restore subcommand.** Use standard PostgreSQL tooling
  (`pg_dump` / `pg_basebackup`). The CLI subcommands are `serve`, `worker`,
  `migrate`, `create-admin`, and `check-config`.
