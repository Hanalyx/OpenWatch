# OpenWatch Install Guide (Native Packages)

This guide walks you through installing OpenWatch from the native RPM or DEB
package, getting the service running, and verifying the install.

> **Heads-up — what this Stage-0 install actually gives you.**
> The Stage-0 build is the **walking-skeleton service**: it boots, listens
> on HTTPS, persists to PostgreSQL, threads correlation IDs through audit
> events, and exposes a small set of demo endpoints (`/health`, `:echo`,
> `/license`, `/audit/events`, plus RBAC and license-gate demos). It does
> **not** run compliance scans, has **no** real authentication (identity
> is bound from an `X-Stub-Role` HTTP header), and has **no** UI. Real
> features land in Stage 2. Install it to validate the platform contract,
> not to scan production hosts.

---

## At a glance

| Step | Time | Command |
|------|------|---------|
| 1. Install PostgreSQL | 2 min | `dnf install postgresql-server` / `apt install postgresql` |
| 2. Provision the database | 1 min | `sudo -u postgres createdb openwatch` |
| 3. Install the package | 30 sec | `dnf install ./openwatch-*.rpm` / `apt install ./openwatch_*.deb` |
| 4. Configure secrets | 1 min | Edit `/etc/openwatch/secrets.env` |
| 5. Run migrations | 5 sec | `sudo -u openwatch openwatch migrate` |
| 6. Start the service | 5 sec | `systemctl enable --now openwatch` |
| 7. Verify | 10 sec | `curl -k https://localhost:8443/api/v1/health` |

**Total time: ~5 minutes** on a host with PostgreSQL already installed.

---

## Requirements

- **OS:**
  - RPM: CentOS Stream 9, RHEL 9, Rocky Linux 9, AlmaLinux 9
  - DEB: Ubuntu 24.04 LTS (or compatible Debian-derivative with `systemd`)
- **CPU/RAM:** 1 vCPU / 512 MB RAM minimum for the service itself.
- **Disk:** 500 MB for binary + data dir growth; size audit retention as
  appropriate for your environment.
- **Ports:** TCP/8443 inbound for the HTTPS API.
- **PostgreSQL:** 14+ recommended. The package declares `postgresql-server`
  (RPM) / `postgresql-client` (DEB) as a dependency but **does not
  provision** a database — you do that in Step 2.
- **Privileges:** `sudo` / root for the install steps. Day-to-day service
  operation runs as the `openwatch` system user (created by the package).

---

## RPM — CentOS Stream 9, RHEL 9, Rocky, AlmaLinux

### Step 1 — Install PostgreSQL

```bash
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

### Step 2 — Provision the database

Create the role and database:

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE openwatch WITH LOGIN PASSWORD 'replace-me-strong-password';
CREATE DATABASE openwatch OWNER openwatch;
SQL
```

Allow password auth from localhost. Edit `/var/lib/pgsql/data/pg_hba.conf`
and ensure these two lines exist near the top of the host rules:

```
host    openwatch    openwatch    127.0.0.1/32    scram-sha-256
host    openwatch    openwatch    ::1/128         scram-sha-256
```

Reload PostgreSQL:

```bash
sudo systemctl reload postgresql
```

Verify the credential works:

```bash
PGPASSWORD='replace-me-strong-password' \
  psql -h 127.0.0.1 -U openwatch -d openwatch -c '\conninfo'
```

### Step 3 — Install the OpenWatch package

```bash
sudo dnf install -y ./openwatch-0.1.0-1.x86_64.rpm
```

What the package does at install time:

1. **Creates the `openwatch` system user + group** (idempotent — no-op if
   already present).
2. **Installs files:**
   - `/usr/bin/openwatch` (binary, mode 0755)
   - `/etc/openwatch/openwatch.toml` (config, mode 0640, owner `root:openwatch`)
   - `/etc/openwatch/tls/cert.pem` + `key.pem` (self-signed demo cert)
   - `/etc/systemd/system/openwatch.service` (systemd unit)
   - `/var/lib/openwatch/` and `/var/log/openwatch/` (writable by openwatch)
3. **Runs `systemctl daemon-reload`** so the unit is registered.
4. **Does NOT enable or start the service** — you do that in Step 6 after
   configuration.

Verify the install:

```bash
rpm -q openwatch
openwatch --version
```

### Step 4 — Configure secrets

The default config in `/etc/openwatch/openwatch.toml` points at a local DSN
that assumes peer/trust auth. Override the DSN with a real password via
the systemd environment file (so the secret does not live in the TOML).

Create `/etc/openwatch/secrets.env`:

```bash
sudo tee /etc/openwatch/secrets.env >/dev/null <<'EOF'
OPENWATCH_DATABASE_DSN=postgres://openwatch:replace-me-strong-password@127.0.0.1:5432/openwatch?sslmode=disable
EOF
sudo chown root:openwatch /etc/openwatch/secrets.env
sudo chmod 0640 /etc/openwatch/secrets.env
```

> Use `sslmode=require` (or stronger) for any non-loopback PostgreSQL.

### Step 5 — Run database migrations

Apply the schema. This creates `audit_events`, `idempotency_keys`,
`job_queue`, `policy_history`, and the `goose_db_version` tracking table:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate
```

Expected output ends with `goose: no migrations to run. current version: 4`
(or whichever migration is highest at install time).

### Step 6 — Start the service

```bash
sudo systemctl enable --now openwatch
sudo systemctl status openwatch
```

### Step 7 — Verify

```bash
curl -k https://localhost:8443/api/v1/health
```

Expected response:
```json
{"status":"healthy","db_connected":true,"version":"0.1.0"}
```

The `-k` flag accepts the self-signed demo cert. Replace the cert under
`/etc/openwatch/tls/` with one from your CA before any non-loopback use
(see [Replacing the demo TLS cert](#replacing-the-demo-tls-cert)).

---

## DEB — Ubuntu 24.04 LTS

### Step 1 — Install PostgreSQL

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

### Step 2 — Provision the database

Same SQL as the RPM path:

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE openwatch WITH LOGIN PASSWORD 'replace-me-strong-password';
CREATE DATABASE openwatch OWNER openwatch;
SQL
```

Ubuntu's default `pg_hba.conf` (`/etc/postgresql/16/main/pg_hba.conf`)
already allows `scram-sha-256` for `host all all 127.0.0.1/32` — no edit
needed unless you've customized it.

Verify:

```bash
PGPASSWORD='replace-me-strong-password' \
  psql -h 127.0.0.1 -U openwatch -d openwatch -c '\conninfo'
```

### Step 3 — Install the OpenWatch package

```bash
sudo apt install -y ./openwatch_0.1.0-alpha.1_amd64.deb
```

If `apt` complains about missing dependencies, install them first or use:

```bash
sudo apt install -y -f ./openwatch_0.1.0-alpha.1_amd64.deb
```

What the package does at install time is the same as the RPM (user
creation, file install, `daemon-reload`). The service is **not**
auto-started.

Verify:

```bash
dpkg -l openwatch
openwatch --version
```

### Step 4 — Configure secrets

Identical to the RPM path:

```bash
sudo tee /etc/openwatch/secrets.env >/dev/null <<'EOF'
OPENWATCH_DATABASE_DSN=postgres://openwatch:replace-me-strong-password@127.0.0.1:5432/openwatch?sslmode=disable
EOF
sudo chown root:openwatch /etc/openwatch/secrets.env
sudo chmod 0640 /etc/openwatch/secrets.env
```

### Step 5 — Run migrations

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate
```

### Step 6 — Start the service

```bash
sudo systemctl enable --now openwatch
sudo systemctl status openwatch
```

### Step 7 — Verify

```bash
curl -k https://localhost:8443/api/v1/health
```

---

## What you can do with the running service

These endpoints are wired and tested. All exercise the foundation
contracts (correlation propagation, idempotency, audit, license, RBAC).

### Public endpoints (no auth required)

```bash
# Health check.
curl -k https://localhost:8443/api/v1/health

# Current license state (free tier by default — no license file installed).
curl -k https://localhost:8443/api/v1/license

# Audit query — see system.startup event from the recent service boot.
curl -k 'https://localhost:8443/api/v1/audit/events?action=system.startup'
```

### Idempotency + audit demo

```bash
# Echo. Requires Idempotency-Key. Records one audit event per unique key.
curl -k -X POST \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-key-001' \
  -H 'X-Correlation-Id: demo-001' \
  -d '{"message":"hello"}' \
  https://localhost:8443/api/v1/diagnostics:echo

# Replay with the same key + same body — returns the cached response,
# no second audit event written.
curl -k -X POST \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-key-001' \
  -H 'X-Correlation-Id: demo-001' \
  -d '{"message":"hello"}' \
  https://localhost:8443/api/v1/diagnostics:echo

# Confirm one audit event written (not two).
curl -k 'https://localhost:8443/api/v1/audit/events?correlation_id=demo-001'
```

### License-gate demo

```bash
# Premium-tier endpoint without a license — returns 402 with the
# canonical error envelope and emits a license.feature_check_denied
# audit event.
curl -k -X POST \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: premium-001' \
  -d '{"message":"premium"}' \
  https://localhost:8443/api/v1/diagnostics:premium-echo
```

### RBAC demo

Stage-0 identity is bound from the `X-Stub-Role` header. Valid values:
`viewer | auditor | ops_lead | security_admin | admin`.

```bash
# No role → 403 authz.permission_denied + audit event.
curl -k -X POST \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: rbac-001' \
  -d '{"message":"hi"}' \
  https://localhost:8443/api/v1/diagnostics:require-host-read

# Viewer role grants host:read → 200.
curl -k -X POST \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: rbac-002' \
  -H 'X-Stub-Role: viewer' \
  -d '{"message":"hi"}' \
  https://localhost:8443/api/v1/diagnostics:require-host-read

# Effective permissions for the calling identity.
curl -k -H 'X-Stub-Role: ops_lead' \
  https://localhost:8443/api/v1/auth/me/permissions

# Full RBAC registry (categories, permissions, built-in roles).
curl -k https://localhost:8443/api/v1/auth/permissions:registry
```

---

## Common operations

### Service control

```bash
sudo systemctl start openwatch        # start
sudo systemctl stop openwatch         # stop
sudo systemctl restart openwatch      # restart
sudo systemctl status openwatch       # current state
sudo systemctl enable openwatch       # start at boot
sudo systemctl disable openwatch      # don't start at boot
```

### Log access

The service logs in JSON format to journald (no separate log file by default):

```bash
sudo journalctl -u openwatch -f                  # tail live
sudo journalctl -u openwatch --since '5 min ago' # recent
sudo journalctl -u openwatch -o cat | jq .       # pretty-print JSON
```

### Configuration

```bash
# Print the resolved config (TOML + env + CLI flag merge).
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch check-config
```

### Replacing the demo TLS cert

The package ships a self-signed cert valid for one year, CN `openwatch-demo`.
For any non-loopback use, replace it with a cert from your CA:

```bash
sudo cp /path/to/your-cert.pem /etc/openwatch/tls/cert.pem
sudo cp /path/to/your-key.pem  /etc/openwatch/tls/key.pem
sudo chown root:openwatch       /etc/openwatch/tls/cert.pem
sudo chown openwatch:openwatch  /etc/openwatch/tls/key.pem
sudo chmod 0644                 /etc/openwatch/tls/cert.pem
sudo chmod 0600                 /etc/openwatch/tls/key.pem
sudo systemctl restart openwatch
```

The server reloads certs on every TLS handshake via `GetCertificate`, so
no restart is required if you swap the files — but a restart guarantees
the new cert is in use for any keep-alive connections.

### Configuration layering

Config values resolve in this order, highest precedence first:

1. **CLI flags** (`--listen`, `--log-level`)
2. **Environment variables** (`OPENWATCH_<SECTION>_<KEY>`)
3. **TOML file** (`/etc/openwatch/openwatch.toml`)
4. **Built-in defaults**

Recognized environment variables:

| Variable | Effect |
|----------|--------|
| `OPENWATCH_SERVER_LISTEN` | Override `[server].listen` |
| `OPENWATCH_SERVER_TLS_CERT` | Override `[server].tls_cert` |
| `OPENWATCH_SERVER_TLS_KEY` | Override `[server].tls_key` |
| `OPENWATCH_DATABASE_DSN` | Override `[database].dsn` |
| `OPENWATCH_DATABASE_MAX_CONNECTIONS` | Override `[database].max_connections` |
| `OPENWATCH_LOGGING_LEVEL` | `debug` / `info` / `warn` / `error` |
| `OPENWATCH_LOGGING_FORMAT` | `json` / `text` |

---

## Troubleshooting

### Service won't start

```bash
sudo systemctl status openwatch
sudo journalctl -u openwatch --since '1 min ago' -p err
```

Common causes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `config: env override: OPENWATCH_DATABASE_DSN: ...` | Bad DSN format in `secrets.env` | Verify `postgres://user:pass@host:port/db?sslmode=...` shape |
| `db: ping: ... password authentication failed` | DSN password wrong, or `pg_hba.conf` doesn't allow scram | Check Step 2; reload PostgreSQL after edits |
| `db: ping: ... connection refused` | PostgreSQL not running | `sudo systemctl status postgresql` |
| `server: listen: bind: permission denied` | Port < 1024 without capability | Default port is 8443 — only an issue if you changed `[server].listen` |
| `server: ... no such file or directory: cert.pem` | TLS cert path wrong or perms wrong | Check `/etc/openwatch/tls/cert.pem` is readable by the `openwatch` user |

### `migrate` fails

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch migrate
```

If you see `dial tcp 127.0.0.1:5432: connect: connection refused`,
PostgreSQL isn't running. If you see `password authentication failed`,
re-check Step 2 in your distro's section.

### Health endpoint returns 503

```bash
curl -k https://localhost:8443/api/v1/health
# {"error":{"code":"server.unavailable",...}}
```

The DB ping inside `/health` failed. Check `journalctl -u openwatch` for
the underlying error.

### Stub-role header is being ignored

The `X-Stub-Role` header only binds an identity to one of the five
built-in roles: `viewer`, `auditor`, `ops_lead`, `security_admin`,
`admin`. Any other value (including typos) falls through to anonymous
and you'll see 403 from RBAC-gated endpoints.

### Audit events are missing for a request

The async audit writer batches up to 100 events / 100 ms. If you query
`/audit/events` immediately after a mutating call, the row may not yet be
visible. Wait 200 ms (or query the same correlation_id twice).

---

## Uninstall

### RPM

```bash
sudo systemctl stop openwatch
sudo dnf remove -y openwatch
```

The package's pre-uninstall script runs `systemctl stop` and `disable`
automatically; the manual `stop` above is belt-and-braces. Configuration
files under `/etc/openwatch/` are preserved (marked `%config(noreplace)`).
Remove them manually if you don't plan to reinstall:

```bash
sudo rm -rf /etc/openwatch /var/lib/openwatch /var/log/openwatch
sudo userdel openwatch && sudo groupdel openwatch
```

### DEB

```bash
sudo systemctl stop openwatch
sudo apt remove openwatch          # leaves /etc/openwatch in place
# OR
sudo apt purge openwatch           # also removes /etc/openwatch
```

The package's `prerm` script runs `systemctl stop` and `disable`. `apt
purge` removes the conffile (`/etc/openwatch/openwatch.toml`) but leaves
`secrets.env` and the demo TLS material — remove those manually if
needed:

```bash
sudo rm -rf /etc/openwatch /var/lib/openwatch /var/log/openwatch
sudo userdel openwatch && sudo groupdel openwatch
```

### The PostgreSQL database

Removing the OpenWatch package does **not** touch the database. To
reclaim that space:

```bash
sudo -u postgres psql <<'SQL'
DROP DATABASE openwatch;
DROP ROLE openwatch;
SQL
```

---

## Where to go next

- **Spec status:** `app/specs/SPEC_REGISTRY.md` (16 specs, 100% strict
  coverage at the time of writing).
- **Stage 0 walkthrough:** `app/docs/stage_0_walking_skeleton.md` — day-
  by-day what's in this build.
- **API contract:** `app/api/openapi.yaml` — every endpoint declared with
  its required permission, license gate, audit events.
- **Audit taxonomy:** `app/docs/audit_event_taxonomy.md` — every event
  the service can emit.
- **Stage 2 plans:** real auth, real hosts, real scans — not in this
  install. Track progress via the roadmap.

---

## Quick reference card

```
URLs           https://localhost:8443/api/v1/{health,license,audit/events,...}
TLS cert       /etc/openwatch/tls/{cert,key}.pem  (self-signed demo)
Config         /etc/openwatch/openwatch.toml
Secrets        /etc/openwatch/secrets.env
Service unit   /etc/systemd/system/openwatch.service
Binary         /usr/bin/openwatch
Data dir       /var/lib/openwatch
Log dir        /var/log/openwatch         (journald is the primary sink)
User/group     openwatch:openwatch
Logs           journalctl -u openwatch -f
Restart        sudo systemctl restart openwatch
Migrate        sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
```
