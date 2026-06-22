# Configuration and environment reference

This document is the field reference for how you configure the OpenWatch Go
binary: the TOML file, the environment-variable overrides, and the on-disk paths
that the service reads at boot.

OpenWatch is a single Go binary (`/usr/bin/openwatch`) that serves both the REST
API and the embedded React UI over HTTPS on port `8443`. It uses PostgreSQL only.
There is no container runtime, no Redis, no Celery, and no separate web tier to
configure. OpenSCAP is not used; the compliance engine is Kensa (SSH-based, native
YAML rules).

For end-to-end install and first-run steps, see
[`docs/guides/INSTALLATION.md`](INSTALLATION.md). This page
documents only the configuration surface and does not repeat the install flow.

## Configuration layering

The binary resolves configuration from four layers. Higher layers win:

| Precedence | Layer | Source |
|------------|-------|--------|
| 1 (highest) | CLI flags | `--listen`, `--log-level`, `--config` |
| 2 | Environment variables | `OPENWATCH_<SECTION>_<KEY>` (see below) |
| 3 | TOML file | `/etc/openwatch/openwatch.toml` (override with `--config`) |
| 4 (lowest) | Built-in defaults | compiled into the binary |

The layering is defined in `internal/config/load.go` and `internal/config/config.go`.
Only the environment variables listed in `internal/config/load.go` (`envOverrides`)
are recognized. There is no reflection-based mapping, so an unrecognized
`OPENWATCH_*` variable has no effect.

Run `openwatch check-config` to print the resolved configuration (secrets redacted)
and validate it. Exit code `0` means valid, `1` means invalid.

## TOML configuration

The default file lives at `/etc/openwatch/openwatch.toml` (mode `0640`, owner
`root:openwatch`). The package ships it with `[server]`, `[database]`, and
`[logging]` populated. The `[identity]` section is optional in the file; when it
is absent the defaults below apply, and you can set the two key paths through the
TOML file or through the matching environment variables.

The full set of recognized keys, their sections, defaults, and the environment
variable that overrides each one:

| Section | Key | Default | Env override |
|---------|-----|---------|--------------|
| `server` | `listen` | `0.0.0.0:8443` | `OPENWATCH_SERVER_LISTEN` |
| `server` | `tls_cert` | `/etc/openwatch/tls/cert.pem` | `OPENWATCH_SERVER_TLS_CERT` |
| `server` | `tls_key` | `/etc/openwatch/tls/key.pem` | `OPENWATCH_SERVER_TLS_KEY` |
| `database` | `dsn` | `postgres://openwatch@localhost/openwatch?sslmode=disable` | `OPENWATCH_DATABASE_DSN` |
| `database` | `max_connections` | `25` | `OPENWATCH_DATABASE_MAX_CONNECTIONS` |
| `logging` | `level` | `info` | `OPENWATCH_LOGGING_LEVEL` |
| `logging` | `format` | `json` | `OPENWATCH_LOGGING_FORMAT` |
| `identity` | `jwt_private_key` | `/etc/openwatch/keys/jwt_private.pem` | `OPENWATCH_IDENTITY_JWT_PRIVATE_KEY` |
| `identity` | `credential_key_file` | `/etc/openwatch/keys/credential.key` | `OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE` |

These are the only configuration keys the binary reads. The values are validated
by `internal/config/validate.go`.

Example `/etc/openwatch/openwatch.toml`:

```toml
[server]
listen   = "0.0.0.0:8443"
tls_cert = "/etc/openwatch/tls/cert.pem"
tls_key  = "/etc/openwatch/tls/key.pem"

[database]
# Keep the password out of this file; set OPENWATCH_DATABASE_DSN in
# /etc/openwatch/secrets.env instead.
dsn             = "postgres://openwatch@localhost/openwatch?sslmode=disable"
max_connections = 25

[logging]
level  = "info"
format = "json"

[identity]
jwt_private_key     = "/etc/openwatch/keys/jwt_private.pem"
credential_key_file = "/etc/openwatch/keys/credential.key"
```

## Environment variables

### Configuration overrides

Each variable maps to exactly one TOML key (see the table above). The format is
`OPENWATCH_<SECTION>_<KEY>`, all uppercase. The recognized set is fixed:

| Variable | Overrides | Notes |
|----------|-----------|-------|
| `OPENWATCH_SERVER_LISTEN` | `[server].listen` | Must be `host:port`. |
| `OPENWATCH_SERVER_TLS_CERT` | `[server].tls_cert` | Path to the TLS certificate. |
| `OPENWATCH_SERVER_TLS_KEY` | `[server].tls_key` | Path to the TLS private key. |
| `OPENWATCH_DATABASE_DSN` | `[database].dsn` | Must parse as `postgres://` or `postgresql://`. |
| `OPENWATCH_DATABASE_MAX_CONNECTIONS` | `[database].max_connections` | Integer greater than `0`. |
| `OPENWATCH_LOGGING_LEVEL` | `[logging].level` | One of `debug`, `info`, `warn`, `error`. |
| `OPENWATCH_LOGGING_FORMAT` | `[logging].format` | One of `json`, `text`. |
| `OPENWATCH_IDENTITY_JWT_PRIVATE_KEY` | `[identity].jwt_private_key` | PEM RSA private key, mode `0600`. |
| `OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE` | `[identity].credential_key_file` | 32-byte AES-256 key, mode `0600`. |

The canonical place to set the database secret is `/etc/openwatch/secrets.env`,
which the systemd unit reads through `EnvironmentFile=-/etc/openwatch/secrets.env`.
Keeping the DSN there keeps the password out of the world-readable TOML file:

```bash
sudo tee /etc/openwatch/secrets.env >/dev/null <<'EOF'
OPENWATCH_DATABASE_DSN=postgres://openwatch:CHANGE_ME@localhost/openwatch?sslmode=require
EOF
sudo chown root:openwatch /etc/openwatch/secrets.env
sudo chmod 0640 /etc/openwatch/secrets.env
```

### Other environment variables read at runtime

| Variable | Default | Read by | Purpose |
|----------|---------|---------|---------|
| `OPENWATCH_LICENSE_FILE` | `/etc/openwatch/license.lic` | `serve`, `worker` | Path to the OpenWatch+ license file. A missing file is not fatal; the service runs at the free tier. |
| `OPENWATCH_POLICIES_DIR` | `/etc/openwatch/policies` | `serve` | Directory scanned when an admin triggers a policy reload through the API. |
| `OPENWATCH_DEV_MODE` | unset | `serve` | When set to `true`, accepts unsigned policy envelopes. Development only; never set in production. |

Standard PostgreSQL libpq environment variables (for example `PGSSLROOTCERT`) are
honored by the underlying driver when present, but OpenWatch itself only reads the
DSN. Prefer encoding connection options in the DSN query string
(`?sslmode=verify-full&...`) so the configuration stays in one place.

## On-disk paths

| Path | Owner / mode | Purpose |
|------|--------------|---------|
| `/usr/bin/openwatch` | `root`, `0755` | The single binary (API + UI + CLI). |
| `/etc/openwatch/openwatch.toml` | `root:openwatch`, `0640` | Main config file. |
| `/etc/openwatch/secrets.env` | `root:openwatch`, `0640` | `OPENWATCH_DATABASE_DSN` and other secrets; loaded by systemd. |
| `/etc/openwatch/tls/cert.pem` | readable by `openwatch` | TLS server certificate. |
| `/etc/openwatch/tls/key.pem` | `openwatch`, `0600` | TLS server private key. |
| `/etc/openwatch/keys/jwt_private.pem` | `openwatch`, `0600` | RSA key that signs access and refresh JWTs. |
| `/etc/openwatch/keys/credential.key` | `openwatch`, `0600` | AES-256 key encrypting MFA secrets and stored SSH credentials. |
| `/etc/openwatch/license.lic` | readable by `openwatch` | Optional OpenWatch+ license. |
| `/var/lib/openwatch` | `openwatch` | Service state directory (`ReadWritePaths` in the unit). |
| `/var/log/openwatch` | `openwatch` | Log directory; journald remains the primary log sink. |

The systemd unit (`packaging/common/openwatch.service`) runs the service as the
`openwatch` user with `ProtectSystem=strict` and writes only to
`/var/lib/openwatch` and `/var/log/openwatch`. Both `[server].tls_key`,
`[identity].jwt_private_key`, and `[identity].credential_key_file` must be present
and readable, or `openwatch serve` exits with an explicit error rather than falling
back to ephemeral keys.

## CLI subcommands

The binary's lifecycle is driven through these subcommands
(`cmd/openwatch/main.go`). All of them honor the same configuration layering.

| Subcommand | Purpose |
|------------|---------|
| `serve` | Run the HTTPS API + UI server. This is the default when no subcommand is given, which is what the systemd unit invokes. |
| `worker` | Run the scan-job claimer/dispatcher loop against the PostgreSQL-native queue. |
| `migrate` | Apply pending database migrations (`internal/db/migrations/`) and print the resulting version. |
| `create-admin` | Create the first admin user. Requires `--username` and `--email`; reads the password from `--password` or stdin. |
| `check-config` | Print the resolved, secret-redacted config and validate it. |

Global flags: `--config <path>`, `--listen <host:port>`, `--log-level <level>`,
`--version`, `-h`/`--help`.

Validate configuration before starting the service:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
    openwatch check-config --config /etc/openwatch/openwatch.toml
```

## Service control and verification

OpenWatch runs under systemd as `openwatch.service`:

```bash
sudo systemctl enable --now openwatch
sudo systemctl status openwatch
sudo journalctl -u openwatch -f
```

Logs are structured JSON on stdout/stderr, captured by journald. Boot, shutdown,
and per-request events carry a correlation ID. Health check:

```bash
curl -k https://localhost:8443/api/v1/health
```

The API is served under `/api/v1/`; `api/openapi.yaml` is the contract
source of truth. Role definitions live in
[`docs/engineering/rbac_registry.md`](../engineering/rbac_registry.md) and
`internal/auth/permissions.yaml`.

## Operational runbooks

These are operational procedures for the single binary on systemd with PostgreSQL.
All commands assume the default paths above.

### Service down

The service is not responding on `8443`.

1. Check the unit state and recent logs:

   ```bash
   sudo systemctl status openwatch
   sudo journalctl -u openwatch -n 200 --no-pager
   ```

2. If the service failed to start, validate the config and confirm the key files
   exist and are readable by the `openwatch` user:

   ```bash
   sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch check-config
   sudo ls -l /etc/openwatch/tls/ /etc/openwatch/keys/
   ```

   A missing or unreadable `tls_key`, `jwt_private_key`, or `credential_key_file`
   causes `serve` to exit immediately with an explicit error in the journal.

3. Confirm PostgreSQL is up and the DSN is reachable:

   ```bash
   sudo systemctl status postgresql
   psql "$OPENWATCH_DATABASE_DSN" -c 'SELECT 1;'
   ```

4. Restart and watch the logs:

   ```bash
   sudo systemctl restart openwatch
   sudo journalctl -u openwatch -f
   ```

### Service down after an upgrade

If the service fails immediately after a package upgrade, a migration may be
pending. Run it as the service user, then restart:

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch migrate
sudo systemctl restart openwatch
```

### Disk full

A full disk most often manifests as failed writes to `/var/lib/openwatch`,
`/var/log/openwatch`, or the PostgreSQL data directory.

1. Find what filled up:

   ```bash
   df -h
   sudo du -xh /var/log/openwatch /var/lib/openwatch | sort -h | tail -20
   ```

2. journald is the primary log sink. If journald is the culprit, vacuum it:

   ```bash
   sudo journalctl --disk-usage
   sudo journalctl --vacuum-time=7d
   ```

3. If PostgreSQL's volume is full, free space there (archive or drop old data per
   your retention policy) before restarting the database and the service.

4. After freeing space, confirm recovery:

   ```bash
   sudo systemctl restart openwatch
   curl -k https://localhost:8443/api/v1/health
   ```

### High CPU

1. Identify the hot process:

   ```bash
   top -b -n1 | head -20
   sudo systemctl status openwatch
   ```

2. If the `openwatch` process is busy, check whether scan jobs are saturating the
   worker. Inspect the journal for scan and queue activity:

   ```bash
   sudo journalctl -u openwatch --since '15 min ago' | grep -i 'scan\|queue\|worker'
   ```

3. If PostgreSQL is the hot process, look for long-running or stuck queries:

   ```bash
   psql "$OPENWATCH_DATABASE_DSN" -c \
     "SELECT pid, state, now() - query_start AS runtime, left(query, 80) AS query
        FROM pg_stat_activity
       WHERE state <> 'idle' ORDER BY runtime DESC LIMIT 10;"
   ```

4. Reduce database connection pressure with `OPENWATCH_DATABASE_MAX_CONNECTIONS`
   (or `[database].max_connections`) if the pool is oversized for the host, then
   restart the service.

### Security incident

1. Contain. Stop the service to halt all API, UI, and scan activity:

   ```bash
   sudo systemctl stop openwatch
   ```

2. Preserve evidence. Export the journal and protect the audit trail before any
   remediation:

   ```bash
   sudo journalctl -u openwatch --since '24 hours ago' > /var/tmp/openwatch-incident.log
   ```

   Authentication and authorization events are emitted to the audit log and the
   journal. Review them for the affected window.

3. Rotate credentials. If key material may be exposed, rotate the database
   password (update `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env`), and
   rotate the JWT signing key and credential key only with a planned procedure —
   replacing `credential.key` makes previously encrypted SSH credentials and MFA
   secrets unreadable, so re-enrollment is required.

4. Verify file ownership and modes have not drifted:

   ```bash
   sudo ls -l /etc/openwatch /etc/openwatch/keys /etc/openwatch/tls
   ```

   `secrets.env` and the key files must be owner-only or `root:openwatch` `0640`/`0600`.

5. Patch and restart only after the cause is understood:

   ```bash
   sudo systemctl start openwatch
   sudo journalctl -u openwatch -f
   ```

## Not yet implemented

The following capabilities existed in the archived Python/Docker stack but are not
present in the current Go binary. Do not configure them; they have no effect.

| Capability | Status |
|------------|--------|
| Prometheus `/metrics` endpoint | Not implemented. Audit counters exist internally (`internal/audit/emit.go`) but are not exposed over HTTP. Use journald metrics and `pg_stat_*` views for observability. |
| Redis / Celery configuration | Removed. Background jobs use a PostgreSQL-native queue (`SKIP LOCKED`); there is nothing to configure. |
| MongoDB configuration | Removed. OpenWatch is PostgreSQL-only. |
| Container-runtime / docker-compose variables | Removed. The service is a native binary under systemd. |
| OpenSCAP / SCAP content directories | Not used and never were in the Go rebuild. Kensa runs SSH-based checks against native YAML rules. |
| SMTP / LDAP environment variables | Not read by the binary today. Notification channels and SSO are configured through the API and database, not environment variables. |
| Separate CORS / `ALLOWED_ORIGINS` variable | Not a recognized config key. The UI is served from the same origin as the API by the single binary. |
