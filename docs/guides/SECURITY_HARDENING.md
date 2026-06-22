# OpenWatch security hardening guide

**Applies to:** OpenWatch 0.2.0 pre-release (rc series; Go single-binary build)
**Audience:** System administrators, security engineers, compliance officers

This guide covers the security controls you operate when you deploy OpenWatch
as a native package: one Go binary (`/usr/bin/openwatch`) that serves the REST
API and the embedded React UI over HTTPS on port 8443, backed by PostgreSQL and
managed by `systemd`. It documents what the current build enforces, what you
configure at the host level, and what is not yet implemented.

For installation, database provisioning, the admin bootstrap, and TLS-cert
replacement, follow [`docs/guides/INSTALLATION.md`](INSTALLATION.md).
This guide does not repeat those steps; it focuses on hardening the result.

Verify any claim here against the source before you rely on it. The grounding
files are cited in each section.

---

## 1. Architecture and trust boundaries

OpenWatch is a single process. There is no separate web tier, container runtime,
cache, or message broker. Background work (scans, discovery, intelligence
cycles) runs either in-process or under `openwatch worker`, draining a
PostgreSQL-native job queue with `SELECT ... FOR UPDATE SKIP LOCKED`.

| Component | What it is | Exposure |
|-----------|------------|----------|
| `openwatch serve` | HTTPS API + embedded UI | TCP/8443 inbound |
| PostgreSQL | All persistent state | You provision and bind it (loopback by default) |
| Kensa (in-process, Go) | SSH-based compliance engine | TCP/22 outbound to managed hosts |

Source: `cmd/openwatch/main.go`, `packaging/common/openwatch.service`,
`internal/server/server.go`.

The compliance engine is Kensa, which connects to managed hosts over SSH and
runs native YAML checks.
See
[`docs/KENSA_OPENWATCH_BOUNDARY.md`](../KENSA_OPENWATCH_BOUNDARY.md).

---

## 2. Network exposure

The binary listens on `0.0.0.0:8443` by default (`[server].listen`, override
with `OPENWATCH_SERVER_LISTEN`). It opens no other listening socket.

Source: `internal/config/config.go` (`Defaults()`), `cmd/openwatch/main.go`.

Hardening steps you perform at the host level:

- Restrict inbound TCP/8443 to operator networks with `firewalld`, `nftables`,
  or `ufw`. OpenWatch does not implement IP allowlisting itself.
- Bind PostgreSQL to the loopback interface and require `scram-sha-256` from
  `127.0.0.1`/`::1`, as the install guide's Step 2 sets up. The package does
  not manage PostgreSQL for you.
- Allow only the outbound TCP/22 that Kensa needs to reach managed hosts.
- The `systemd` unit sets `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  so the process cannot open raw or exotic sockets even if compromised.

Source: `packaging/common/openwatch.service`,
`docs/guides/INSTALLATION.md` (Step 2).

### Outbound SSH to managed hosts

When OpenWatch connects to a managed host it validates the host key on a
trust-on-first-use basis and **persists** the accepted key in PostgreSQL
(`ssh_known_hosts`, migration 0036). The first connection records the key; every
later connection compares against it and is rejected if the key changed
(`ErrHostKeyMismatch`). Because the store is durable, a service restart does not
re-trust hosts, so an attacker cannot MITM the first scan after a restart to
harvest credentials. Presented keys are also strength-validated per NIST SP
800-57 (RSA >= 2048, Ed25519 always accepted). To rotate a host's key
intentionally (a re-provisioned host), delete its row from `ssh_known_hosts` so
the next connection re-learns it. Source: `internal/knownhosts/store.go`,
`internal/ssh/`.

---

## 3. Transport security (TLS)

The HTTPS server is configured with:

| Setting | Value | Source |
|---------|-------|--------|
| Minimum TLS version | TLS 1.2 | `internal/server/server.go` (`tls.Config{MinVersion: tls.VersionTLS12}`) |
| Cipher suites | Go standard-library defaults (not pinned) | `internal/server/server.go` |
| Certificate loading | `GetCertificate` callback, read per handshake | `internal/server/server.go`, `internal/server/tls.go` |
| Cert / key paths | `/etc/openwatch/tls/cert.pem`, `/etc/openwatch/tls/key.pem` | `internal/config/config.go` |

Because the cert is read on every handshake, you can replace the files and new
connections pick up the new cert without a restart; restart anyway to drop
existing keep-alive connections.

The package ships a self-signed cert. Replace it with a CA-issued cert before
any non-loopback use, following the "Replace the demo TLS cert" section of the
install guide. Set the key file to mode `0600`, owned `openwatch:openwatch`.

> The build does not pin an explicit cipher-suite list, so TLS 1.2 negotiation
> follows the Go runtime's secure defaults for the toolchain it was built with.
> If your accreditation requires a documented, pinned cipher list, raise it as a
> requirement; it is not configurable today.

Source: `internal/server/server.go`, `internal/server/tls.go`,
`docs/guides/INSTALLATION.md`.

---

## 4. Cryptography and FIPS

| Function | Algorithm | Source |
|----------|-----------|--------|
| Password hashing | Argon2id, t=3, m=64 MiB, p=1, 128-bit salt, 256-bit key | `internal/identity/password.go` |
| Credential / MFA-secret encryption at rest | AES-256-GCM (DEK) | `internal/secretkey/secretkey.go` |
| JWT signing | RS256 (RSA ≥ 2048) | `internal/identity/jwt.go`, `cmd/openwatch/main.go` |
| Breach-corpus lookup | SHA-1 prefix (HaveIBeenPwned k-anonymity; not authentication) | `internal/identity/password.go` |

### FIPS builds

A FIPS build target exists and uses the Go-native FIPS 140-3 module, not an
OpenSSL provider. Build it with:

```bash
make build-fips
```

This sets `GOFIPS140=v1.0.0` and produces `dist/openwatch-fips`. The resulting
binary reports its FIPS status:

```bash
openwatch --version
# ... fips: true ...
```

Source: `Makefile` (`build-fips`), `internal/version/version.go`.

> The standard package build is not FIPS-validated. If you require FIPS 140-3,
> deploy the `-fips` artifact and confirm `fips: true` from `openwatch --version`.
> The legacy "RHEL OpenSSL FIPS provider" / `fips-mode-setup` approach from the
> archived Python stack does not apply.

---

## 5. Cryptographic key material

`openwatch serve` refuses to start unless both identity keys are present. There
is no silent fallback to ephemeral keys.

| Config key | Default path | Contents | Required mode |
|------------|--------------|----------|---------------|
| `[identity].jwt_private_key` | `/etc/openwatch/keys/jwt_private.pem` | PEM RSA private key, ≥ 2048-bit | `0600` |
| `[identity].credential_key_file` | `/etc/openwatch/keys/credential.key` | 32-byte raw AES-256 key | `0600` |

Source: `internal/config/config.go` (`IdentityConfig`), `cmd/openwatch/main.go`
(`cmdServe` key-loading).

Hardening steps:

- Set both key files to mode `0600`, owned by the `openwatch` user.
- Keep the database password out of the world-readable config: put
  `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env` (mode `0640`, owner
  `root:openwatch`), which the `systemd` unit loads via `EnvironmentFile=`.
- `openwatch check-config` prints the resolved config with the DSN password
  redacted, so it is safe to capture in tickets.

Source: `packaging/common/openwatch.service`, `internal/config/config.go`
(`RedactDSN`, `Summary`), `docs/guides/INSTALLATION.md` (Step 4).

---

## 6. Authentication

| Control | Value | Source |
|---------|-------|--------|
| Access-token lifetime | 30 minutes | `internal/identity/jwt.go` (`AccessTokenWindow`) |
| Refresh-token lifetime | 7 days, rotated on use (reuse is detected and revokes the chain) | `internal/identity/refresh.go` (`RefreshTokenWindow`) |
| Session inactivity timeout | 15 minutes | `internal/identity/sessions.go` (`SessionInactivityWindow`) |
| Session absolute timeout | 12 hours | `internal/identity/sessions.go` (`SessionAbsoluteWindow`) |
| Password policy | Length only — 8 chars (regular), 15 chars (admin), max 128; NIST SP 800-63B | `internal/identity/password.go` |
| Breach check | Always-on in production: new passwords are screened against an embedded common/breached corpus (airgap-safe); point `OPENWATCH_BREACH_CORPUS_FILE` at a full HIBP list to extend it | `internal/identity/password.go`, `internal/identity/breach_corpus_default.go` |
| MFA | TOTP enrollment and verification | `internal/identity/mfa.go` |

The password policy is deliberately length-based with no character-class rules,
per NIST SP 800-63B. The first admin is created out-of-band with
`openwatch create-admin`, which enforces the 15-character admin minimum.

Source: `internal/identity/`, `cmd/openwatch/main.go` (`cmdCreateAdmin`).

`/api/v1/auth/login` and `/auth/mfa:verify` are rate-limited per client IP
(Section 10), which throttles online guessing in addition to the Argon2id cost
(~50-100 ms per verification). There is still no per-account lockout after N
failed attempts, so for an internet-facing 8443 a reverse proxy or network ACL
is still worthwhile as defense in depth. Source:
`internal/server/auth_handlers.go`, `internal/server/ratelimit.go`.

---

## 7. Authorization (RBAC)

Authorization is a permission registry, not free-form strings. Every protected
operation declares `x-required-permission` in `api/openapi.yaml`; the handler
middleware checks the caller's effective permission set; built-in roles grant
permissions from the same registry. A misspelled permission anywhere is a build
error.

Source of truth: `auth/permissions.yaml` →
`internal/auth/permissions.gen.go` and `internal/auth/roles.gen.go`. Enforcement:
`internal/auth/middleware.go` (`EnforcePermission`, `RequirePermission`).
Design doc: [`docs/engineering/rbac_registry.md`](../engineering/rbac_registry.md).

Built-in roles, least to most privileged:

| Role ID | Purpose |
|---------|---------|
| `viewer` | Read-only across the platform |
| `auditor` | Read-only plus exception authority and audit export |
| `ops_lead` | Day-to-day operations — hosts, scans, alerts |
| `security_admin` | Full security operations, including dangerous and license-gated actions |
| `admin` | Full system administration (user/role/SSO/system-setting management) |

Source: `internal/auth/roles.gen.go` (`BuiltInRoles`).

Hardening steps:

- Assign the least-privileged role that satisfies each user's job. `auditor` is
  read-only except for exception workflow and audit export.
- Keep `admin` accounts to the minimum. Only `admin` holds the
  `admin:user_manage`, `admin:role_manage`, `admin:sso_provider`, and
  `admin:system_setting` permissions.
- License-gated permissions (for example `remediation:execute`) are enforced in
  the same middleware pass as RBAC; you cannot use them without the entitlement.

---

## 8. Audit logging

Security-relevant events are written to a durable audit store in PostgreSQL with
a stable taxonomy (`actor`, `resource`, `action`, correlation ID). The taxonomy
is the single naming source so events do not drift across components.

The writer initializes at startup (`audit.Init`) and `system.startup` is emitted
synchronously before the server accepts traffic. Operational logs are separate:
the process logs JSON to `journald`.

Source: `cmd/openwatch/main.go` (`audit.Init`, `audit.EmitSync`),
`internal/audit/`, `internal/db/migrations/0002_audit_events_taxonomy.sql`,
[`docs/engineering/audit_event_taxonomy.md`](../engineering/audit_event_taxonomy.md).

Representative event codes (taxonomy):

| Category | Examples |
|----------|----------|
| Authentication | `auth.login.success`, `auth.login.failure`, `auth.logout` |
| System lifecycle | `system.startup`, `system.shutdown` |
| Hosts / scans / users / roles | `host.*`, `scan.*`, `user.*`, `role.*` |
| Licensing | license load/result events |

Hardening steps:

- Ship `journald` to a central collector (`systemd-journal-remote`, or a
  shipper such as Vector or rsyncd) so operational logs survive host loss.
- The durable audit trail lives in PostgreSQL; back up the database (Section 11)
  to retain audit evidence for your compliance window.
- View live operational logs:

  ```bash
  sudo journalctl -u openwatch -f
  sudo journalctl -u openwatch -o cat | jq .   # pretty-print the JSON
  ```

> The audit-event taxonomy is the authoritative list. Treat the table above as a
> sample, not a complete enumeration — read `internal/audit/` and
> `docs/engineering/audit_event_taxonomy.md` for the full set.

---

## 9. Process hardening (systemd)

The packaged `systemd` unit runs the service unprivileged and confined:

| Directive | Value | Effect |
|-----------|-------|--------|
| `User` / `Group` | `openwatch` | Runs as a dedicated unprivileged account |
| `NoNewPrivileges` | `true` | Process cannot gain privileges via setuid/setgid |
| `PrivateTmp` | `true` | Isolated `/tmp` |
| `ProtectSystem` | `strict` | Filesystem is read-only except declared paths |
| `ProtectHome` | `true` | No access to `/home`, `/root`, `/run/user` |
| `ProtectKernelTunables` | `true` | Cannot write `/proc/sys`, `/sys` |
| `ProtectKernelModules` | `true` | Cannot load kernel modules |
| `ProtectControlGroups` | `true` | Cgroup hierarchy is read-only |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_UNIX` | No raw/packet sockets |
| `LockPersonality` | `true` | Cannot change execution domain |
| `ReadWritePaths` | `/var/lib/openwatch /var/log/openwatch` | Only these are writable |

Source: `packaging/common/openwatch.service`.

Hardening steps:

- Do not loosen `ProtectSystem=strict` or widen `ReadWritePaths` unless you have
  a verified need.
- Confirm the effective sandbox after any unit edit:

  ```bash
  systemd-analyze security openwatch
  ```

- Keep the config and key files owned away from the service account where the
  service only needs read access (cert/JWT/credential keys at `0600`, owned by
  `openwatch`; `secrets.env` at `0640`, owner `root:openwatch`).

---

## 10. Rate limiting, CSRF, and security headers

The HTTP server sets request-hardening timeouts and size limits:

| Control | Value | Source |
|---------|-------|--------|
| `ReadHeaderTimeout` | 10 s | `internal/server/server.go` |
| `ReadTimeout` | 30 s | `internal/server/server.go` |
| `WriteTimeout` | 60 s | `internal/server/server.go` |
| `IdleTimeout` | 120 s | `internal/server/server.go` |
| `MaxHeaderBytes` | 64 KiB | `internal/server/server.go` |

The single binary serves the SPA and the API from one origin with no required
edge proxy, so the perimeter controls run in the application itself:

| Control | Behavior | Source |
|---------|----------|--------|
| Auth rate limiting | Per-client-IP sliding window on `POST /api/v1/auth/login` and `/auth/mfa:verify`; over the limit returns `429` + `Retry-After` and skips the credential check. The key is the direct connection address (`RemoteAddr`), not a client-supplied `X-Forwarded-For`. | `internal/server/ratelimit.go` |
| CSRF | Double-submit token: login and refresh set a non-HttpOnly `XSRF-TOKEN` cookie, and unsafe (POST/PUT/PATCH/DELETE) cookie-authenticated requests must echo it in `X-CSRF-Token` (constant-time compare) or get `403 authz.csrf_invalid`. Bearer/token requests and `/api/v1/auth/*` are exempt. | `internal/server/csrf.go` |
| Security headers | Every response carries HSTS (>=1 year, includeSubDomains), a Content-Security-Policy that denies framing (`frame-ancestors 'none'`, `default-src 'self'`; `/docs` relaxes script/style for Swagger but still denies framing), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`. | `internal/server/security_headers.go` |

> Scope notes: auth rate limiting covers the credential-guessing surface, not
> every route — there is still no general per-route HTTP limiter, and no request
> body-size cap (`http.MaxBytesReader`) on JSON endpoints. If you expose 8443
> publicly, an upstream reverse proxy is still useful for global rate limiting
> and body-size enforcement. The scheduler `RateLimit` constants are unrelated
> (they bound how many hosts the intelligence and discovery schedulers enqueue
> per tick), see `internal/intelligence/scheduler/service.go`.

---

## 11. Database and backups

OpenWatch stores all persistent state — hosts, credentials (AES-256-GCM
encrypted), scans, transactions, the job queue, and the audit trail — in
PostgreSQL. The package does not manage PostgreSQL and does not implement an
in-product backup tool.

Schema is applied with `openwatch migrate`, which runs the migrations in
`internal/db/migrations/` (goose).

Source: `cmd/openwatch/main.go` (`cmdMigrate`), `internal/db/migrations/`.

Hardening steps:

- Require TLS to PostgreSQL when it is not on the loopback interface: use
  `sslmode=require` (or `verify-full` with a CA) in `OPENWATCH_DATABASE_DSN`.
  Source: `docs/guides/INSTALLATION.md` (Step 4).
- Back up with the standard PostgreSQL tooling on a schedule that meets your
  retention requirement, and store backups encrypted off-host:

  ```bash
  sudo -u postgres pg_dump -Fc openwatch > openwatch-$(date -u +%Y-%m-%dT%H%M%SZ).dump
  ```

- Restrict the database role to the `openwatch` database only; do not reuse a
  superuser DSN for the service.

---

## 12. Operational runbooks

These are first-response procedures for the single binary on `systemd` with
PostgreSQL. They assume you have shell access on the OpenWatch host.

### SERVICE_DOWN — the service is not responding

```bash
sudo systemctl status openwatch
sudo journalctl -u openwatch --since '5 min ago' -p err
curl -k https://localhost:8443/api/v1/health
# healthy: {"status":"healthy","db_connected":true,"version":"…"}
```

1. If `status` shows the unit failed, read the error lines from `journalctl`.
2. Common causes (from the install guide's troubleshooting table): malformed
   `OPENWATCH_DATABASE_DSN`, wrong DB password or `pg_hba.conf`, PostgreSQL not
   running, or an unreadable TLS cert. Validate config without starting:

   ```bash
   sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) openwatch check-config
   ```

3. If `/api/v1/health` returns 503, the database ping failed — check
   PostgreSQL: `sudo systemctl status postgresql`.
4. Restart once the cause is fixed: `sudo systemctl restart openwatch`. The unit
   uses `Restart=on-failure` with a 5 s delay, so transient crashes self-heal.

Source: `docs/guides/INSTALLATION.md` (Troubleshooting),
`internal/server/server.go`, `packaging/common/openwatch.service`.

### DISK_FULL — the host is out of disk

```bash
df -h
sudo du -xh /var/log/openwatch /var/lib/openwatch 2>/dev/null | sort -h | tail
sudo journalctl --disk-usage
```

1. Identify the consumer. The service writes only to `/var/lib/openwatch` and
   `/var/log/openwatch` (`ReadWritePaths`); `journald` and PostgreSQL data are
   the other large consumers.
2. Vacuum `journald` to a bound:

   ```bash
   sudo journalctl --vacuum-size=500M
   ```

3. If PostgreSQL's data directory is the consumer, reclaim space there (vacuum,
   prune old backups) — do not delete files under PostgreSQL's data directory by
   hand.
4. A full disk can wedge the audit writer and database. After reclaiming space,
   confirm health with the `SERVICE_DOWN` check.

Source: `packaging/common/openwatch.service` (`ReadWritePaths`),
`internal/db/migrations/`.

### HIGH_CPU — sustained high CPU

```bash
top -b -n1 | head -20
sudo journalctl -u openwatch --since '10 min ago' | jq -r 'select(.level=="ERROR")' 2>/dev/null
```

1. Identify whether the `openwatch` process or `postgres` backends dominate.
2. If `postgres` dominates, look for slow queries:

   ```bash
   sudo -u postgres psql -d openwatch \
     -c "SELECT pid, state, now()-query_start AS runtime, left(query,80) \
         FROM pg_stat_activity WHERE datname='openwatch' AND state<>'idle' \
         ORDER BY runtime DESC LIMIT 10;"
   ```

3. Background scan/intelligence/discovery load is operator-tunable. Reduce the
   scheduler rate or pause it via the system-config API
   (`PUT /api/v1/system/intelligence/config`,
   `PUT /api/v1/system/discovery/config`) — the boot logs name these knobs when a
   scheduler is paused.
4. If the API process itself is hot with no DB pressure, capture logs and
   restart as a containment step: `sudo systemctl restart openwatch`.

Source: `cmd/openwatch/main.go` (scheduler wiring and maintenance knobs),
`internal/intelligence/scheduler/`, `internal/intelligence/discovery/scheduler/`.

### SECURITY_INCIDENT — suspected compromise or credential exposure

1. **Contain.** Block inbound 8443 at the host firewall, or stop the service if
   you must take it offline:

   ```bash
   sudo systemctl stop openwatch
   ```

2. **Preserve evidence.** Snapshot operational logs and the audit trail before
   changing anything:

   ```bash
   sudo journalctl -u openwatch --since '24 hours ago' > /tmp/openwatch-journal.log
   sudo -u postgres pg_dump -Fc openwatch > /tmp/openwatch-evidence.dump
   ```

3. **Review authentication and authorization events** in the audit trail —
   `auth.login.success`, `auth.login.failure`, role and user changes — for the
   incident window. Query the audit tables directly with `psql` or via the audit
   API.
4. **Rotate secrets.** Rotate the database password (update
   `/etc/openwatch/secrets.env`), and replace the JWT signing key
   (`/etc/openwatch/keys/jwt_private.pem`) and TLS cert/key as warranted.
   Replacing the JWT key invalidates all outstanding access tokens.
5. **Revoke or reset affected accounts.** Reset compromised users' passwords and
   reassign roles as needed; review `admin`-role membership.
6. **Restart and re-verify** once contained: `sudo systemctl start openwatch`,
   then the `SERVICE_DOWN` health check. File the incident per your
   organization's process.

Source: `cmd/openwatch/main.go` (JWT key loading, audit), `internal/identity/`,
`docs/engineering/audit_event_taxonomy.md`.

---

## 13. Hardening checklist

Network and transport

- [ ] Inbound TCP/8443 restricted to operator networks at the host firewall.
- [ ] PostgreSQL bound to loopback (or TLS-required) with `scram-sha-256` auth.
- [ ] CA-issued TLS cert installed at `/etc/openwatch/tls/`; key mode `0600`.
- [ ] If 8443 is reachable beyond a trusted network, an upstream reverse proxy
      provides rate limiting and security response headers.

Cryptography and keys

- [ ] `[identity].jwt_private_key` present, RSA ≥ 2048, mode `0600`.
- [ ] `[identity].credential_key_file` present, 32 bytes, mode `0600`.
- [ ] `OPENWATCH_DATABASE_DSN` in `secrets.env` (mode `0640`, `root:openwatch`),
      not in the world-readable TOML.
- [ ] For FIPS environments: the `-fips` build is deployed and
      `openwatch --version` reports `fips: true`.

Identity and access

- [ ] Admin accounts minimized; users hold the least-privileged role.
- [ ] MFA (TOTP) enrolled for privileged users.
- [ ] Breach-corpus check enabled for production password validation.

Process and platform

- [ ] `systemd-analyze security openwatch` reviewed; sandbox not loosened.
- [ ] `ProtectSystem=strict` and `ReadWritePaths` unchanged unless justified.

Audit and durability

- [ ] `journald` forwarded to a central collector.
- [ ] Scheduled, encrypted, off-host PostgreSQL backups meeting the retention
      window (audit trail lives in the database).

Source for every checklist item is cited in the section above that introduces it.

---

## Related documentation

- Install, configure, TLS replacement, uninstall:
  [`docs/guides/INSTALLATION.md`](INSTALLATION.md)
- RBAC registry and permission model:
  [`docs/engineering/rbac_registry.md`](../engineering/rbac_registry.md)
- Audit event taxonomy:
  [`docs/engineering/audit_event_taxonomy.md`](../engineering/audit_event_taxonomy.md)
- Kensa ↔ OpenWatch boundary:
  [`docs/KENSA_OPENWATCH_BOUNDARY.md`](../KENSA_OPENWATCH_BOUNDARY.md)
- API contract (per-operation required permission, license gate, audit events):
  [`api/openapi.yaml`](../../api/openapi.yaml)
- Behavioral specs: [`specs/`](../../specs/)
