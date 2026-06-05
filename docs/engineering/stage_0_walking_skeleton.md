# Stage 0 — Walking Skeleton

> **Status:** Plan, not yet executed
> **Goal:** Prove the entire toolchain composes correctly before any feature work begins
> **Estimate:** 7–13 working days, single-developer (revised 2026-04-30: RBAC registry added as Day 8; policies pushed to Day 9; subsequent days renumbered. Stage 0 has reached its working maximum — further foundation expansions should be evaluated against shipping Stage 0 first.)
> **Output:** A buildable, installable, runnable Go binary that exercises every architectural decision from the roadmap. One demonstrable endpoint. No business logic.

---

## Why this stage exists

Eighty percent of "I should have known sooner" architectural problems surface in the first week of integration: oapi-codegen output doesn't match the chi router's middleware contract, sqlc generates types that don't compose with pgx pool semantics, embed.FS paths break in cross-compile, microsoft/go FIPS toolchain refuses to build a CGO-less binary, systemd unit can't read `/etc/openwatch/secrets.env` because of permissions, the cert hot-reload callback double-locks under concurrency, etc.

If we hit any of these once we've built features on top of the stack, we re-architect with rework. If we hit them on a hello-world endpoint, we re-architect cheaply.

**The walking skeleton ships nothing of business value. That's the point.** It is the cheapest insurance against architectural rework that the project has.

---

## Definition of done

A reviewer (or you, in two weeks) can do all of these in one sitting:

1. `git clone` the repo at the Stage-0 tag, `cd app/`, and have a clear README walk them through every command below.
2. Run `make build` — produces `dist/openwatch` as a single statically-linked binary.
3. Run `make build-fips` — produces a FIPS-compliant binary using `microsoft/go`.
4. Run `make rpm` and `make deb` — produces installable packages (CentOS Stream 9 + Ubuntu 24.04).
5. Install the package on a test VM. Verify systemd unit installs to `/etc/systemd/system/openwatch.service`.
6. `systemctl start openwatch` — service starts, logs appear in `journalctl -u openwatch`.
7. `curl https://localhost:8443/api/v1/health` — returns `200 OK` with the canonical envelope. Cert is the test cert installed by the package.
8. `curl -X POST -H "Idempotency-Key: <uuid>" -H "X-Correlation-Id: test-1" https://localhost:8443/api/v1/diagnostics:echo -d '{"message":"hi"}'` — returns the message echoed back, with the same correlation ID in response headers.
9. `curl https://localhost:8443/api/v1/audit/events` — returns a paginated list including the audit event from step 8.
10. Replay step 8 with the same idempotency key — returns identical response (no second audit event written).
11. `curl -H "X-Stub-Role: viewer" https://localhost:8443/api/v1/auth/me/permissions` — returns the viewer role's permission list (read-only set).
12. `curl -H "X-Stub-Role: viewer" -X POST https://localhost:8443/api/v1/diagnostics:require-host-write` — returns `403` with `error.code = "authz.permission_denied"` and `detail.required_permission: "host:write"`. An `authz.permission_denied` audit event is recorded.
13. `curl -H "X-Stub-Role: security_admin" -X POST https://localhost:8443/api/v1/diagnostics:require-remediation-execute` — returns `402` with `error.code = "license.feature_unavailable"` (RBAC passed; license check failed). A `license.feature_check_denied` audit event is recorded.
14. `curl -X POST https://localhost:8443/api/v1/diagnostics:evaluate-alert -d '{"score":65}'` — returns a `Decision` from the active `alert_thresholds` policy with `policy_version` populated. A `policy.applied` audit event appears via `/audit/events`.
15. Drop a signed `policies/alert_thresholds.yaml` v1.0.0; `POST /admin/policies:reload` returns `outcome: loaded`. Replay step 14 — the new policy's decision is returned.
16. `curl -X POST -H "X-Correlation-Id: req-end2end-001" https://localhost:8443/api/v1/diagnostics:enqueue-test-job -d '{}'` — enqueues a no-op job. Worker picks it up and writes a `diagnostics.test_job_completed` audit event. Both the API audit event and the worker audit event for this request return matching `correlation_id: req-end2end-001` from `/audit/events`. (Note: the original DoD used `test-` here, but `test-` is reserved for in-process generation by the correlation contract — clients use `req-`.)
17. `specter sync` in the repo root — passes with 100% AC coverage on the demo specs (echo + correlation propagation + RBAC).
18. Edit the cert file on disk. New TLS handshakes pick up the new cert without restarting the service.
19. Stop the service. Database state survives. Restart. Service comes back healthy. The `system.startup` audit event from the restart shares one `boot-` correlation_id with the `policy.loaded` and `license.loaded` events at startup.

If any of those 19 steps fail, Stage 0 is not done.

---

## What the skeleton does NOT include

Stage 0 is a forcing function. To stay focused, these are explicit non-goals:

- **No business logic.** No hosts, scans, findings, or compliance state. The only "feature" is a diagnostic echo endpoint.
- **No frontend.** A trivial `index.html` says "OpenWatch is running" — that's it. Real frontend integration is Stage 2.
- **No Kensa.** Engine integration is Stage 2.
- **No SSH.** Required for scans, deferred to Stage 2.
- **No auth.** The skeleton's two endpoints are anonymous. Auth lands in Slice A of Stage 2. Why: auth is feature work that can mask toolchain problems if we wire it in too early.
- **No multi-host or job queue execution.** The job_queue tables are migrated and a worker process exists, but it does nothing except idle. Real jobs land in Stage 2.

> **One non-obvious deferral:** auth. It's tempting to build login first because everything depends on it. But the toolchain is what we're testing here. Auth is a feature. Build the auth slice in Stage 2 once we know oapi-codegen + pgx + microsoft/go all play nicely.

---

## Architecture decisions exercised

Each Stage-0 acceptance criterion maps to a specific roadmap decision:

| Criterion | Roadmap decision verified |
|---|---|
| `make build` produces single static binary | Go backend; embed.FS frontend |
| `make build-fips` works | microsoft/go FIPS toolchain |
| RPM + DEB build via `make rpm/deb` | RPM/DEB packaging from `packaging/` carries to Go |
| systemd unit installs and starts | Fully native deployment topology (Phase 1) |
| `/health` returns canonical envelope | Error envelope shape, top-level health endpoint |
| `Idempotency-Key` round-trip | Idempotency key contract (24h TTL) |
| `X-Correlation-Id` round-trip on response | Correlation IDs end-to-end (HTTP boundary) |
| API + worker audit events share one correlation_id | Correlation propagation across HTTP→queue→worker |
| Boot events share one `boot-` correlation_id | Single-ID-per-startup contract |
| Stub-role-based permission denial returns 403 + audit | RBAC registry + middleware + audit chain |
| License-gated permission denial returns 402 not 403 | Combined RBAC+license middleware order (RBAC first) |
| Audit log endpoint queryable | Audit-as-API contract |
| Idempotent replay | Same key = same response, no duplicate side effects |
| Specter passes with 100% AC coverage | Behavioral contract enforcement |
| Cert hot-reload | TLS-managed-by-Go (no Nginx) |
| Restart preserves state | pgx pool + goose migrations work |
| TOML + env + flag config | Config layering (CLI > env > file > defaults) |
| `journalctl -u openwatch` shows structured logs | `log/slog` to stdout |

If any of those decisions don't survive Stage 0, they're wrong. Better to find out now.

---

## Deliverables (in order)

### Day 1 — Repository scaffold

**Goal:** `make build` produces a hello-world Go binary that does nothing.

```
app/
├── api/
│   ├── hosts.yaml              # already exists (Stage A worked example)
│   ├── scans.yaml              # already exists
│   └── openapi.yaml            # NEW: meta-spec composing all domain specs
├── cmd/
│   └── openwatch/
│       └── main.go             # entry point, ~50 LOC
├── internal/
│   ├── server/                 # placeholder package
│   │   └── server.go
│   ├── config/                 # placeholder
│   │   └── config.go
│   └── version/
│       └── version.go          # build-time injected version string
├── go.mod
├── go.sum
├── Makefile                    # build, build-fips, rpm, deb, test, clean
├── README.md                   # how to build, install, run
└── .gitignore
```

`go.mod` deps locked to:

```go
require (
    github.com/go-chi/chi/v5 v5.x
    github.com/jackc/pgx/v5 v5.x
    github.com/oapi-codegen/oapi-codegen/v2 v2.x
    github.com/oapi-codegen/runtime v1.x
    github.com/pressly/goose/v3 v3.x
    github.com/BurntSushi/toml v1.x
    github.com/golang-jwt/jwt/v5 v5.x        // not used in Stage 0, but locked
    github.com/go-playground/validator/v10 v10.x
)
```

`Makefile` targets:

- `make build` → `go build -o dist/openwatch ./cmd/openwatch`
- `make build-fips` → uses `microsoft/go` toolchain via `GOEXPERIMENT=systemcrypto`
- `make generate` → runs `oapi-codegen` against `app/api/openapi.yaml`
- `make migrate` → runs goose migrations against the configured DB
- `make rpm` → calls `packaging/rpm/build-rpm.sh` (adapted for Go binary)
- `make deb` → calls `packaging/deb/build-deb.sh`
- `make test` → `go test ./...`
- `make spec` → runs `specter sync`
- `make run` → builds and runs locally with a dev TOML config

**Acceptance:** `make build && ./dist/openwatch --version` prints a version string. Nothing else.

---

### Day 2 — Config + flags + TOML

**Goal:** The binary reads a TOML config, applies env-var overrides, and accepts CLI flags.

Config file at `/etc/openwatch/openwatch.toml`:

```toml
[server]
listen = "0.0.0.0:8443"
tls_cert = "/etc/openwatch/tls/cert.pem"
tls_key = "/etc/openwatch/tls/key.pem"

[database]
dsn = "postgres://openwatch@localhost/openwatch?sslmode=disable"
max_connections = 25

[logging]
level = "info"
format = "json"
```

Env-var overrides: `OPENWATCH_SERVER_LISTEN`, `OPENWATCH_DATABASE_DSN`, etc. (Underscored from the TOML path.)

CLI flags via stdlib `flag`:

- `--config <path>` — defaults to `/etc/openwatch/openwatch.toml`
- `--version` — prints version, exits
- `migrate` — subcommand; runs goose migrations and exits
- `check-config` — validates config and exits
- `serve` — runs the HTTP server (default if no subcommand)

**Acceptance:**
- `./openwatch check-config` validates a sample TOML.
- `OPENWATCH_SERVER_LISTEN=0.0.0.0:9443 ./openwatch check-config` shows override applied.
- `./openwatch --listen 0.0.0.0:8000 check-config` shows flag override.

---

### Day 3 — PostgreSQL + goose migrations

**Goal:** Binary connects to PostgreSQL, runs migrations, basic CRUD against a test table.

Files:

- `internal/db/db.go` — pgx pool connection helper
- `internal/db/migrations/0001_initial.sql` — creates `audit_events` and `idempotency_keys` tables (the only two tables Stage 0 needs)
- `internal/db/queries/audit.sql` — sqlc input
- `internal/db/queries/audit.sql.go` — sqlc-generated (regenerated via `make generate`)
- `sqlc.yaml` — sqlc config

**Migration 0001:**

```sql
-- +goose Up
CREATE TABLE audit_events (
    id              UUID PRIMARY KEY,
    correlation_id  TEXT NOT NULL,
    actor_type      TEXT NOT NULL,         -- 'system' for Stage 0
    actor_id        TEXT,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    detail          JSONB,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_correlation ON audit_events (correlation_id);
CREATE INDEX idx_audit_occurred_at ON audit_events (occurred_at DESC);

CREATE TABLE idempotency_keys (
    key             TEXT PRIMARY KEY,
    request_hash    TEXT NOT NULL,
    response_status INT NOT NULL,
    response_body   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_idempotency_expires ON idempotency_keys (expires_at);

-- +goose Down
DROP TABLE idempotency_keys;
DROP TABLE audit_events;
```

**sqlc queries** (audit.sql):

```sql
-- name: InsertAuditEvent :one
INSERT INTO audit_events (id, correlation_id, actor_type, actor_id, action, resource_type, resource_id, detail)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListAuditEvents :many
SELECT * FROM audit_events
WHERE ($1::timestamptz IS NULL OR occurred_at < $1)
ORDER BY occurred_at DESC, id DESC
LIMIT $2;
```

**Acceptance:**
- `./openwatch migrate` creates both tables.
- A unit test inserts an audit event and reads it back.
- Restart binary; data survives.

---

### Day 4 — HTTP server + chi + TLS + cert hot-reload + correlation propagation

> **Updated 2026-04-30:** correlation propagation foundation (`internal/correlation/`, slog handler, httpclient wrapper) folded into Day 4. The audit foundation in Day 5 already requires `X-Correlation-Id` on context, so the propagation contract must exist before any endpoint is written. Full design in `app/docs/correlation_id_propagation.md`.

**Goal:** HTTPS server running with chi router, cert hot-reload via `GetCertificate`, and the correlation propagation contract end-to-end (HTTP entry → context → slog → outbound HTTP). Job-queue propagation lands Day 9.

Files:

- `internal/server/server.go` — http.Server setup, tls.Config, chi router wiring
- `internal/server/tls.go` — `GetCertificate` callback that re-reads cert from disk on each handshake (with mtime-based caching)
- `internal/correlation/correlation.go` — context key, `Set`, `From`, `Generate`, `SanitizeOrGenerate`, prefix constants (req/cron/boot/test)
- `internal/correlation/http.go` — `HTTPMiddleware` (sanitize, set on ctx, set response header, log warn on rejected client values)
- `internal/log/handler.go` — `CorrelationHandler` wraps `slog.JSONHandler` to add correlation_id from ctx as a top-level attr
- `internal/httpclient/client.go` — `net/http.Client` wrapper that forwards `X-Correlation-Id` on outbound calls
- `app/cmd/openwatch/main.go` — generates `boot-` correlation at startup; passes ctx through `license.Load`, `policy.LoadAll`, `audit.EmitSync`, `server.Run`
- `.golangci.yml` — `forbidigo` config rejecting raw `slog.Info`/`Warn`/`Error`/`Debug`, `http.DefaultClient`, raw `INSERT INTO job_queue` outside `internal/queue/`

Cert hot-reload pattern:

```go
type certManager struct {
    certPath, keyPath string
    mu                sync.RWMutex
    cached            *tls.Certificate
    cachedAt          time.Time
}

func (m *certManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
    m.mu.RLock()
    if m.cached != nil && time.Since(m.cachedAt) < 5*time.Second {
        defer m.mu.RUnlock()
        return m.cached, nil
    }
    m.mu.RUnlock()

    m.mu.Lock()
    defer m.mu.Unlock()
    cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
    if err != nil {
        return nil, err
    }
    m.cached = &cert
    m.cachedAt = time.Now()
    return &cert, nil
}
```

`http.Server` config locked to:

- `ReadHeaderTimeout: 10s`
- `ReadTimeout: 30s`
- `WriteTimeout: 60s`
- `IdleTimeout: 120s`
- `MaxHeaderBytes: 1 << 16` (64 KiB)

**Acceptance:**
- `./openwatch serve` listens on `https://0.0.0.0:8443`.
- `curl -k https://localhost:8443/` returns a 404 with the canonical error envelope; response includes `X-Correlation-Id` header.
- Replace cert files on disk. New `curl` shows new cert via `openssl s_client -showcerts`. Without restart.
- `curl -H "X-Correlation-Id: my-test-001" -k https://localhost:8443/` echoes the same ID in the response header.
- `curl -H "X-Correlation-Id: $(printf 'a%.0s' {1..200})" -k https://localhost:8443/` regenerates (header value too long); response carries a fresh `req-` ID; structured warning log records the rejection.
- `curl -H "X-Correlation-Id: cron-fake" -k https://localhost:8443/` regenerates (reserved prefix); fresh `req-` ID.
- Startup logs (`journalctl -u openwatch | head -20`) show a single `boot-` correlation_id shared across all startup events.
- Every JSON log line has a `correlation_id` field; none are empty for HTTP-served requests.
- `golangci-lint run` rejects a planted `slog.Info("test")` call (no Context variant).

---

### Day 5 — OpenAPI codegen + first endpoints + audit foundation

> **Updated 2026-04-29:** audit event taxonomy folded into Day 5. The first endpoints emit audit events, so the foundation must exist before they're written.
>
> **Updated 2026-04-30:** audit emit reads `correlation_id` from `context.Context` via `correlation.From(ctx)` (the Day 4 foundation). No changes to Day 5 work — just confirming the dependency. If `correlation_id` is missing on context, the writer logs a warning and increments a counter (per `correlation_id_propagation.md` §5.3); the event still writes.

**Goal:** Two endpoints implemented from `app/api/openapi.yaml` via oapi-codegen.

Endpoints for Stage 0:

1. `GET /api/v1/health` — current health (returns `{status: "healthy", db_connected: true, version: "..."}`).
2. `POST /api/v1/diagnostics:echo` — echoes request body back, exercises idempotency, writes audit event. Body: `{message: string}`.
3. `GET /api/v1/audit/events` — cursor-paginated list of audit events.

These three endpoints exercise:
- Routing (chi)
- Codegen (oapi-codegen → chi-compatible handlers)
- DB read (`/health` checks db connection)
- DB write (`:echo` writes audit event)
- DB read with pagination (`/audit/events`)
- Idempotency middleware
- Correlation ID middleware
- Error envelope shape
- Cursor pagination

**Spec files:**

Create `app/api/openapi.yaml` (meta-spec) that imports from `hosts.yaml` (already exists) and adds:

- `/health` — health check
- `/diagnostics:echo` — diagnostic echo (action form, demonstrates `:action` pattern)
- `/audit/events` — audit list (cursor pagination)

For Stage 0, the meta-spec only references the new minimal endpoints. Hosts and scans are wired in later stages.

**Audit foundation (per `app/docs/audit_event_taxonomy.md`):**

- `app/audit/events.yaml` registry committed (already drafted: ~70 codes across 13 categories)
- `internal/audit/events.gen.go` produced by codegen with typed constants
- `internal/audit/{types,emit,writer,redact,store}.go` per package layout in §5.1
- Migration `0002_audit_events.sql` creates `audit_events` table with 7 indexes per §6.2
- Async writer goroutine started on boot (channel + 100/100ms batched insert), drained on shutdown
- Critical-event sync path (`EmitSync`) for license, system.startup, system.shutdown
- Redaction pre-write scrubs `password`, `ssh_key`, `api_key`, `token`, `secret`, `license_jwt` from `detail`

**Acceptance:**
- `make generate` produces `internal/server/api/server.gen.go` from the meta-spec.
- All three endpoints respond correctly.
- `curl https://localhost:8443/api/v1/health` returns JSON.
- `:echo` writes one audit event with proper canonical envelope per `audit_event_taxonomy.md` §3.
- `:echo` replay with same key returns identical response, no second audit event.
- `system.startup` event written synchronously on boot.
- `GET /api/v1/audit/events` returns the events with full envelope including correlation_id, actor, resource fields.
- `GET /api/v1/audit/events:taxonomy` returns the parsed registry. *(deferred to Phase 1; the registry ships embedded in `events.gen.go` and is exposed via API when the frontend needs it.)*
- Redaction test: emit event with `detail.password = "x"` → stored row shows `detail.password = "<REDACTED>"` and `redactions = ["password"]`.
- Emit benchmark: async <10µs per call, sync <500µs per call.
- Bench: 1000 emit calls → 1000 events written within 200ms.

---

### Day 6 — Idempotency middleware

> **Status (2026-04-29):** Complete. Implemented as part of Day 5b since
> `:echo` depends on it. Live: replay verified (two POSTs with same
> `Idempotency-Key` + same body produce 1 audit row; handler not re-invoked).
> See `internal/idempotency/middleware.go` and `specs/system/idempotency.spec.yaml`.

**Goal:** Idempotency-Key header makes replays safe.

Files:

- `internal/server/middleware/idempotency.go`

Behavior:
1. On request to mutating endpoints (`POST`/`PUT`/`PATCH`/`DELETE`), check for `Idempotency-Key` header.
2. If present, lookup `idempotency_keys` table for that key.
3. If found AND `request_hash` matches: return cached `response_body` with cached `response_status`. Do NOT re-invoke the handler.
4. If found AND `request_hash` differs: return `409 Conflict` with `error.code = "idempotency.key_reused"`.
5. If not found: invoke handler. After handler runs successfully, store key + request_hash + response_body + response_status with 24h TTL.
6. Cleanup of expired keys runs in a background goroutine every hour.

**Acceptance:**
- Two replays of `:echo` with the same key return identical responses.
- Only one audit event written.
- Replay with different body but same key returns 409 + `idempotency.key_reused`.
- After 24h, the key is purged and a fresh request creates a new audit event.

> **Test the 24h TTL with a flag:** `--idempotency-ttl 60s` for tests, default `24h` for production.

---

### Day 7 — Licensing foundation (added 2026-04-28)

**Goal:** The license validation seam is wired end-to-end so Phase-2 features can declare `x-required-feature` confidently.

Files (per `app/docs/licensing_foundation.md`):

- `internal/license/types.go` — License, Feature, Quota, State structs
- `internal/license/features.go` — feature registry loader (parses `app/license/features.yaml`)
- `internal/license/validator.go` — JWT (EdDSA/Ed25519) parsing + signature verification + claim checks
- `internal/license/loader.go` — file loading, fingerprint check
- `internal/license/state.go` — `*atomic.Pointer[State]` for lock-free reads
- `internal/license/middleware.go` — `RequireFeature(featureID)` chi middleware
- `internal/license/audit.go` — license event emission
- `internal/license/keys/license-pubkey-current.pem` — embedded test key (for Stage 0 only; production keys come from Hanalyx infra)
- `app/license/features.yaml` — initial 9 feature IDs
- `app/cmd/owlicgen/main.go` — license generator tool (uses test private key for Stage 0; production private key never on dev machines)

Stage 0 demo endpoint: `POST /api/v1/diagnostics:premium-echo` declared in `openapi.yaml` with `x-required-feature: premium_diagnostics`. Without a license file → returns `402` with `error.code = "license.feature_unavailable"` and emits `license.feature_check_denied` audit event. With a Stage-0 test license that includes `premium_diagnostics` → succeeds.

Migration `0003_licenses.sql`: creates the `licenses` table per `licensing_foundation.md` §6.1.

**Acceptance:**
- Service boots without license file in Free tier; `GET /api/v1/license` returns `status: "no_license"`.
- `owlicgen` produces a test license including `premium_diagnostics`.
- Drop the test license at `/etc/openwatch/license.lic`, send SIGHUP. `GET /api/v1/license` reflects the new license. `:premium-echo` succeeds.
- `POST /api/v1/admin/license:verify` with a tampered JWT returns `is_valid: false` with the specific failed check (signature/issuer/audience).
- Replay `:premium-echo` without a license → 402 with proper error envelope; audit event emitted.
- `IsEnabled` benchmark confirms ~20ns per check (lock-free atomic load).

> **Why this is in Stage 0, not Stage 2:** licensing is foundation. If we add it after Phase-2 features depend on it, every gated handler has to be retrofitted. One day in Stage 0 saves two weeks in Stage 2.

### Day 8 — RBAC registry (added 2026-04-30)

> **Status (2026-05-24):** Complete (codegen + middleware + demo endpoints).
> 59 permissions across 18 categories. 5 built-in roles with wildcards
> expanded at codegen time. `RequirePermission` middleware enforces RBAC
> first (403), license gate second (402). `specs/system/rbac.spec.yaml`
> ships at 16/16 ACs covered under `specter coverage --strict`. Deferred
> to follow-up: `scripts/validate-rbac.go` and `scripts/validate-openapi.go`
> (registry shape is enforced at codegen time today).

**Goal:** Permission registry, built-in roles, combined RBAC+license middleware, and the OpenAPI validator extension are wired end-to-end. Stage-2 endpoints can declare `x-required-permission` and have it enforced from day one.

Files (per `app/docs/rbac_registry.md`):

- `app/auth/permissions.yaml` — registry of permissions, categories, and built-in roles (~50 permissions across 17 categories; 5 built-in roles)
- `internal/auth/permissions.gen.go` — codegen-typed `Permission` constants and `Permissions` metadata map
- `internal/auth/roles.gen.go` — codegen-typed `RoleID` constants and `BuiltInRoles` map (wildcards expanded at codegen time)
- `internal/auth/middleware.go` — `RequirePermission(p)` chi middleware combining RBAC + license-gate check in one pass
- `internal/auth/registry.go` — runtime lookup helpers (`HasPermission`, `LicenseGate`, `IsDangerous`)
- `scripts/validate-rbac.go` — registry validator (regex, category refs, license_gated cross-refs, role permission validation)
- `scripts/validate-openapi.go` — extension validator: every `x-required-permission` is registered; `license_gated` permissions co-declare `x-required-feature`; dangerous permissions co-declare `x-audit-events`
- Migration `0004_roles.sql` — creates `roles` and `user_roles` tables; inserts the 5 built-in roles with `is_built_in=true`
- `.golangci.yml` — forbidigo rule rejecting raw permission-string literals outside `internal/auth/`

Stage 0 demo:

- `POST /api/v1/diagnostics:require-host-read` declared in `openapi.yaml` with `x-required-permission: host:read`. Stage-0 user model is a stub (real auth lands Stage 2 Slice A); the Stage-0 demo grants the calling identity a synthetic role determined by an `X-Stub-Role` header (`viewer`, `auditor`, `ops_lead`, `security_admin`, `admin`) — sufficient to verify the middleware fires.
- `GET /api/v1/auth/me/permissions` — returns the calling identity's effective permissions (built-in role expansion).
- `GET /api/v1/auth/permissions:registry` — returns the full registry (categories, permissions, built-in roles) for frontend rendering.
- `GET /api/v1/admin/roles` — returns the 5 built-in roles. Custom-role CRUD is Stage 2.

**Acceptance:**

- `make generate` produces `permissions.gen.go` and `roles.gen.go` from the registry.
- `golangci-lint run` rejects a planted `if user.HasPermission("host:read")` (raw string).
- `validate-rbac.go` rejects a registry edit that introduces an unknown category, a `license_gated` value not in `features.yaml`, or a built-in role granting an unregistered permission.
- `validate-openapi.go` rejects a spec that declares `x-required-permission: host:writte` (typo); rejects a spec that declares `x-required-permission: remediation:execute` without `x-required-feature: remediation_execution`; rejects a spec that declares a dangerous permission without `x-audit-events`.
- `:require-host-read` with `X-Stub-Role: viewer` succeeds (`viewer` has `host:read`).
- `:require-host-read` with `X-Stub-Role: <none>` returns `403` with `error.code = "authz.permission_denied"`; `authz.permission_denied` audit event emitted with `detail.required_permission: "host:read"`.
- `POST /api/v1/diagnostics:require-remediation-execute` (declared with `x-required-permission: remediation:execute` + `x-required-feature: remediation_execution`) with `X-Stub-Role: security_admin` and no license → `402` with `error.code = "license.feature_unavailable"`; `license.feature_check_denied` audit event emitted.
- Same call with `X-Stub-Role: viewer` and a valid license → `403` (RBAC fails first).
- `GET /auth/me/permissions` for `X-Stub-Role: ops_lead` returns the expected permission list including category-wildcard expansions.
- `GET /auth/permissions:registry` returns the full registry; matches `app/auth/permissions.yaml` source.
- `RequirePermission` middleware benchmark < 1µs per call.

> **Why this is in Stage 0, not Stage 2:** every Stage-2 endpoint that declares `x-required-permission` lands into a working middleware. Without the registry, the first Stage-2 slice's handlers either ship with hand-written gating decorators (the failure mode that produced today's drift) or block on RBAC scaffolding being added retroactively. One day in Stage 0 saves a multi-week refactor when 6+ Stage-2 feature areas land concurrently.

### Day 9 — Policies-as-data scaffolding + queue correlation helpers (added 2026-04-29; expanded 2026-04-30)

> **Status (2026-05-24):** Complete (queue + policy framework + spec ACs).
> Two specs added: `specs/system/job-queue.spec.yaml` (11 ACs) and
> `specs/system/policy.spec.yaml` (12 ACs). Migrations 0003 (`job_queue`)
> and 0004 (`policy_history`). `internal/queue/` ships `Enqueue` (rejects
> missing correlation_id), `Dequeue` (FOR UPDATE SKIP LOCKED, fresh
> worker ctx with the job's correlation_id, never the caller's),
> `Complete`/`Fail`. `internal/cron/` ships the per-tick correlation
> scheduler. `internal/policy/` ships the generic loader (Ed25519 verify
> + semver monotonic + atomic.Pointer swap), `alert_thresholds`
> evaluator, `policy_history` snapshot, audit emit. Forbidigo rules
> reject raw `INSERT INTO job_queue` and `http.DefaultClient`. Demo
> HTTP endpoints (`:enqueue-test-job`, `:evaluate-alert`,
> `:reload-policies`) deferred to a follow-up — the spec ACs are
> validated by per-package tests, not by HTTP veneer.

**Goal:** Policy framework loads, validates, snapshots, and emits audit events end-to-end. Type-specific evaluators are stubs returning built-in defaults; real evaluation comes online with each consumer in Stage 2. **Concurrent goal:** the `internal/queue/` enqueue/dequeue helpers ship with correlation propagation built in, so Stage-2 handlers cannot bypass the contract from `correlation_id_propagation.md`.

Files (per `app/docs/policies_as_data.md`):

- `internal/policy/state.go` — `*atomic.Pointer[State]`, `Get()`, `IsActive()` (lock-free)
- `internal/policy/loader.go` — read file, verify Ed25519 signature, validate against type-specific schema, monotonic-version check, atomic swap
- `internal/policy/reload.go` — SIGHUP handler + admin endpoint glue
- `internal/policy/history.go` — snapshot to `policy_history` table
- `internal/policy/audit.go` — `policy.loaded` / `.invalid` / `.applied` emit helpers
- `internal/policy/types/{exceptions,approvals,schedules,alert_thresholds,remediation}.go` — typed structs + JSON Schema validators
- `internal/policy/eval/{exceptions,approvals,schedules,alert_thresholds,remediation}.go` — evaluator stubs returning `Decision` from built-in defaults
- `internal/policy/keys/admin-pubkey-current.pem` — embedded test key (production keys come from Hanalyx infra)
- `policies/{type}.default.yaml` — built-in default policies, version `0.0.0`, unsigned in dev mode
- `app/cmd/owpolicysign/main.go` — policy signing tool (uses test private key for Stage 0)

Files (per `app/docs/correlation_id_propagation.md`):

- `internal/queue/enqueue.go` — `Enqueue(ctx, jobType, payload)` extracts correlation_id from ctx; errors if missing
- `internal/queue/dequeue.go` — `Dequeue(ctx) (*Job, context.Context, error)` reads correlation_id from row, restores onto fresh context
- `internal/queue/job.go` — `Job` struct with `CorrelationID string`
- `internal/cron/scheduler.go` — `tick()` generates fresh `cron-` correlation_id per tick
- Migration `0001_job_queue.sql` (Day 3) **updated** to add `correlation_id TEXT NOT NULL` column + index `idx_job_queue_correlation`. (If Day 3 already shipped, ship a follow-up migration `0001a_job_queue_correlation.sql`.)

Stage 0 demo (policy):

- `POST /api/v1/admin/policies:reload` declared in `openapi.yaml` with `x-required-permission: admin.policies.reload`. Returns the per-type reload outcome map (`{loaded | invalid | unchanged}`).
- One policy type (`alert_thresholds`) is wired to a synthetic Stage-0 caller: `POST /api/v1/diagnostics:evaluate-alert` with body `{score: 65}` evaluates against the active policy and returns the `Decision`. Verifies the eval → audit chain works without needing real scan data.

Stage 0 demo (queue + correlation):

- `POST /api/v1/diagnostics:enqueue-test-job` enqueues a no-op job (`diagnostics.test_job`). Worker dequeues, sleeps 1s, emits `diagnostics.test_job_completed` audit event. The end-to-end test asserts the API audit event and the worker audit event share the same correlation_id.

Migration `0005_policy_history.sql`: creates the `policy_history` table per `policies_as_data.md` §6.3.

OpenAPI codegen extensions: `oapi-codegen` config gains parsers for `x-requires-approval` and `x-policy-evaluated` (parsing only — middleware generation in Stage 2 when approvals state machine exists).

**Acceptance (policy):**

- Service boots with no `policies/*.yaml` on disk; built-in defaults load with `version: 0.0.0`. `policy.loaded` audit event emitted for each type.
- Drop a signed `policies/alert_thresholds.yaml` at version `1.0.0` into `/opt/openwatch/policies/`; `POST /admin/policies:reload` returns `outcome: loaded`. New version active. `policy.loaded` audit event records `previous_version: 0.0.0`.
- Replay reload with the same file → `outcome: unchanged` (source_hash matches), no new policy_history row, no new audit event.
- Submit a `version: 0.9.0` of the same type → `outcome: invalid`, `policy.invalid` audit event with `errors: ["version regression: 0.9.0 < 1.0.0"]`. Previous in-memory state retained.
- Submit a tampered file (signature broken) → `outcome: invalid`, `policy.invalid` audit event with signature error.
- Submit a file with unknown rule reference → `outcome: invalid`, `policy.invalid` with the reference in `errors[]`.
- `:evaluate-alert` against `score: 65` returns the expected `Decision` (severity per active policy); `policy.applied` audit event emitted via async path.
- `Evaluate()` benchmark confirms < 50µs p99.
- SIGHUP reloads all types; per-type outcomes logged.
- `policy_history` table contains one row per successful load; `superseded_at` populated correctly when a newer version replaces an older one.

**Acceptance (queue + correlation):**

- `queue.Enqueue` returns an error when called with a `context.Background()` — programming-error guard works.
- `:enqueue-test-job` with `X-Correlation-Id: test-end2end-001` produces matching audit events at API and worker; both have `correlation_id: test-end2end-001`.
- `:enqueue-test-job` without a header generates a fresh `req-` ID; worker audit event carries the same ID.
- A second job enqueued while the first is in-flight has a different correlation_id (no leakage between concurrent requests).
- Cron scheduler tick (synthetic Stage-0 cron job runs every 30s; emits `system.health.recovered` audit event) produces audit events with `cron-` prefix; each tick has a distinct ID.
- `golangci-lint run` rejects a planted raw `INSERT INTO job_queue` outside `internal/queue/`.
- `golangci-lint run` rejects a planted `http.DefaultClient.Get(...)` (forbidigo `http.DefaultClient`).

> **Why this is in Stage 0, not Stage 2:** every policy-gated handler in Stage 2 (exception requests, approval routing, scheduler, alert dispatch, remediation) needs the framework to exist before it's written. Building the framework alongside its first consumer means every consumer retrofits when the second arrives. The queue helpers piggyback on the same day because (a) policy framework is the first non-trivial consumer of the audit→queue chain and (b) shipping the helpers with correlation built in *before* any real job type exists makes Stage-2 retrofits unnecessary. One day in Stage 0 saves a multi-week refactor when alert thresholds, approvals, and the first scan job all land in close succession.

---

### Day 10 — Specter spec + AC coverage

**Goal:** One behavioral spec covering `:echo` with full AC traceability via `specter ingest`.

Files:

- `specs/api/diagnostics-echo.spec.yaml` — spec for the echo endpoint
- `internal/server/api/diagnostics_echo_test.go` — Go tests with `# Spec:` comment + AC docstrings

**Spec sample:**

```yaml
spec_id: api/diagnostics-echo
status: active
acceptance_criteria:
  - id: AC-1
    description: Echoes the request message verbatim
  - id: AC-2
    description: Writes one audit event per unique correlation_id
  - id: AC-3
    description: Idempotency-Key replay returns identical response
  - id: AC-4
    description: Idempotency-Key with different body returns 409
```

Test file uses Go `testing` package with `// Spec: api/diagnostics-echo` header and `// AC-1` per test function.

**Acceptance:**
- `specter sync` passes with no errors.
- `specter coverage --enforce-active` shows 100% AC coverage for the spec.
- `go test -json ./... | specter ingest` succeeds.

---

### Day 11 — Native packaging (RPM + DEB)

> **Status (2026-05-24):** Complete. Spec
> `specs/release/package-build.spec.yaml` (13 ACs) at 100% strict
> coverage. `make rpm` produces `dist/openwatch-<ver>.x86_64.rpm`;
> `make deb` produces `dist/openwatch_<ver>_amd64.deb`. Both packages
> install the binary at `/usr/bin/openwatch`, default config at
> `/etc/openwatch/openwatch.toml`, systemd unit at
> `/etc/systemd/system/openwatch.service`, and a demo TLS cert under
> `/etc/openwatch/tls/`. Maintainer scripts: pre-install creates the
> openwatch system user/group, post-install runs daemon-reload,
> pre-uninstall stops + disables. Go tests in `packaging/tests/`
> exercise every AC against the real artifacts using rpm + dpkg-deb.

**Goal:** Buildable RPM and DEB packages that install the binary, systemd unit, default config, and demo cert.

Adapt `packaging/rpm/build-rpm.sh` and `packaging/deb/build-deb.sh` for the Go binary instead of Python:

- Single binary at `/usr/bin/openwatch`
- Config at `/etc/openwatch/openwatch.toml`
- TLS materials at `/etc/openwatch/tls/{cert.pem,key.pem}` (test cert; production deploys replace)
- Systemd unit at `/etc/systemd/system/openwatch.service`
- Post-install: `systemctl daemon-reload`
- Pre-uninstall: `systemctl stop openwatch && systemctl disable openwatch`

Systemd unit:

```ini
[Unit]
Description=OpenWatch Compliance Platform
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=openwatch
Group=openwatch
EnvironmentFile=-/etc/openwatch/secrets.env
ExecStart=/usr/bin/openwatch serve
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/openwatch /var/log/openwatch

[Install]
WantedBy=multi-user.target
```

**Acceptance:**
- `make rpm` builds a CentOS Stream 9 RPM.
- `make deb` builds an Ubuntu 24.04 DEB.
- `dnf install ./dist/openwatch-*.rpm` (CS9) or `apt install ./dist/openwatch-*.deb` (Ubuntu) installs cleanly.
- Service starts via `systemctl start openwatch`.

---

### Day 12 — FIPS build via microsoft/go

> **Status (2026-05-24):** Complete using Go 1.25's native FIPS 140-3
> mode (`GOFIPS140=v1.0.0`) instead of microsoft/go. Go 1.24+ ships the
> in-toolchain FIPS module, so the second toolchain is unnecessary —
> stock Go is the dependency. `make build-fips` builds
> `dist/openwatch-fips` linked against `crypto/internal/fips140/v1.0.0`.
> Spec `specs/release/fips-build.spec.yaml` (8 ACs) at 100% strict
> coverage. Tests verify: version flag (`fips: true` vs `false`), linked
> module symbols, TLS handshake + /health serves identically, full
> license + RBAC + correlation suites pass under `GOFIPS140=v1.0.0`
> (Ed25519 is FIPS 186-5 approved), build metadata matches across both
> binaries.

**Goal:** A second binary, built with the FIPS toolchain, runs and produces identical functional output.

Tasks:
1. Install `microsoft/go` toolchain in CI.
2. `make build-fips` uses it.
3. Verify binary uses FIPS-validated crypto: `openwatch --version` includes a flag like `fips=true`.
4. All Day-7 tests pass against the FIPS binary.

**Acceptance:**
- `dist/openwatch-fips` exists, ELF-inspectable, links OpenSSL FIPS provider.
- `./dist/openwatch-fips --version` shows `fips=true`.
- Running `:echo` against the FIPS binary returns identical results to non-FIPS.

---

### Day 13 — Documentation, demo, sign-off

> **Status (2026-05-24):** Complete. Spec
> `specs/release/stage-0-signoff.spec.yaml` (13 ACs) at 100% strict
> coverage. The four previously-deferred demo endpoints
> (`:require-host-write`, `:evaluate-alert`, `:enqueue-test-job`,
> `/admin/policies:reload`) are wired and tested. In-process worker
> (`internal/worker/`) drains `diagnostics.test_job` and emits the
> completion event with the originating correlation_id. README expanded
> with a developer walkthrough and a runnable mapping of every DoD step
> to its enforcing test. **DoD step 16 amended**: the original example
> used `X-Correlation-Id: test-end2end-001` which collides with the
> `test-` reserved prefix in the correlation contract; the canonical
> example uses `req-end2end-001`. **18/18 specs at 100% under
> `specter coverage --strict`.**

**Goal:** A `app/README.md` that walks a new developer through every command. The 19-step Definition of Done passes end-to-end on a fresh test VM.

`app/README.md` outline:

1. Prerequisites (Go 1.22+, microsoft/go, PostgreSQL 15+, goose, sqlc, specter, oapi-codegen)
2. `make build` and `make build-fips`
3. Local development: `docker-compose up postgres`, `make migrate`, `make run`
4. Running tests: `make test`, `make spec`
5. Building packages: `make rpm`, `make deb`
6. Installing on a test VM
7. The 19-step Definition of Done as a runnable checklist

Tag the commit `stage-0-complete`.

---

## Risks and how Stage 0 surfaces them

| Risk | How Stage 0 catches it |
|---|---|
| oapi-codegen output incompatible with chi middleware | First endpoint (Day 5) wires both together |
| sqlc + pgx pool semantics surprise | Day 3 forces real pool usage |
| microsoft/go FIPS doesn't build cleanly | Day 12 attempts the build |
| systemd User= permission breaks `/etc/openwatch/` reads | Day 11 RPM install + start |
| TLS cert hot-reload races under load | Day 4 + manual test |
| Idempotency middleware leaks across requests | Day 6 replay test |
| Specter ingest doesn't accept Go test JSON shape | Day 10 ingest test |
| oapi-codegen + Go module path conflicts | Day 1 scaffold |
| TOML config parser doesn't handle env-var override layering | Day 2 |
| RPM postinstall scripts break on CS9 vs Ubuntu | Day 11 cross-build |
| Policy `atomic.Pointer[State]` swap leaks readers | Day 9 reload test under concurrent eval |
| Policy signature verify pulls in unexpected dependency | Day 9 reuse of license `crypto/ed25519` |
| OpenAPI validator rejects valid x-required-permission shape | Day 8 codegen + validator together |
| Built-in role wildcard expansion drifts from runtime check | Day 8 codegen-time expansion enforced; spec test verifies |

If any of these blocks Stage 0, the rebuild is paused while we resolve. **Don't proceed to Stage 2 with unresolved Stage-0 blockers.**

---

## What "done" unlocks

Stage 0 done means:

1. Stage 1 (usage audit) can proceed in parallel with no dependency.
2. Stage 2 (vertical slices) has a known-working stack to build on.
3. Every architectural decision in `app/docs/openwatch_roadmap.md` is empirically validated, not just locked-on-paper.
4. A test VM with the binary running becomes the reference deployment for all subsequent work.

---

## What it explicitly does NOT unlock

- A demo to customers. There is no business value in Stage 0.
- A pull-the-team-in moment. This is one developer, one focused week, no broader ceremony.
- Frontend or Kensa work. Both are blocked on Stage 2 slices.

---

## Commit cadence

Commit at the end of each numbered day. Tag `stage-0-day-N`. If a day's work fails, roll back to the prior tag and try again — don't accumulate broken intermediate states.

The final tag is `stage-0-complete`. That tag is the start point for Stage 2 Slice A.

---

## When to ask for help vs push through

**Push through:**
- Compiler/linker errors (read the error, fix it)
- Library API confusion (read the docs, fix it)
- Local test failures (debug them)

**Ask:**
- An architectural decision in the roadmap turns out to be wrong (e.g., microsoft/go fundamentally doesn't link the way we assumed). Don't quietly pivot — surface the conflict, decide explicitly.
- Something that looks like a Stage 0 task turns into a feature decision (e.g., you discover the audit envelope shape doesn't match a customer requirement). Don't over-design — note it for Stage 1 triage.
- Estimated 1 day's work is heading into 3. Surface the blocker; reset scope or get help.

---

## After Stage 0

`app/docs/stage_2_slices.md` will define Slice A (auth + add a host), Slice B (run a Kensa scan, view findings), Slice C (query historical posture). Each slice is full-stack: API + frontend + audit + spec + tests, target ≤2 weeks.

Stage 0 is the foundation those slices build on. Don't skip it. Don't rush it. Don't add features to it.
