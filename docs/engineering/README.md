# OpenWatch — Go Rebuild

This directory is the working tree for the from-scratch OpenWatch rebuild in
Go. The existing Python backend lives in `../backend/` and remains in
production until the rebuild is ready to take over.

**Status:** Stage 0 (walking skeleton) **complete**. 18/18 specs at 100% under `specter coverage --strict`. 19-step Definition of Done passes end-to-end (see `internal/server/api_signoff_test.go`).

> **What this means:** The toolchain is proven — every Stage-0 foundation (config layering, migrations, HTTPS + cert hot-reload + correlation propagation, audit, idempotency, license validation, RBAC, policy framework, queue, in-process worker, native RPM + DEB packaging, FIPS 140-3 build) is wired end-to-end and tested. **It is not a working compliance scanner yet** — that's Stage 2 (slice A: auth + add host; slice B: Kensa scan; slice C: historical posture).

---

## Design references

All design work is in `docs/`. Read these before changing anything:

| Topic | File |
|-------|------|
| Vision, goals, decisions | [`docs/openwatch_roadmap.md`](docs/openwatch_roadmap.md) |
| Stage 0 plan (current) | [`docs/stage_0_walking_skeleton.md`](docs/stage_0_walking_skeleton.md) |
| Stage 1 audit plan | [`docs/stage_1_usage_audit.md`](docs/stage_1_usage_audit.md) |
| API design principles | [`docs/api_design_principles.md`](docs/api_design_principles.md) |
| Audit event taxonomy | [`docs/audit_event_taxonomy.md`](docs/audit_event_taxonomy.md) |
| Licensing foundation | [`docs/licensing_foundation.md`](docs/licensing_foundation.md) |
| Policies-as-data | [`docs/policies_as_data.md`](docs/policies_as_data.md) |
| RBAC registry | [`docs/rbac_registry.md`](docs/rbac_registry.md) |
| Correlation ID propagation | [`docs/correlation_id_propagation.md`](docs/correlation_id_propagation.md) |

Registries (source of truth for codegen):

| Registry | File |
|----------|------|
| Audit events | [`audit/events.yaml`](audit/events.yaml) |
| Error codes | [`api/error_codes.yaml`](api/error_codes.yaml) |
| License features | [`license/features.yaml`](license/features.yaml) |
| Permissions + built-in roles | [`auth/permissions.yaml`](auth/permissions.yaml) |

OpenAPI domain specs in [`api/`](api/) (4 full-fidelity + 11 skeletons + meta `openapi.yaml`).

---

## Prerequisites

- Go 1.25+ (auto-downloaded by toolchain if local Go is older; raised from
  the originally-planned 1.22+ floor when `pressly/goose v3.27` required 1.25)
- `make`, `git`

Optional (lands in later days):

- `golangci-lint` (Day 1: lint target works without it, just skips)
- `oapi-codegen`, `sqlc`, `redocly` (Day 5: codegen — until then, the
  audit queries are hand-written but match what sqlc would produce)
- A running PostgreSQL 15+ for `migrate` and integration tests; integration
  tests in `internal/db` skip if `OPENWATCH_TEST_DSN` is unset
- `microsoft/go` (Day 12: FIPS build)

---

## Quick start

```bash
# From this directory (app/)
make help          # list all targets
make version       # show what version metadata will be injected
make build         # produces dist/openwatch
make test          # run all Go tests

./dist/openwatch --version
./dist/openwatch check-config                                       # uses defaults (silent if /etc/openwatch/openwatch.toml missing)
./dist/openwatch --config configs/openwatch.toml.example check-config
OPENWATCH_SERVER_LISTEN=0.0.0.0:9443 ./dist/openwatch check-config  # env override
./dist/openwatch --listen 0.0.0.0:8000 check-config                  # flag override (wins over env)
```

Config layering (highest precedence first):

1. CLI flags (`--listen`, `--log-level`)
2. Env vars (`OPENWATCH_<SECTION>_<KEY>`)
3. TOML file (`--config`, default `/etc/openwatch/openwatch.toml`)
4. Built-in defaults

Subcommands beyond `check-config` are stubbed until their day arrives:
`serve` (Day 4), `migrate` (Day 3).

---

## Layout

```
app/
├── api/                # OpenAPI specs and error_codes.yaml registry
├── audit/              # events.yaml registry
├── auth/               # permissions.yaml registry (RBAC)
├── cmd/                # binaries (entry points)
│   └── openwatch/      # the main daemon
├── dist/               # build output (gitignored)
├── docs/               # design docs (the spec)
├── internal/           # Go packages, not importable outside this module
│   ├── config/         # (placeholder, Day 2)
│   ├── server/         # (placeholder, Day 4)
│   └── version/        # build-time metadata
├── license/            # features.yaml registry
├── .golangci.yml
├── .gitignore
├── Makefile
├── README.md           # this file
├── go.mod
└── go.sum              # (populated by `go mod tidy`)
```

Foundation packages (`internal/audit/`, `internal/auth/`, `internal/correlation/`,
`internal/errors/`, `internal/license/`, `internal/log/`, `internal/policy/`,
`internal/queue/`, `internal/httpclient/`) come online as their Stage 0 days arrive.

---

## Stage 0 progress

See [`docs/stage_0_walking_skeleton.md`](docs/stage_0_walking_skeleton.md) for
the 13-day plan and the 19-step Definition of Done.

| Day | Topic | Status |
|----:|-------|--------|
| 1   | Repository scaffold                                       | complete |
| 2   | Config + flags + TOML                                     | complete |
| 3   | PostgreSQL + goose migrations                             | complete |
| 4   | HTTP server + chi + TLS + correlation propagation         | complete |
| 5a  | Audit foundation (migration + codegen + emit/writer/redact) | complete |
| 5b  | OpenAPI codegen + endpoints (/health, :echo, /audit/events) | complete |
| 6   | Idempotency middleware (folded into Day 5b)               | complete |
| 7   | Licensing foundation (JWT EdDSA + RequireFeature + owlicgen) | complete |
| 8   | RBAC registry                                             | complete |
| 9   | Policies-as-data + queue correlation helpers              | complete |
| 10  | Specter spec + AC coverage                                | complete (18/18 specs at 100% under strict mode) |
| 11  | Native packaging (RPM + DEB)                              | complete |
| 12  | FIPS build (Go 1.25 native `GOFIPS140`)                   | complete |
| 13  | Documentation, demo, sign-off                             | complete |

---

## Developer walkthrough (from a fresh clone)

This section walks a new developer through every Stage-0 command. Run from `app/`.

### 1. Build

```bash
make build           # produces dist/openwatch (non-FIPS)
make build-fips      # produces dist/openwatch-fips (Go 1.25 native FIPS 140-3)

./dist/openwatch --version
./dist/openwatch-fips --version    # → "fips: true"
```

### 2. Local development against PostgreSQL

The integration tests require a running PostgreSQL. Easiest setup uses
docker / podman:

```bash
docker run -d --name openwatch-pg \
    -e POSTGRES_USER=openwatch \
    -e POSTGRES_PASSWORD=openwatch \
    -e POSTGRES_DB=openwatch \
    -p 5432:5432 \
    postgres:16-alpine

export OPENWATCH_TEST_DSN="postgres://openwatch:openwatch@127.0.0.1:5432/openwatch?sslmode=disable"

./dist/openwatch migrate    # apply all goose migrations
./dist/openwatch check-config
```

To run the daemon locally with a self-signed cert:

```bash
mkdir -p /tmp/ow-tls
bash packaging/common/gen-demo-cert.sh /tmp/ow-tls

OPENWATCH_DATABASE_DSN="$OPENWATCH_TEST_DSN" \
OPENWATCH_SERVER_TLS_CERT=/tmp/ow-tls/cert.pem \
OPENWATCH_SERVER_TLS_KEY=/tmp/ow-tls/key.pem \
./dist/openwatch --listen 127.0.0.1:8443 serve
```

In another terminal, exercise the surface:

```bash
curl -k https://127.0.0.1:8443/api/v1/health
curl -k 'https://127.0.0.1:8443/api/v1/audit/events?limit=5'
curl -k https://127.0.0.1:8443/api/v1/license
curl -k https://127.0.0.1:8443/api/v1/auth/permissions:registry | jq .
```

### 3. Running tests

```bash
make test                     # unit + integration; integration tests skip without DSN
specter sync                  # spec validation + coverage gate
```

### 3a. Quality + security gates (run before pushing)

```bash
make check                    # vet → lint → vuln → test-race, chained
```

Or individually:

```bash
make vet                      # go vet ./...
make lint                     # golangci-lint (staticcheck + gosec + govet + ...)
make vuln                     # govulncheck ./... (stdlib + deps; auto-installs)
make test-race                # go test -race -p 1 ./...
```

The same gates run in CI via `.github/workflows/go-ci.yml` on every PR touching `app/**`.

For strict-mode AC coverage (requires the test pipeline to ingest results):

```bash
export OPENWATCH_TEST_DSN="postgres://openwatch:openwatch@127.0.0.1:5432/openwatch?sslmode=disable"
go test -json -p 1 ./... > /tmp/go-test.json
specter ingest --go-test /tmp/go-test.json
specter coverage --strict     # → "18 specs: 18 passing, 0 failing"
```

### 4. Building packages

```bash
make rpm    # → dist/openwatch-<ver>-1.x86_64.rpm  (needs rpmbuild)
make deb    # → dist/openwatch_<ver>_amd64.deb     (needs dpkg-deb)
```

Install on a target VM via [`docs/install_guide.md`](docs/install_guide.md).

### 5. Code generation

When you edit any registry, regenerate the typed Go output:

```bash
make generate-audit     # audit/events.yaml      → internal/audit/events.gen.go
make generate-api       # api/openapi.yaml       → internal/server/api/server.gen.go
go run scripts/gen-rbac.go              # auth/permissions.yaml  → internal/auth/{permissions,roles}.gen.go
go run scripts/gen-license-features.go  # license/features.yaml  → internal/license/features.gen.go
```

CI fails if a generated file is out of sync with its source registry.

---

## The 19-step Definition of Done — runnable checklist

Each step below has an enforcing test in the spec registry. Steps that
the operator must run on a VM (file-watch cert reload, full binary
restart) are flagged.

| # | Step | Spec AC / test |
|---|------|----------------|
| 1 | `git clone` + walk-through this README | covered by this section |
| 2 | `make build` produces `dist/openwatch` | `release-package-build/AC-13` |
| 3 | `make build-fips` produces `dist/openwatch-fips` with `fips: true` | `release-fips-build/AC-01`, `AC-02` |
| 4 | `make rpm` + `make deb` produce installable packages | `release-package-build/AC-01`, `AC-02` |
| 5 | Package installs to `/etc/systemd/system/openwatch.service` + friends | `release-package-build/AC-04`, `AC-06` |
| 6 | `systemctl start openwatch` + `journalctl -u openwatch` | operator (install guide) |
| 7 | GET `/api/v1/health` → 200 + canonical body | `release-stage-0-signoff/AC-01` |
| 8 | POST `:echo` with `Idempotency-Key` + `X-Correlation-Id` → 200 echoed | `release-stage-0-signoff/AC-02` |
| 9 | GET `/audit/events` includes the row from step 8 | `release-stage-0-signoff/AC-03` |
| 10 | Replay step 8 → cached response, only one audit row | `release-stage-0-signoff/AC-04` |
| 11 | `viewer` permissions include `host:read`, exclude `host:write` | `release-stage-0-signoff/AC-05` |
| 12 | `viewer` + POST `:require-host-write` → 403 + audit row | `release-stage-0-signoff/AC-06` |
| 13 | `security_admin` + no license + `:require-remediation-execute` → 402 | `release-stage-0-signoff/AC-07` |
| 14 | POST `:evaluate-alert` `{score:65}` → `outcome=high`, version `0.0.0` | `release-stage-0-signoff/AC-08` |
| 15 | Drop signed `alert_thresholds.yaml` v1.0.0; reload; reflect new thresholds | `release-stage-0-signoff/AC-09` |
| 16 | POST `:enqueue-test-job` with `X-Correlation-Id: req-end2end-001`; worker emits matching audit event | `release-stage-0-signoff/AC-10` |
| 17 | `specter sync` → 100% AC coverage on every Active spec | `release-stage-0-signoff/AC-11` |
| 18 | Edit cert on disk; new TLS handshakes pick up the new cert | `system-http-server/AC-08` + `AC-09`; full file-watch is operator |
| 19 | Stop / restart service — DB state survives, audit row persists | `system-db/AC-12` (pool reopen); binary restart is operator |

Run all 19 in CI by running `go test ./...` after `make rpm && make deb && make build-fips` — the test suite asserts steps 7-17 against a live server; steps 2-5 are exercised by the packaging build itself; steps 1, 6, 18, 19 are the operator's gate.
