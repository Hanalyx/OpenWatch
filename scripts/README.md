# OpenWatch Scripts

Developer and CI helper scripts for the OpenWatch Go rebuild (single Go binary
serving the API + embedded UI, PostgreSQL-only). The legacy Python/FastAPI +
Docker-Compose helper scripts were removed in the GA cleanup; the Go quality
gate is `make check` (see the Makefile).

## Local development

| Script | Purpose |
|--------|---------|
| `openwatch.sh` | Local dev bootstrap: `{start\|stop\|restart\|status}` for the Go backend (HTTPS, :8443) and the Vite frontend (:5173). |
| `generate-certs.sh` | Generate self-signed TLS material for local dev. |

## Code generation (run via `make generate`)

| Script | Generates |
|--------|-----------|
| `gen-audit-events.go` | Audit event constants from the taxonomy. |
| `gen-license-features.go` | `internal/license/features.gen.go` from `licensing/features.yaml`. |
| `gen-rbac.go` | RBAC permission/role code from the registry. |

## Spec-driven development

| Script | Purpose |
|--------|---------|
| `validate-specs.py` | Validate `.spec.yaml` files against the schema. |
| `check-go-spec-coverage.sh` | Go spec-coverage check. |

## CI / quality automation

| Script | Purpose |
|--------|---------|
| `check-commit-message.py` | Validate commit messages against OpenWatch conventions. |
| `risk_assessment.py` | Security-automation risk scoring (invoked by GitHub workflows). |

> Note: a few of these helpers are written in Python purely as CI/dev tooling
> (commit-message linting, spec validation, CodeQL/risk automation). They are
> not part of the OpenWatch runtime, which is entirely Go.
