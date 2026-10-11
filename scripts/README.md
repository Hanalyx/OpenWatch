# OpenWatch Scripts

Developer and CI helper scripts for OpenWatch (single Go binary
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

## Release preparation

| Script | Purpose |
|--------|---------|
| `evidence_capture.py` | Capture a command's raw stdout, stderr and exit status as release evidence. Each capture is bound to the candidate, the host and the invocation, sealed with SHA256SUMS, and verified again after transfer from a fleet host. Secrets go through named environment variables only. Spec: `release-evidence-capture`. Run `python3 -S scripts/evidence_capture.py --help` for usage. |
| `release_prep.py` | Maintained release-preparation steps built on `evidence_capture.py`. `f2` runs the F2 staged-remediation check on one fleet host in three phases (preflight, staged, after). It prompts rollback only after the staged capture verifies, then builds a packet with the captain's fields left blank. Spec: `release-preparation`. Skill: `.claude/skills/release-prep/SKILL.md`. |
| `release_tag.py` | Cut a release tag on an explicit candidate commit (RELEASING.md Stage 2; CP `bugs/OW-118`). It takes the full SHA and the release key's fingerprint. A dry run checks the candidate's ancestry, version agreement, that the tag exists nowhere, and the key against `security/KEYS`, then stops. `--sign` signs with that key and verifies the tag; `--push` pushes that one tag and checks origin. Spec: `release-tagging`. |
| `release_assets.py` | Verify a release's assets against the candidate commit, read-only. It checks what gates A1 and A2 do not: each binary's Go toolchain, revision, version and modules, `govulncheck`, the RPM signatures, the shipped notices and the SBOMs. Every expectation comes from the commit, including the asset inventory in `release/assets.toml`, and every command is captured. Spec: `release-asset-verification`. |
| `release_compat.py` | Run the candidate commit's own engine and corpus pairing test (`TestUpgrade_EngineCorpusPairingInContainers`) in local, disposable containers. The new pair is the release's own packages and the old pair an older release's, both verified against their signed `SHA256SUMS` first. A skipped or incomplete run never passes. Spec: `release-compat-runs`. |
| `release_upgrade.py` | Run `UPGRADE_PROCEDURE.md` Steps 1 to 8 on one OpenWatch server in five gated phases (plan, backup, install, verify, rules). Each runs a maintained script from `release/prep/upgrade/` under the capture library. Nothing changes the host without `--execute`, and nothing changes a host whose machine-id or hostname differs from the verified preflight's. It never starts the service by hand, rolls back or reboots, and Step 8 must end in `MATCH`. Spec: `release-upgrade-steps`. |

> Note: a few of these helpers are written in Python purely as CI/dev tooling
> (commit-message linting, spec validation, CodeQL/risk automation). They are
> not part of the OpenWatch runtime, which is entirely Go.
