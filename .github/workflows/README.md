# GitHub Actions workflows

This directory holds the CI/CD workflows for OpenWatch. OpenWatch is a single Go
module at the repo root (`github.com/Hanalyx/openwatch`, Go 1.26) that builds one
binary (`/usr/bin/openwatch`) serving the REST API and the embedded React UI over
HTTPS on port `8443`. There is no separate web tier, no container runtime in
production, and no Python/Docker-Compose stack. That was archived out of the repo
on 2026-06-05.

The workflows below reflect that. Each section describes one file that actually
exists in this directory; verify details against the workflow file itself before
relying on them.

## Workflow index

| File | Trigger | Purpose |
|------|---------|---------|
| `go-ci.yml` | push/PR to `main`, `v*` tags | Quality and security gates: vet, lint, govulncheck, race tests against PostgreSQL, spec coverage; a shorter documentation path for documentation-only changes; the `Full test evidence` job release gates read |
| `codeql.yml` | PR to `main`/`develop`, `v*` tag, daily, manual | CodeQL static analysis (JavaScript/TypeScript) |
| `release.yml` | `v*` tags, manual | Build RPM/DEB (amd64 + arm64), SBOMs, signing, publish a GitHub Release |
| `package-smoke.yml` | `v*` tags, packaging PRs, manual | Install built packages on RPM/DEB distros and smoke-test |
| `branch-naming.yml` | PR to `main` | Enforce the branch-prefix policy |
| `issue-management.yml` | issues, PRs, comments | Auto-assign, auto-label, size-label, stale handling, welcome messages |
| `automated-triage.yml` | daily, manual | Triage Dependabot/CodeQL alerts |
| `claude-code-alerts.yml` | PRs, weekly, manual | Assist with security alert triage |

Dependency updates are configured in `.github/dependabot.yml` (a config file, not a
workflow). The branch-prefix policy is documented in `.github/BRANCH_MANAGEMENT.md`.

## Core CI: `go-ci.yml`

The pre-merge gate and the source of release test evidence. It runs on every push
and pull request to `main` and on every pushed `v*` tag. The required status check
is the aggregate job **Quality + security gates**, which runs on every event so the
check is always present.

The **Detect Go-relevant changes** job picks one of two paths. A release tag always
takes the full path. Otherwise a change to code, specs, packaging, scripts,
tooling or CI takes the full path, and any other change takes the documentation
path.

**Full path.** Two jobs run in parallel, each with its own `postgres:16-alpine`
service container:

- **Vet, lint, vuln, Specter gate and race tests (all but internal/server)**:
  - `go mod tidy` followed by a `git diff` check (fails if `go.mod`/`go.sum`
    drifted), and the generated API stubs checked against `api/openapi.yaml`
  - `make vet`
  - `make lint` (golangci-lint, built from source to match the runner toolchain)
  - `make vuln` (govulncheck)
  - `make license-bundle` and the Specter gate
  - `go test -race -json` for every package except `internal/server`, under a
    900 s per-package budget
  - frontend `vitest` (JUnit), and the generated frontend API types checked
- **Race tests (internal/server)**: `go test -race -json` for `internal/server`
  alone, under its own 1800 s budget.

Every package runs exactly once, and the database-heavy server suite does not
share a PostgreSQL service with its siblings. The aggregate then runs the Python
checks under `scripts/`, checks the test streams, and runs `specter ingest` and
`specter sync` to enforce coverage thresholds. **Full test evidence** succeeds
only when that whole pipeline ran and passed. The release gates read it, not the
aggregate, because the aggregate also passes on the documentation path.

**Documentation path.** **Documentation validation (packaging tests, partial)**
runs `go test -race` on `packaging/tests`, without native package builds or a
database. The aggregate runs the Python checks, checks that documentation test
stream and runs a partial Specter ingest. It fails if any of these fails. The full
Go suites, Vitest and `specter sync` do not run, and **Full test evidence** is
skipped.

A separate **Doc Style** job checks the tracked documents on every run.

The DSN is supplied via `OPENWATCH_TEST_DSN`; module resolution is pinned read-only
with `GOFLAGS=-mod=readonly`. See `specs/release/ci-gates.spec.yaml`.

## Security analysis: `codeql.yml`

Runs CodeQL on pull requests to `main`/`develop`, daily on the default branch, on
`v*` tag pushes, and on manual dispatch. It does not run on pushes to `main`. The
tag scan exists for release gate Q2, which needs a passing
`Analyze Code (javascript)` check run on the tagged commit. The language matrix is
`javascript` only. The Python tree was archived, so TypeScript
and JavaScript cover the `frontend/` SPA. Results land in the GitHub Security tab.

Go static analysis is handled by `make lint` and `make vuln` inside `go-ci.yml`
(staticcheck, gosec, govulncheck), not by CodeQL.

## Release: `release.yml`

Triggers on a `v*` tag or manual dispatch. It builds the four native packages, RPM
and DEB for amd64 and arm64, via `make packages`. Each package contains the
complete API+UI binary (the SPA is embedded with `go:embed`); there is no container
image to publish.

The workflow then:

- GPG-signs the RPMs (when `GPG_PRIVATE_KEY` is configured)
- generates a CycloneDX 1.5 SBOM per artifact with `syft`
- writes `SHA256SUMS`, a detached GPG signature (`SHA256SUMS.asc`), and a `cosign`
  signature (`SHA256SUMS.cosign.sig`) when the respective keys are present
- publishes a GitHub Release with the packages, checksums, SBOMs, and `KEYS`

Distribution is via GitHub Releases. Operators install with
`sudo dnf install ./openwatch-*.rpm` or `sudo apt install ./openwatch_*.deb`. A tag
with a pre-release suffix (for example `-rc.5`) is marked as a pre-release; a bare
`vX.Y.Z` builds a draft that a separate publish step releases after verification
(`docs/runbooks/RELEASING.md`, Stage 4). The current GA line is 0.7.1 (Eyrie);
0.8.0 is in release candidates. See
`specs/system/supply-chain.spec.yaml`, `specs/release/package-build.spec.yaml`, and
`docs/runbooks/RELEASING.md`.

## Package smoke test: `package-smoke.yml`

Runs on `v*` tags, on PRs that touch `packaging/`, and on demand. It builds the
packages, then installs them in containers for each target distro (`rockylinux:9`,
`almalinux:9`, `fedora:41`, `oraclelinux:9`, `ubuntu:24.04`, `debian:12`) and
verifies that:

- dependencies resolve and the package installs cleanly
- `/usr/bin/openwatch`, `/etc/openwatch/openwatch.toml`,
  `/etc/systemd/system/openwatch.service`, and `/etc/openwatch/tls/cert.pem` land
- the `openwatch` system user is created
- `openwatch --version` and `openwatch check-config` run

A third job, **Package upgrade (`rpm -U` auto-migrate)**, covers the path the
per-distro `smoke` job (a fresh install) does not: in a `rockylinux:9` container it
builds an old + new RPM, installs the old one, stands up PostgreSQL, rolls the schema
back one migration, then `rpm -U`s the new package and asserts the `%post` scriptlet
migrates the DB to head, takes a pre-upgrade backup, and stop/starts the service. It
runs via `packaging/tests/run-upgrade-container-test.sh` (uses `--network host` and a
throwaway Postgres on port `55432`).

The smoke matrix is amd64 only (GitHub runners are amd64); arm64 correctness is
covered by the cross-build in `release.yml`. Service start and functional E2E against
a real fleet remain a manual RC step (see `docs/runbooks/RELEASING.md`).

## Repository automation

- **`branch-naming.yml`**: fails a PR whose head branch does not start with an
  allowed prefix (`feat/`, `fix/`, `chore/`, `docs/`, `refactor/`, `perf/`, `test/`,
  `build/`, `ci/`, `revert/`, `release/`, `dependabot/`). See
  `.github/BRANCH_MANAGEMENT.md`.
- **`issue-management.yml`**: auto-assigns issues by label, auto-labels PRs by
  changed paths, applies size labels, marks stale issues/PRs, and welcomes
  first-time contributors.
- **`automated-triage.yml`**: daily (and on-demand) triage of Dependabot and CodeQL
  alerts.
- **`claude-code-alerts.yml`**: assists with security alert triage on PRs and on a
  weekly schedule.

## Required secrets

| Secret | Used by | Purpose |
|--------|---------|---------|
| `GITHUB_TOKEN` | issue/PR automation | Provided automatically by GitHub Actions |
| `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` | `release.yml` | Sign RPMs and the checksum manifest |
| `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD` | `release.yml` | Cosign signature over the checksum manifest |

On a tag-push release, GPG signing is required: `release.yml` fails closed and refuses
to publish unsigned if `GPG_PRIVATE_KEY` is absent. The cosign layer is optional and
skips if its key is absent. An unsigned build is only possible via a `workflow_dispatch`
trial run (never a tag push).

## Reproducing CI locally

The gates in `go-ci.yml` map to Makefile targets you can run from the repo root:

```bash
make vet           # go vet
make lint          # golangci-lint (staticcheck, gosec, ...)
make vuln          # govulncheck
make test-race     # race detector + integration suite (needs PostgreSQL)
make packages      # build RPM + DEB for amd64 and arm64
```

`make test-race` and the spec-coverage steps need a PostgreSQL instance reachable via
`OPENWATCH_TEST_DSN` (the database name must end in `_test`).

## Related documentation

- Install and configuration: `docs/guides/INSTALLATION.md`,
  `docs/guides/PRODUCTION_DEPLOYMENT.md`, `docs/guides/ENVIRONMENT_REFERENCE.md`
- Branch policy: `.github/BRANCH_MANAGEMENT.md`
- Release procedure: `docs/runbooks/RELEASING.md`
- CI gate spec: `specs/release/ci-gates.spec.yaml`
- Supply-chain spec: `specs/system/supply-chain.spec.yaml`
- Kensa boundary: Context Plane record `projects/kensa/KENSA_OPENWATCH_BOUNDARY`
  (the repository copy is a local-only mirror)
