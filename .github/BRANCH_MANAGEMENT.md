# Branch Management Policy

This document outlines branch strategy, naming conventions, and automated
workflows for the OpenWatch repository. The repo is a single Go module at the
root (`github.com/Hanalyx/openwatch`, go 1.26) with an embedded React frontend:

| Subtree | Stack | CI workflow |
|---------|-------|-------------|
| `cmd/`, `internal/`, `api/` | Go 1.26 backend + pgxpool + specter | `go-ci.yml` (job: Quality + security gates) |
| `frontend/` | React 19 + TypeScript + Vite + Vitest | `go-ci.yml` (Vitest results ingested by specter) |
| `packaging/` | RPM / DEB native packages | `release.yml` |

`go-ci.yml` is the single gating pipeline. It builds and tests the Go module,
runs the frontend Vitest suite for spec coverage, and gates the
`Quality + security gates` check.

## Branch naming

The repository follows [Conventional Commits](https://www.conventionalcommits.org/)
prefixes for branches as well as commits. The commitlint config
(`.commitlintrc.json`) enforces this on every commit.

### Allowed prefixes

| Prefix | When | Example |
|--------|------|---------|
| `feat/` | New feature or capability | `feat/host-detail-redesign` |
| `fix/` | Bug fix | `fix/auth-token-localstorage-key` |
| `chore/` | Maintenance, refactor, infra | `chore/bump-postgres-16.4` |
| `docs/` | Documentation only | `docs/kensa-integration-guide` |
| `refactor/` | Internal restructure, no behavior change | `refactor/extract-scan-service` |
| `perf/` | Performance change | `perf/transactions-query-index` |
| `test/` | Test-only changes | `test/regression-mfa-flow` |
| `build/`, `ci/` | Build system, CI config | `ci/add-go-ci-workflow` |
| `revert/` | Reverting a prior change | `revert/redux-removal` |

### Slice-based naming for the Go rebuild

Spec-driven work follows the slice naming convention:

```
feat/slice-<letter>-<sub-id>-<short-name>
```

Examples (from Slice B):
- `feat/slice-b-b1a-scheduler`
- `feat/slice-b-b3a-event-bus`
- `feat/slice-b-b4-fleet-rollup`

Each slice PR pairs a spec change with the code that implements it.
See the behavioral specs under `specs/` and `specter.yaml`.

### Dependabot branches

Dependabot creates branches in the form `dependabot/<ecosystem>/<scope>-<version>`.
They are not subject to the prefixes above. See `.github/dependabot.yml`.

### Release branches

`release/<version>` — branch from `main`, only bug fixes and doc updates
allowed, tag on merge.

## Main branch protection

The `main` branch is the only long-lived branch (no `develop`). It is
protected with:

- **Required status checks** (strict, branch must be up-to-date):
  - `Quality + security gates` — Go pipeline (`go-ci.yml`)
- **Required reviews**: 0 approvals (small team), but enforced via the
  `enforce_admins` flag so even admins go through PRs
- **Dismiss stale reviews** on new commits
- **No force pushes** to `main`
- **No deletion** of `main`

If you need to add a check (e.g., when a new pipeline lands), update the
required-status-checks list via the GitHub UI or `gh api`. Do not remove
checks to work around failing CI — fix the underlying issue.

## Automated branch management

### Dependabot configuration

`.github/dependabot.yml` covers three ecosystems today:

- `gomod` (`/`) — Go module deps, weekly Monday (patch/minor groups). Every
  accepted update must keep the depguard allowlist in `.golangci.yml` in sync.
- `npm` (`/frontend`) — JS/TS deps, weekly Monday, plus a daily security-only lane
- `github-actions` (`/`) — workflow action versions

### Auto-merge eligibility

Auto-merge respects branch protection — it queues, then merges when checks
pass. Set via `gh pr merge <N> --squash --auto`.

**Generally eligible**:
- Patch version dependency updates with green CI
- Documentation-only PRs (`docs/`)
- Test-only PRs (`test/`)
- Conventional-commit-compliant PRs whose CI is green

**Requires manual review** (do not auto-merge):
- Major version updates
- Minor updates that touch security configuration, auth flow, or
  cryptography
- Schema migrations (`internal/db/migrations/`)
- Anything changing required-status-checks or branch protection
- Anything touching CODEOWNERS, GitHub Actions permissions, or secrets

### Branch cleanup

Merged feature branches are deleted automatically by GitHub's "Automatically
delete head branches" repo setting. If a branch persists after merge,
delete it manually:

```bash
git push origin --delete feat/foo-completed
git remote prune origin
```

## Local branch operations

### Common operations

```bash
# Create a feature branch from current main
git fetch origin
git checkout -b feat/short-description origin/main

# Update branch with latest main (rebase preferred — keeps linear history)
git fetch origin
git rebase origin/main

# Clean up local branches whose remote tracking ref is gone
git remote prune origin
git branch -vv | grep ': gone]' | awk '{print $1}' | xargs -r git branch -d
```

### Force-push policy

Force pushes are allowed on feature branches but should use
`--force-with-lease` so a stale local checkout never overwrites someone
else's work:

```bash
git push --force-with-lease origin feat/your-branch
```

`--force` and `--force-with-lease` are **never** allowed on `main`.

## Emergency procedures

### Pre-merge: undo work on a feature branch

```bash
# Discard the last local commit but keep changes staged
git reset --soft HEAD~1

# Discard the last commit AND its changes
git reset --hard HEAD~1   # only ever on your own feature branch

# Force-push the rewrite
git push --force-with-lease origin <branch>
```

### Post-merge: roll back a bad change on main

If a bad PR merged to `main`, **revert via a new PR**. Do not reset or
force-push `main`:

```bash
git fetch origin
git checkout -b revert/bad-pr-NNN origin/main
git revert -m 1 <merge-commit-sha>   # -m 1 for squash/merge commits
git push -u origin revert/bad-pr-NNN
gh pr create --title "revert: <subject of bad PR>" --base main
```

The revert PR is subject to the same required checks as any other.

### Recover an accidentally deleted branch

```bash
git reflog                              # find the tip commit of the lost branch
git checkout -b recovered-branch <sha>  # recreate from that commit
git push -u origin recovered-branch
```

### What we do NOT do

- We do **not** disable branch protection to land a "must-go" change.
  If protection blocks a legitimate merge, fix the failing check or
  update the protection rules through the GitHub UI as a deliberate,
  reviewed change — not a transient bypass.
- We do **not** push directly to `main`. All changes go through PRs.
- We do **not** use `--admin` to bypass required status checks.
- We do **not** skip pre-commit hooks (`--no-verify`) or commit signing
  to land a change. If a hook fails, the underlying issue is the work.

These are durable rules; treat them as load-bearing.

## Quality gates

### Go (backend)

Enforced by the root `Makefile` and `go-ci.yml`. All of these must pass for the
single required check (`Quality + security gates`) to go green:

- `make vet` — `go vet ./...`
- `make lint` — `golangci-lint` (vet, ineffassign, staticcheck, unused,
  gofmt, goimports, misspell, errcheck, revive, gosec, forbidigo)
- `make vuln` — `govulncheck ./...`
- `make test-race` — full test suite under `-race`, against a Postgres
  service container (DSN from `OPENWATCH_TEST_DSN`)
- frontend Vitest — `go-ci.yml` runs the `frontend/` Vitest suite and feeds the
  JUnit results into specter so `specs/frontend/` ACs report real coverage
- `specter sync --tests '**/*'` — spec validation + 100% AC coverage gate for
  every `status: approved` spec under `specs/`

`forbidigo` enforces the foundation-doc contracts: typed RBAC constants,
correlation-id propagation, queue-only INSERTs into `job_queue`. See
`.golangci.yml` for the full rule list.

### Spec-driven development gates

For specs marked `status: approved`:

- Every `C-NN` constraint must be referenced by at least one `AC-N`
- Every `AC-N` must have a corresponding test annotated with
  `// @ac AC-N` and a `// @spec <name>` file header (Go tests, plus
  `frontend/` Vitest tests for `specs/frontend/`)
- 100% coverage on approved specs is gated by `specter sync` in `go-ci.yml`

If you change scope, update the spec AND the source code AND the tests in
the same PR. Spec drift is caught at CI, not in review.

## Review requirements

Beyond automated checks:

- **Code review**: at least one approving review for non-trivial PRs.
  Smaller chore/docs PRs may self-merge by the author after CI passes,
  at the author's discretion.
- **Security review**: required for changes touching auth, authorization,
  cryptography, secrets handling, or session management.
- **Schema review**: required for new `internal/db/migrations/*.sql`. Confirm
  forward-only, idempotent, and reversible where reasonable.
- **Documentation**: API changes start in `api/openapi.yaml` (the contract
  source of truth; run `make generate-api`) and require corresponding updates
  to the relevant `specs/api/` spec or `docs/` page.

## Metrics

Track via GitHub Insights and the weekly `BACKLOG.md` sweep:

- Average PR lifetime (target < 3 days)
- Time to first review (target < 1 day)
- CI failure rate (target < 5%)
- Dependabot auto-merge success rate
- Open PRs older than 14 days (review weekly)

## Troubleshooting

**CI failing on a feature branch with errors unrelated to your changes** —
likely a flaky test or a stdlib CVE bump landed on main. Rebase onto
latest main, re-run failed jobs, and check `go-ci.yml` Go version against
the latest `govulncheck` advisory list.

**Dependabot PR has merge conflicts** — close and let Dependabot recreate.
For repeated conflicts on the same dep, manually rebase locally and
force-push.

**Auto-merge queued but never fires** — the most common cause is
required-status-check drift (a check name was renamed but protection
still requires the old name). Fix the required-checks list to match the
workflow output, do not bypass protection.

**`mergeStateStatus: BLOCKED` despite green CI** — same root cause: a
required check is not reporting. Inspect via
`gh pr view <N> --json statusCheckRollup` and compare against branch
protection's `required_status_checks.contexts`.

## References

- [GitHub Flow](https://guides.github.com/introduction/flow/) — trunk-based workflow
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- `specter.yaml` and `specs/` — spec-driven development discipline
- `.golangci.yml` — Go linter configuration with drift-prevention rules
- `CLAUDE.md` — repository-wide AI-collaboration rules (also applies to humans)
