# Restructure plan: promote `app/` to the repo root

**Status:** DRAFT — not yet executed. Created 2026-06-05 on `chore/archive-python-to-owar`.
**Goal:** collapse the repo to a **single Go module at the root**
(`github.com/Hanalyx/openwatch`, go 1.26), eliminating two structural smells:

1. The active product lives in a subdirectory (`app/`) while the root is a
   secondary CLI module.
2. Two Go modules whose import paths collide on case —
   `github.com/hanalyx/openwatch` (root/owadm) vs `github.com/Hanalyx/openwatch` (app).

This is cheap relative to its appearance: **`app/`'s module path is already
`github.com/Hanalyx/openwatch`**, so promoting it to root needs **no import
rewrites inside `app/`**. Only owadm's 8 import sites change (and only if owadm is
kept). Verified: `app/` has **zero** dependency on the root owadm module.

---

## Pre-flight DECISION (blocker): what happens to owadm?

The root module is the `owadm` admin/container CLI (`cmd/owadm`, `internal/owadm`,
`internal/sdd`, `bin/`, `owadm`, `test-owadm`). It must be resolved before promotion
because it owns root `go.mod`, `Makefile`, `cmd/`, `internal/`, `scripts/`.

owadm's primary function is `owadm start|stop|status` → drives `docker-compose`.
That compose stack was the **Python deployment and is now archived**, so owadm's
main job is currently dead until/unless it is repurposed for the Go deployment.

| Option | What it means | Recommendation |
|---|---|---|
| **B1 — Archive owadm** | Move `cmd/owadm`, `internal/owadm`, `bin/`, `owadm`, `test-owadm`, root `go.mod/sum`, root `Makefile` to OWAR. Decide `internal/sdd/` separately (it's SDD tooling/plans, not owadm). | **Preferred** — owadm manages the archived stack; least code to carry. Re-introduce a Go-native deploy CLI later if needed. |
| **B2 — Fold owadm in** | Keep owadm under the unified module: `cmd/owadm`, `internal/owadm`, `internal/sdd` stay; rewrite the 8 `github.com/hanalyx/openwatch/...` imports to `github.com/Hanalyx/openwatch/...`; merge owadm's Makefile targets into the root Makefile. | Choose only if owadm is still actively used. |

`internal/sdd/` (plans, archaeology, reverse-specs) is **separable from owadm** —
it's SDD migration tooling. If the SDD workflow still references it, relocate it
(e.g. keep `internal/sdd/` under the unified module) regardless of the owadm choice.

---

## Name collisions to resolve (root vs `app/`)

Both trees contain these entries; promotion must merge or pick a winner for each:

| Entry | Root (owadm/meta) | `app/` (active) | Resolution |
|---|---|---|---|
| `go.mod` / `go.sum` | owadm module | **product module** | `app/` wins → becomes root module (B1). Merge if B2. |
| `Makefile` | owadm build | **product build** | `app/Makefile` wins (B1). Merge owadm targets if B2. |
| `cmd/` | `cmd/owadm` | `cmd/openwatch` | Union — keep both under root `cmd/` (rewrite owadm imports if B2). |
| `internal/` | `owadm`, `sdd` | 37 service pkgs | Union — service pkgs + (owadm/sdd if B2/kept). |
| `docs/` | operator + vision | **engineering** | **MERGE, do not overwrite.** Both have value (see below). |
| `scripts/` | owadm + shared | product scripts | **MERGE.** |
| `README.md` | repo landing | app dev readme | Root README wins (already updated); fold app/README content in or link it. |
| `CHANGELOG.md` | (owadm) | (product) | `app/` version wins; preserve root history if distinct. |
| `.gitignore` | root rules | app rules | **MERGE** (union of patterns). |
| `.specter-results.json` | stale | active | `app/` wins. |

**The tricky merges** (need an explicit choice, not a blind `mv`):
- **`docs/`** — root `docs/` is operator-facing (guides, runbooks, vision, Q-plans,
  Kensa boundary, security reviews); `app/docs/` is engineering (BACKEND_FUNCTIONALITY,
  ADRs, stage_*, rbac_registry). Proposed: keep root `docs/` as-is and nest engineering
  docs under `docs/engineering/` (move `app/docs/*` there), or vice-versa. Decide the layout.
- **`scripts/`** — keep both sets; de-dupe any owadm-only scripts if owadm is archived (B1).
- **`Makefile`** — `app/Makefile` becomes the root build; under B1 the owadm targets are dropped.

---

## Execution steps (on a fresh branch off `main`, after the archive branch merges)

> Do this **soon** — only PR #481 is open today, so the rebase blast radius is
> minimal. It grows with every new branch.

```
git checkout -b chore/promote-app-to-root main
```

1. **Resolve owadm** (B1 or B2). For B1, move owadm artifacts to
   `~/hanalyx/OWAR/openwatch-python/owadm/` (or a sibling archive); decide `internal/sdd/`.
2. **Clear root collisions** that `app/` will replace: remove root `go.mod`, `go.sum`,
   `Makefile`, `.specter-results.json`, and (B1) the owadm `cmd/`/`internal/` after archiving.
3. **Promote** — move `app/*` and `app/.*` up to the root:
   `git mv app/<each> .` for every entry, applying the merge decisions above for
   `docs/`, `scripts/`, `.gitignore`, `cmd/`, `internal/`.
4. **Delete the now-empty `app/`.**
5. **Update CI / config that hardcodes `app/`** (3 files):
   - `.github/workflows/go-ci.yml` — drop `working-directory: app`; `app/go.sum`→`go.sum`;
     `app/frontend/...`→`frontend/...`; change-detection regex `^(app/|...)`→`^(...)`;
     `app/.specter-results.json`→`.specter-results.json`. **Keep the job name
     "Quality + security gates" unchanged** (it is the sole required status check).
   - `.github/workflows/codeql.yml` — update any `app/` path filters.
   - `.pre-commit-config.yaml` — `app/internal/*.go` → `internal/*.go` (and any other `app/` paths).
6. **Verify config relative paths still resolve** from the new root: `sqlc.yaml`,
   `specter.yaml`, `.golangci.yml`, `api/openapi.yaml` codegen targets, `Makefile generate-api`.
7. **Update docs** that name `app/` paths: `CLAUDE.md` "quick orient" block, README,
   `docs/README.md` Quick Links, CONTRIBUTING.
8. **Verify green:**
   ```
   go build ./...
   go vet ./...
   go test ./internal/... -count=1     # -p 1 for DB-touching
   gofmt -l cmd/ internal/             # must be silent
   specter check && specter coverage
   (cd frontend && npm ci && npx tsc --noEmit && npx vitest run)
   make generate-api                   # only if api/openapi.yaml changed
   ```
9. **Confirm the required check still reports** as "Quality + security gates" on the PR.

---

## Risks & mitigations

- **Rebase cascade** for open work → do it now while only PR #481 is open; land the
  archive branch first, then branch this off `main`.
- **`git mv` history** — moves preserve history; reviewers should use `--follow`.
- **Required-check name drift** — the only required check is `go-ci.yml`'s
  "Quality + security gates"; do not rename that job or PRs will hang on a missing check
  (branch protection is owner-managed; do not modify it).
- **Relative-path configs** (`sqlc.yaml`, `specter.yaml`) — these are already relative
  *within* `app/`, so they should resolve unchanged once `app/` is the root; verify in step 6.
- **`docs/`/`scripts/`/`Makefile` merges** are the only judgment-heavy parts — agree the
  target layout (esp. `docs/engineering/`) before running `git mv`.

---

## Open decisions to confirm before executing

1. **owadm:** B1 (archive) or B2 (fold in)? Fate of `internal/sdd/`?
2. **docs layout:** nest `app/docs/` under `docs/engineering/`, or another scheme?
3. **Timing:** execute right after the archive PR merges, or batch with other root cleanup?
