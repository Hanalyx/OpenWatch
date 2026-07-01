# AGENTS.md — contributor & AI-assistant guide

This is the **tracked, reviewed** orientation for anyone (human or AI) working in
this repo. It is intentionally short and points at authoritative, tracked
sources rather than restating them — restated facts rot. For live counts
(version, package count, spec count) run **`scripts/repo-facts.sh`** instead of
trusting a number written here.

> **Note on `CLAUDE.md` and `docs/engineering/`.** `CLAUDE.md` and everything
> under `docs/engineering/` are **gitignored / local-only** by policy
> (`.gitignore`), so they are not reviewed and may drift per-machine. Treat them
> as personal scratch, not shared truth. Durable guidance that should be shared
> belongs **here** or in the tracked docs referenced below.

## What OpenWatch is

A single Go binary (`github.com/Hanalyx/openwatch`, Go 1.26) that serves a REST
API plus an embedded React 19 SPA over HTTPS, backed by **PostgreSQL only** (no
MongoDB, Redis, or Celery). Compliance scanning is the **Kensa** engine
(SSH-based, native YAML rules), integrated as a Go dependency — OpenSCAP/`oscap`
is not used. See [README.md](README.md) and [docs/guides/](docs/guides/) for the
product-level picture.

## Repo layout

```
cmd/openwatch/     main.go — serve | worker | migrate; the .With chain wires services
internal/<concern> one Go package per concern (import the package, not its files)
api/openapi.yaml   OpenAPI contract (source of truth); `make generate-api` regenerates
                   internal/server/api/server.gen.go + frontend/src/api/schema.d.ts
specs/             behavioral specs (.spec.yaml) — the SSOT, indexed by specter.yaml
frontend/          React 19 + TanStack Router/Query + Vite (dev port 5173)
packaging/         native RPM/DEB build; version.env is the single version source
Makefile, specter.yaml, sqlc.yaml, .golangci.yml, api/oapi-codegen.yaml
```

For a per-package responsibility map, read the package doc comments under
`internal/` and the specs in `specs/`. (A prose architecture manifest may exist
locally at `docs/engineering/ARCHITECTURE.md`, but it is not tracked.)

## Build, run, test

```bash
go build -o dist/openwatch ./cmd/openwatch && ./dist/openwatch serve   # API+SPA on :8443
cd frontend && npm install && npm run dev                              # Vite HMR on :5173
```

Before pushing, run the local mirror of the CI gate:

```bash
make ci-local     # check-generated + vet + lint + vuln + spec-check + test-race + vitest
```

Narrower targets: `make check` (vet/lint/vuln/test-race), `make check-generated`
(OpenAPI drift), `make spec-check` (Specter gates), `make test` /
`make test-integration` (needs a `_test` DB via `OPENWATCH_TEST_DSN`; never point
tests at a non-`_test` database). See [CONTRIBUTING.md](CONTRIBUTING.md) for the
full workflow and the pre-commit / pre-push hooks.

## OpenAPI-first (and the drift gate)

`api/openapi.yaml` is the contract. After editing it, run
`make generate-api generate-api-types` and commit the regenerated
`internal/server/api/server.gen.go` and `frontend/src/api/schema.d.ts`. CI fails
if they drift (the "Verify generated … in sync" steps). The generator
(oapi-codegen) is **pinned** in the Makefile and the embedded-spec blob is
**off** (see `api/oapi-codegen.yaml`) so regeneration is byte-deterministic —
don't turn embedded-spec back on without reading the comment there.

## Spec-driven development (Specter)

Specs in `specs/` are the SSOT; the registry is [specter.yaml](specter.yaml).
Every acceptance criterion (`AC-NN`) must be covered by a test carrying a literal
`// @spec <id>` + `// @ac AC-NN` annotation, and Go subtests also use a
`t.Run("<spec-id>/AC-NN", …)` token. CI enforces annotation hygiene
(`specter check --test`), 100% **structural** coverage
(`specter coverage --strictness annotation` — the literal `// @ac` is required,
the `t.Run` token alone is not enough), and 100% **outcome** coverage
(`specter sync` — the annotated test must pass). Run `make spec-check` locally
first. If the spec and code disagree, the (human-approved) spec wins.

## Standards that trip people up

- **`gofmt -s` before committing** — CI lint is strict; `go vet`/`build` pass on
  unformatted code, so run `gofmt -l` on touched files yourself.
- **No emojis anywhere in code/config/specs** (YAML/encoding hazards).
- **No em-dashes in user-facing UI copy** — restructure with periods/colons/
  parentheses. (Docs and commit messages are unaffected.)
- **Security is not optional**: parameterized SQL only, argument-list exec (never
  a shell), RBAC + license gates on handlers, audit auth/authz events, secrets
  from env/files only. `.golangci.yml` forbidigo encodes several of these
  (context-carrying `slog`, no `http.DefaultClient`, no raw job-queue INSERTs).
- **UUIDs, not integers**, for primary keys. Frontend auth token lives under the
  `auth_token` localStorage key.
- **Git**: branch + PR, never push to `main`, never bypass branch protection or
  required checks. Don't add AI co-author trailers to commits.

## Where to look

| Need | Tracked source |
|------|----------------|
| Contributor workflow, hooks, PR rules | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Behavioral contracts (SSOT) | [specs/](specs/) + [specter.yaml](specter.yaml) |
| API contract | [api/openapi.yaml](api/openapi.yaml) |
| Operator guides & runbooks | [docs/guides/](docs/guides/), [docs/runbooks/](docs/runbooks/) |
| Release history | [CHANGELOG.md](CHANGELOG.md) |
| Live repo facts (counts, versions) | run `scripts/repo-facts.sh` |
