# write-doc

Generate or regenerate an operator-facing document from the documentation spec.

## Usage

```
/write-doc <doc-name>
```

Where `<doc-name>` is one of:
- `docs-readme` — docs/README.md (documentation index)
- `intro` — docs/INTRODUCTION.md
- `installation` — docs/guides/INSTALLATION.md
- `quickstart` — docs/guides/QUICKSTART.md
- `user-roles` — docs/guides/USER_ROLES.md
- `api-guide` — docs/guides/API_GUIDE.md
- `scanning` — docs/guides/SCANNING_AND_COMPLIANCE.md
- `hosts-remediation` — docs/guides/HOSTS_AND_REMEDIATION.md

## Instructions

When this skill is invoked:

### Step 1: Load the source of truth

Read the authoritative engineering docs and behavioral specs to ground the content:

- `docs/engineering/BACKEND_FUNCTIONALITY.md` — backend behavior and service topology
- `docs/engineering/rbac_registry.md` and `specs/system/rbac.spec.yaml` — RBAC roles and permissions
- `specs/system/http-server.spec.yaml` — the single Go binary that serves the REST API and the embedded React UI over HTTPS on port `8443`
- `specs/system/kensa-executor.spec.yaml` — the Kensa compliance engine (Go, SSH-based, native YAML rules)
- `specs/system/job-queue.spec.yaml` — the PostgreSQL-native background job queue (`SKIP LOCKED`)
- `api/openapi.yaml` — the API contract source of truth (routes, request/response schemas)

OpenWatch is a single Go module at the repo root. There is no `app/` or `backend/` directory, no Docker Compose, and no Redis, Celery, or MongoDB. Data lives in PostgreSQL only.

### Step 2: Read source files

Based on the document being generated, read the relevant source files to populate content with verified facts:

| Document | Source files |
|----------|-------------|
| docs-readme | `docs/` directory listing (verify all linked files exist) |
| intro | `docs/engineering/BACKEND_FUNCTIONALITY.md`, `specs/system/http-server.spec.yaml` |
| installation | `docs/engineering/install_guide.md`, `docs/guides/INSTALLATION.md`, `docs/guides/PRODUCTION_DEPLOYMENT.md`, `docs/guides/ENVIRONMENT_REFERENCE.md`, `packaging/` |
| quickstart | `cmd/openwatch/main.go` (subcommands and service wiring), `api/openapi.yaml` (auth and Kensa scan routes), `specs/system/http-server.spec.yaml` |
| user-roles | `internal/users/roles.go`, `internal/auth/roles.gen.go`, `docs/engineering/rbac_registry.md`, `specs/system/rbac.spec.yaml` |
| api-guide | `api/openapi.yaml` (route and schema source of truth), `internal/server/` (handler wiring) |
| scanning | `internal/kensa/`, `specs/system/kensa-executor.spec.yaml`, `specs/system/intelligence-scheduler.spec.yaml` |
| hosts-remediation | `internal/host/`, `api/openapi.yaml` (hosts and remediation routes), `specs/system/host-inventory.spec.yaml`, `specs/system/host-discovery.spec.yaml` |

### Step 3: Write the Document

Follow these rules from the spec constraints:

- **UI-First**: OpenWatch is a GUI platform. 90% of operator tasks happen in the web UI. Workflow guides (quickstart, scanning, hosts-remediation) MUST describe UI interactions first with screenshot placeholders (`![Description](../images/<guide>/<step>.png)`). API/curl examples belong in a clearly labeled "Appendix: API Automation" section at the end. Only the Installation Guide and API Guide use CLI as the primary format.
- **Tone**: Procedural and direct. Write for operators who deploy and maintain, not developers who extend.
- **Accuracy**: All file paths, API endpoints, environment variables, and role names MUST be verified against the codebase before inclusion. Never state a feature exists without verifying the route/service/model exists in code.
- **Scope**: Daily/weekly/monthly tasks only. No edge cases, no developer internals.
- **Format**: GitHub-flavored Markdown. No emojis. Tables for structured data. Code blocks for commands.
- **Cross-references**: Link between docs using relative paths. Every doc should link to at least 2 others.
- **Role names**: `admin`, `security_admin`, `ops_lead`, `auditor`, `viewer` (built-in roles from `internal/users/roles.go` / `internal/auth/roles.gen.go`; admins may also create custom roles)
- **Framework data**: Use framework IDs and rule counts verified against `internal/kensa/` and `specs/system/kensa-executor.spec.yaml`
- **API paths**: All REST endpoints use the `/api/v1` prefix. Verify against `api/openapi.yaml`.
- **Auth**: Browser sessions use HttpOnly cookies (`openwatch_session` / `openwatch_refresh`). The first admin is created with `openwatch create-admin`. The frontend stores its auth token under the `auth_token` localStorage key.

### Step 4: Verify

After writing, run these checks:

1. **File paths**: Grep or glob every file path mentioned in the document to confirm it exists
2. **API endpoints**: Verify each endpoint is defined in `api/openapi.yaml`
3. **Environment variables**: Verify each env var against `internal/config/` and `docs/guides/ENVIRONMENT_REFERENCE.md`
4. **Role names**: Verify against `internal/users/roles.go` and `internal/auth/roles.gen.go`
5. **Framework data**: Verify IDs and counts against `internal/kensa/` and `specs/system/kensa-executor.spec.yaml`
6. **Cross-references**: Verify all linked docs exist

Report any verification failures and fix them before finishing.

## Example

```
/write-doc quickstart
```

This reads the source of truth, reads the source files (`cmd/openwatch/main.go`, the auth and Kensa scan routes in `api/openapi.yaml`), writes `docs/guides/QUICKSTART.md` as a UI-first walkthrough with screenshot placeholders and API examples in the appendix, and checks that all endpoints and paths are valid.
