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

### Step 1: Load the Spec

Read `specs/system/documentation.spec.yaml` to get:
- The document's outline (sections, content requirements)
- Constraints (tone, accuracy, scope, format)
- Acceptance criteria
- Source files to read

Read `specs/system/architecture.spec.yaml` to get:
- Verified tech stack versions
- Service topology (6 Docker services)
- API route packages and prefixes
- RBAC roles (6 roles, 33 permissions)
- Compliance engine details (Kensa v1.1.0, 338 rules, 5 frameworks)
- Celery task routing and beat schedule
- Environment differences (dev vs production)

### Step 2: Read Source Files

Based on the document being generated, read the relevant source files to populate content with verified facts:

| Document | Source Files |
|----------|-------------|
| docs-readme | docs/ directory listing (verify all linked files exist) |
| intro | docker-compose.yml, architecture.spec.yaml |
| installation | docker-compose.yml, docker-compose.prod.yml, docker/Dockerfile.backend, docker/Dockerfile.frontend, start-openwatch.sh, docs/guides/PRODUCTION_DEPLOYMENT.md, docs/guides/ENVIRONMENT_REFERENCE.md |
| quickstart | backend/app/main.py (route registrations), backend/app/routes/auth/login.py, backend/app/routes/scans/kensa.py |
| user-roles | backend/app/rbac.py (UserRole enum, Permission enum, ROLE_PERMISSIONS mapping) |
| api-guide | backend/app/main.py, backend/app/routes/*/__init__.py, backend/app/schemas/*.py |
| scanning | backend/app/plugins/kensa/, backend/app/services/compliance/, backend/app/tasks/adaptive_monitoring_dispatcher.py |
| hosts-remediation | backend/app/routes/hosts/, backend/app/routes/remediation/, backend/app/routes/host_groups/, backend/app/services/remediation/ |

### Step 3: Write the Document

Follow these rules from the spec constraints:

- **UI-First**: OpenWatch is a GUI platform. 90% of operator tasks happen in the web UI. Workflow guides (quickstart, scanning, hosts-remediation) MUST describe UI interactions first with screenshot placeholders (`![Description](../images/<guide>/<step>.png)`). API/curl examples belong in a clearly labeled "Appendix: API Automation" section at the end. Only the Installation Guide and API Guide use CLI as the primary format.
- **Tone**: Procedural and direct. Write for operators who deploy and maintain, not developers who extend.
- **Accuracy**: All file paths, API endpoints, environment variables, and role names MUST be verified against the codebase before inclusion. Never state a feature exists without verifying the route/service/model exists in code.
- **Scope**: Daily/weekly/monthly tasks only. No edge cases, no developer internals.
- **Format**: GitHub-flavored Markdown. No emojis. Tables for structured data. Code blocks for commands.
- **Cross-references**: Link between docs using relative paths. Every doc should link to at least 2 others.
- **Role names**: SUPER_ADMIN, SECURITY_ADMIN, SECURITY_ANALYST, COMPLIANCE_OFFICER, AUDITOR, GUEST (from backend/app/rbac.py)
- **Framework data**: Use IDs and rule counts from architecture.spec.yaml compliance_engine.frameworks
- **API paths**: All REST endpoints use /api prefix. Verify against main.py router registrations.
- **Auth**: JWT Bearer token via Authorization header. localStorage key is auth_token.

### Step 4: Verify

After writing, run these checks:

1. **File paths**: Grep or glob every file path mentioned in the document to confirm it exists
2. **API endpoints**: Verify each endpoint is registered in backend/app/main.py or its route packages
3. **Environment variables**: Verify each env var exists in docker-compose.yml or backend/app/config.py
4. **Role names**: Verify against backend/app/rbac.py UserRole enum
5. **Framework data**: Verify IDs and counts against specs/system/architecture.spec.yaml
6. **Cross-references**: Verify all linked docs exist

Report any verification failures and fix them before finishing.

## Example

```
/write-doc quickstart
```

This reads the spec, reads the source files (main.py, auth routes, kensa routes), writes docs/guides/QUICKSTART.md as a UI-first walkthrough with screenshot placeholders and API examples in the appendix, and checks that all endpoints and paths are valid.
