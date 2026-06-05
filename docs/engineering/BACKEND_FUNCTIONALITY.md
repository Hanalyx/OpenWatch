# OpenWatch Backend Functionality Inventory

> **Generated:** 2026-04-27
> **Source:** `backend/app/` — Python/FastAPI implementation
> **Purpose:** Stage 1 input for the Go rebuild — complete catalog of features that exist today, so we can triage MUST / MAYBE / NEVER for the rebuild.
> **Method:** Six parallel sub-agents inventoried routes, auth/security, compliance/Kensa, infra services, data layer, and background work. This document synthesizes their reports.

---

## How to read this document

Every section is a **factual** description of what exists today. A feature being listed here does **not** mean it must be rebuilt — that's Stage 1's triage job.

- Entries with **[LEGACY]** are SCAP-era or replaced by newer subsystems; high candidates for the NEVER list.
- Entries with **[DUPLICATED]** have overlapping scope with another subsystem; one of the two should be dropped.
- Entries with **[FEATURE-GATED]** require an OpenWatch+ license today.

The "Rebuild Attention List" at the end aggregates these flags into a single triage view.

---

## 1. HTTP API surface (~350+ endpoints across 18 route modules)

Routes are mounted under `/api`. Below: one section per route module with the route table. Auth column shows the FastAPI dependency: `JWT` = any authenticated user, `require_permission(X)` = RBAC permission required, `require_role(X)` = role-based check, `None` = unauthenticated.

### 1.1 Auth (`/api/auth`)

Login, refresh, MFA, API keys, SSO callbacks (OIDC + SAML).

| Method | Path | Handler | Auth | Purpose |
|---|---|---|---|---|
| POST | /login | login | None | Authenticate with username/password; optional MFA |
| POST | /register | register | None | Register new user account |
| POST | /refresh | refresh_token | JWT | Refresh access token using refresh token |
| POST | /logout | logout | JWT | Invalidate refresh token |
| GET | /me | get_current_user | JWT | Get current user profile |
| POST | /mfa/status | get_mfa_status | JWT | Check MFA enrollment |
| POST | /mfa/enroll | enroll_mfa | JWT | Start TOTP enrollment |
| POST | /mfa/validate | validate_mfa_code | JWT | Validate TOTP code |
| POST | /mfa/enable | enable_mfa | JWT | Enable MFA after enrollment |
| POST | /mfa/regenerate-backup-codes | regenerate_backup_codes | JWT | Regenerate backup codes |
| POST | /mfa/disable | disable_mfa | JWT | Disable MFA |
| POST | /api-keys | create_api_key | JWT | Create API key |
| GET | /api-keys | list_api_keys | JWT | List user's API keys |
| DELETE | /api-keys/{id} | delete_api_key | JWT | Delete API key |
| PUT | /api-keys/{id}/permissions | update_api_key_permissions | JWT | Update key permissions |
| GET | /sso/providers | get_sso_providers | None | List enabled SSO providers |
| GET | /sso/login | sso_login | None | Initiate SSO login |
| GET | /sso/callback/oidc/{provider_id} | oidc_callback | None | OIDC callback |
| POST | /sso/callback/saml/{provider_id} | saml_callback | None | SAML callback |

### 1.2 Admin (`/api/admin`)

User/role/permission/SSO/security/retention/notification administration. ~45 endpoints.

Highlights: `/users`, `/users/roles`, `/audit/events`, `/audit/stats`, `/authorization/permissions/host/{id}`, `/authorization/check`, `/credentials/hosts/{id}`, `/notifications/channels` (CRUD + test), `/security/mfa`, `/security/templates`, `/sso/providers` (CRUD + test), `/retention` (policies + enforce), `/transactions/backfill`.

### 1.3 Hosts (`/api/hosts`)

Host CRUD, OS discovery, system intelligence, baseline, connectivity. ~40 endpoints.

Notable groupings:
- **Core CRUD:** GET/POST `/`, GET/PUT/DELETE `/{id}`, DELETE `/{id}/ssh-key`
- **OS / platform discovery:** `/{id}/discover-os`, `/{id}/os-info`, `/{id}/detect-platform`, `/{id}/system-info`
- **Discovery sub-domains:** basic, network, security, compliance — single + bulk variants for each
- **Server intelligence:** `/{id}/intelligence/{services,packages,users,audit,network,baseline}`
- **Baseline:** GET/POST/DELETE `/{id}/baseline`
- **Connectivity:** `/check`, `/status`, `/{id}/ping`, `/{id}/check-connectivity`, `/{id}/state`

### 1.4 Bulk operations (`/api/bulk/hosts`)

`/bulk-import`, `/import-template`, `/export-csv`, `/analyze-csv`, `/import-with-mapping`.

### 1.5 Host groups (`/api/host-groups`)

CRUD + member management + group-level scans + compliance reports/metrics + scheduling. ~17 endpoints.

### 1.6 Scans (`/api/scans`)

Largest single domain. ~50 endpoints across:
- **Scan lifecycle:** GET `/`, GET `/{id}`, POST `/legacy` **[LEGACY]**, PATCH/DELETE `/{id}`, `/{id}/stop`, `/{id}/cancel`, `/{id}/recover`, `/{id}/apply-fix`
- **Kensa subgroup:** POST `/kensa` (execute), GET `/kensa/{frameworks,health,frameworks/db,rules/framework/{f},framework/{f}/coverage,rules/{id}/framework-refs,controls/search,controls/{f}/{c},sync-stats,compliance-state/{host_id}}`, POST `/kensa/sync`
- **Templates:** CRUD on `/templates`, plus `/templates/quick`, `/templates/host/{id}`, `/templates/{id}/{apply,clone,set-default}`
- **Execution helpers:** `/validate`, `/hosts/{id}/quick-scan`, `/verify`, `/{id}/rescan/rule`, `/{id}/remediate`
- **Capabilities/profiles:** `/capabilities`, `/summary`, `/profiles`
- **Bulk scans:** POST `/bulk-scan`, GET `/bulk-scan/{session_id}/progress`, `/bulk-scan/{session_id}/cancel`, GET `/sessions`
- **Results/reports:** `/{id}/results`, `/{id}/report/{html,json,csv}`, `/{id}/failed-rules`

### 1.7 Compliance (`/api/compliance`)

Alerts, audit queries, baselines, drift, exceptions, OWCA, posture, scheduler, remediation. ~70 endpoints.

- **Alerts:** list/stats/thresholds (GET/PUT) + per-alert `/acknowledge`, `/resolve`. `/alert-routing` CRUD.
- **Audit queries:** `/audit/queries` (CRUD + saved query execution + ad-hoc execution + statistics) **[FEATURE-GATED]** for execute/preview
- **Audit exports:** `/audit/exports` (CRUD + download + statistics) **[FEATURE-GATED]**
- **Baselines:** list/create/get
- **Drift:** `/drift`, `/drift/summary`
- **Exceptions:** list/get/request/approve/reject/revoke/check; `/exceptions/summary`
- **OWCA:** `/owca/score`, `/owca/frameworks`, `/owca/control/{f}/{c}`, `/owca/trends` **[FEATURE-GATED]**, `/owca/forecast` **[FEATURE-GATED]**, `/owca/export`
- **Posture:** `/posture` (current), `/posture/history` **[FEATURE-GATED]**, `/posture/drift` **[FEATURE-GATED]**, `/posture/snapshot`, `/posture/drift/group` **[FEATURE-GATED]**, `/posture/drift/export`
- **Scheduler:** config (GET/PUT), `/toggle`, `/status`, `/hosts-due`, `/hosts/{id}` (schedule view), `/hosts/{id}/maintenance` (PUT), `/hosts/{id}/force-scan`, `/initialize`
- **Remediation:** `/remediation` (request/get/approve/execute/pending/rollback) **[DUPLICATED]** — also exists at `/api/remediation/`

### 1.8 Integrations (`/api/integrations`)

Webhooks (CRUD + deliveries + test), Jira (webhook handler + field mapping), plugins (CRUD + execute + executions), ORSA plugin discovery, integration metrics. ~28 endpoints.

### 1.9 Rules (`/api/rules`)

Rule reference (Kensa YAML browser): list, stats, frameworks, categories, variables, capabilities, detail, refresh.

### 1.10 Remediation (`/api/automated-fixes` and `/api/remediation`)

Fix evaluation/execution lifecycle: evaluate-options → request-execution → approve → execute → rollback → status; pending-approvals; secure-commands; cleanup; provider listing; Kensa remediation callback. ~17 endpoints.

### 1.11 SSH (`/api/ssh`)

Policy (GET/POST), known-hosts CRUD, connectivity test, debug auth/log. 8 endpoints.

### 1.12 System (`/api`)

Version, capabilities, feature flags, health (integrations, service, content, summary, refresh, history), discovery config + run, scheduler config + start/stop, system credentials CRUD, session-timeout. ~30 endpoints.

### 1.13 Transactions (`/api/transactions`, `/api/hosts/{id}/transactions`)

Q1 transaction-log read API: list, list by rule, get, list by host. 5 endpoints.

### 1.14 Signing (`/api/signing`)

Public keys (GET), verify, sign. 3 endpoints.

### 1.15 Fleet (`/api/fleet`)

Single endpoint: `/health`.

### 1.16 Content (`/api/content`)

[Empty/minimal — was for SCAP content; **[LEGACY]**, mostly removed.]

### 1.17 Plugins (`/api/plugins`)

[Largely consolidated into `/api/integrations/plugins/` — verify what remains here.]

---

## 2. Authentication, Authorization, RBAC

### 2.1 JWT (FIPSJWTManager)

- **Location:** `backend/app/auth.py`
- RS256 with RSA-2048 keys
- 30-min access token, 7-day refresh token, 12-hour absolute session timeout
- JTI claim for revocation tracking; PostgreSQL-backed blacklist (`token_blacklist_pg.py`)
- Public surface: `create_access_token`, `create_refresh_token`, `verify_token`, `validate_access_token`, `validate_refresh_token`
- NIST AC-12 / AC-13 compliance

### 2.2 API key authentication

- Prefix `owk_`; SHA256-hashed at rest; expiry-aware; per-key permissions
- Resolved via `decode_token()` in `auth.py`

### 2.3 Password hashing (PasswordManager)

- Argon2id, FIPS-approved
- 64 MB memory, 3 iterations, 1 parallelism, 32-byte hash, 16-byte salt

### 2.4 MFA

- `backend/app/services/auth/mfa.py`
- TOTP (RFC 6238), 160-bit secret, 1-window validation with replay protection
- 10 backup codes, SHA256-hashed
- QR code generation
- FIDO2 interface scaffolded but not implemented

### 2.5 Token blacklist (PostgreSQL-backed)

- `backend/app/services/auth/token_blacklist_pg.py`
- Replaces former Redis-based blacklist
- `token_blacklist` table; atomic UPSERT; cleanup of expired entries
- Fail-open on DB error (availability preference)

### 2.6 SSO — OIDC

- `backend/app/services/auth/sso/oidc.py`
- `authlib`-based; PKCE; standard claims validation (iss/aud/exp/nbf); rejects `alg=none`
- IdP JWKS validation

### 2.7 SSO — SAML 2.0

- `backend/app/services/auth/sso/saml.py`
- `pysaml2`-based; AuthnRequest generation; signature validation; InResponseTo + RelayState anti-CSRF
- Rejects unsigned assertions

### 2.8 SSO state storage

- `backend/app/services/auth/sso_state.py`
- Single-use state tokens, 5-min TTL, atomic delete-on-validate
- PostgreSQL `sso_state` table (replaces Redis)

### 2.9 RBAC

- `backend/app/rbac.py`
- 6 roles: SUPER_ADMIN, SECURITY_ADMIN, SECURITY_ANALYST, COMPLIANCE_OFFICER, AUDITOR, GUEST
- 33 fine-grained permissions across USER, HOST, CONTENT, SCAN, RESULTS, REPORTS, SYSTEM, AUDIT, COMPLIANCE
- Decorators: `@require_permission`, `@require_any_permission`, `@require_role`, `@require_admin`, `@require_super_admin`, `@require_analyst_or_above`

### 2.10 Authorization middleware (Zero-Trust)

- `backend/app/middleware/authorization_middleware.py`
- Intercepts protected endpoints (16+ patterns); extracts user/resources/action; delegates to AuthorizationService; **fails secure** on any error
- Audit logs allow/deny decisions

---

## 3. Cryptography, Signing, Audit

### 3.1 AES-256-GCM encryption (EncryptionService)

- `backend/app/encryption/service.py`
- NIST SP 800-38D (GCM); PBKDF2-HMAC-SHA256 (100K iter default, min 10K per SP 800-132)
- 16-byte salt + 12-byte nonce per encryption; format: `salt + nonce + ciphertext + tag`
- Configurable: DEFAULT (100K), FAST_TEST (10K), HIGH_SECURITY (200K, SHA512)
- Used for credentials, SSH keys, MFA secrets, channel configs

### 3.2 Ed25519 evidence signing (SigningService)

- `backend/app/services/signing/signing_service.py`
- Signs compliance evidence envelopes; supports key rotation without breaking old verifications
- Private keys encrypted at rest (via EncryptionService)
- Dev-mode flag: `OPENWATCH_SIGNING_DEV_MODE` (hard fail in production)
- Transaction-level locking prevents concurrent key generation

### 3.3 File-based audit (SecurityAuditLogger)

- `backend/app/auth.py`
- Logs login attempts, API key actions, scan operations to file

### 3.4 Database audit (`audit_db.py`)

- Writes to PostgreSQL `audit_logs` table
- Helpers: `log_audit_event`, `log_login_event`, `log_scan_event`, `log_host_event`, `log_user_event`, `log_security_event`, `log_admin_event`
- Defensive SSH conflict handling suggests in-progress migration

**[DUPLICATED]** File-based and DB-based audit both exist; consolidate to DB-only in rebuild.

---

## 4. Middleware

| Middleware | File | Purpose |
|---|---|---|
| Authorization (Zero-Trust) | `authorization_middleware.py` | RBAC enforcement on protected endpoints |
| Rate limiting | `rate_limiting.py` | Token-bucket per client/endpoint; suspicious-activity tracking; environment-aware (dev 10x); HMAC-SHA256 client hashing |
| Error handling | `error_handling.py` | Global exception → standardized error response with correlation IDs |
| Metrics | `metrics.py` | Latency, status code, endpoint count collection |

Rate limit categories: anonymous (60/min), authenticated (300/min), system (600/min), auth (15/min strict), validation (60/min).

---

## 5. Compliance services

### 5.1 Temporal compliance

- `backend/app/services/compliance/temporal.py`
- Point-in-time posture queries (NIST SP 800-137)
- Public surface: `TemporalComplianceService.{get_posture, get_posture_history, detect_drift}`
- **[FEATURE-GATED]** historical queries

### 5.2 Exception management

- `backend/app/services/compliance/exceptions.py`
- Approval workflow: pending → approved → expired
- Host-level and host-group waivers; risk_acceptance + compensating_controls fields
- Auto-expiry via scheduled task

### 5.3 Alert thresholds & lifecycle

- `backend/app/services/compliance/alerts.py`, `alert_generator.py`, `alert_routing.py`
- 15 alert types (CRITICAL_FINDING, SCORE_DROP, EXCEPTION_EXPIRING, CONFIGURATION_DRIFT, …)
- Lifecycle: Active → Acknowledged → Resolved
- Default thresholds: score-drop 20pp/24h, non-compliant <80%, mass-drift 10+ hosts

### 5.4 Audit queries & export

- `backend/app/services/compliance/audit_query.py`, `audit_export.py`
- Saved queries with preview; ad-hoc execution; pagination
- Exports: JSON / CSV / PDF; signed; tracked in `audit_exports`; auto-cleanup
- **[FEATURE-GATED]**

### 5.5 Drift detection

- `backend/app/services/monitoring/drift.py`
- Major (≥10pp), Minor (5–10pp), Improvement (≥5pp); auto-baseline on first scan
- Triggers `CONFIGURATION_DRIFT` alerts

### 5.6 Baseline management

- `backend/app/services/compliance/baseline_management.py`
- Manual reset / promote / rolling 7-day average
- One active baseline per host; baseline_type tracks origin

### 5.7 Adaptive compliance scheduler

- `backend/app/services/compliance/compliance_scheduler.py`
- State-based intervals: compliant 24h, mostly 12h, partial 6h, critical 1h; max 48h
- Reads `host_compliance_schedule` table
- Dispatched via job queue every 2 minutes

### 5.8 State writer (write-on-change)

- `backend/app/services/compliance/state_writer.py`
- Updates `host_rule_state` every scan; writes `transactions` rows only on status change
- Captures evidence, framework_refs, skip_reason, initiator_type/id

### 5.9 Retention policy

- `backend/app/services/compliance/retention_policy.py`
- Default 365 days; per-resource policies (transactions, audit_exports, posture_snapshots)
- Never deletes `host_rule_state`
- Signed archive bundles **partially planned** (AC-4)

### 5.10 Remediation service

- `backend/app/services/compliance/remediation.py`
- License-gated (OpenWatch+ for execution); rollback support; step-level tracking; dry-run preview
- Real Kensa dry-run plans
- Snapshots retained 30 days

---

## 6. Kensa integration & ORSA plugin

### 6.1 KensaScanner

- `backend/app/plugins/kensa/scanner.py`
- BaseScanner implementation; delegates to Kensa runner package
- 338 canonical YAML rules; SSH-based execution

### 6.2 KensaExecutor & credential bridge

- `backend/app/plugins/kensa/executor.py`
- Bridges OpenWatch's encrypted credentials to Kensa's SSH session requirements
- `OpenWatchCredentialProvider`, `KensaSessionFactory`
- Writes credentials to temp files; cleaned after use

### 6.3 KensaORSAPlugin

- `backend/app/plugins/kensa/orsa_plugin.py`
- ORSA v2.0 implementation
- Capabilities advertised: compliance_check, remediation, rollback, dry-run
- License-gated for remediation/rollback

### 6.4 KensaRuleSyncService

- `backend/app/plugins/kensa/sync_service.py`
- Syncs Kensa YAML rules to `kensa_rules` table; framework mappings to `framework_mappings`
- Hash-based change detection; dual-mapping system (inline refs + mapping files)

### 6.5 RuleReferenceService

- `backend/app/services/rule_reference_service.py`
- UI-facing browser of Kensa YAML rules; in-process cache; search/filter/pagination

### 6.6 FrameworkMapper (Kensa)

- `backend/app/plugins/kensa/framework_mapper.py`
- Maps rules to CIS RHEL 8/9/10, STIG RHEL 8/9, NIST 800-53 R5, PCI-DSS v4, FedRAMP, SRG
- PostgreSQL-backed via `framework_mappings` table

### 6.7 ComplianceFrameworkMapper **[LEGACY]**

- `backend/app/services/framework/mapper.py`
- SCAP-era mapper; in-memory; superseded by Kensa FrameworkMapper

### 6.8 ORSA plugin interface & registry

- `backend/app/services/plugins/orsa/{interface,registry}.py`
- `ORSAPlugin` ABC + `ORSAPluginRegistry` singleton
- Capability enum: COMPLIANCE_CHECK, REMEDIATION, ROLLBACK, CAPABILITY_DETECTION, DRY_RUN, PARALLEL_EXECUTION, FRAMEWORK_MAPPING

### 6.9 Plugin governance

- `backend/app/services/plugins/governance/service.py`
- Policy-based plugin compliance; lifecycle, evaluation vs SOC2/HIPAA/ISO-27001 standards
- Immutable audit events for evaluations

---

## 7. Scan engine

### 7.1 Executors

- `services/engine/executors/ssh.py` — remote scan execution via SSH
- `services/engine/executors/local.py` — local self-assessment

### 7.2 Scanners

- `services/engine/scanners/scap.py` — **[LEGACY]** SCAP/XCCDF (replaced by Kensa)

### 7.3 Result parsers

- `services/engine/result_parsers/` — XCCDF + ARF parsers; `RuleResult` dataclass; JSONB evidence in `scan_findings`

### 7.4 Dependency resolver **[LEGACY]**

- `services/engine/dependency_resolver.py` — SCAP content dependency walker (OVAL, CPE, tailoring)

### 7.5 Platform detector

- `services/engine/discovery/` — JIT OS/kernel/arch detection, per-host caching

### 7.6 Kensa mapper (engine integration)

- `services/engine/integration/kensa_mapper.py` — XCCDF → Kensa remediation plan **[LEGACY]** (SCAP-era bridge)

### 7.7 Scan orchestrator

- `services/engine/orchestration/orchestrator.py` — multi-scanner coordination, parallel execution, result merging

### 7.8 Bulk scan orchestrator

- `services/bulk_scan_orchestrator.py` — multi-host scanning with intelligent batching, progress tracking, **per-host zero-trust authorization**

---

## 8. SSH layer

### 8.1 Connection manager

- `services/ssh/connection_manager.py` — Paramiko-backed; `SSHConnectionContext`; integrates `PolicyFactory` for host-key verification

### 8.2 Key validation

- `services/ssh/key_validator.py`, `key_parser.py` — RSA / Ed25519 / ECDSA validation; security level assessment per NIST SP 800-57; SHA256 fingerprints

### 8.3 Known-hosts manager

- `services/ssh/known_hosts.py` — DB-backed (not filesystem); automation-friendly verification

### 8.4 SSH config manager

- `services/ssh/config_manager.py` — policy persistence; per-host overrides

---

## 9. OWCA — OpenWatch Compliance Algorithm (5 layers)

### 9.1 Score calculator (Core, Layer 1)

- `services/owca/core/score_calculator.py`
- `get_host_compliance_score(host_id)` → `ComplianceScore` (overall, tier, severity breakdown)

### 9.2 Severity risk calculator (Extraction, Layer 0)

- `services/owca/extraction/severity_calculator.py`
- NIST SP 800-30 weighted formula: critical=10, high=5, medium=2, low=0.5

### 9.3 Framework intelligence (Layer 2)

- `services/owca/framework/` — per-framework analyzers (NIST 800-53, CIS, STIG, PCI-DSS, FedRAMP)

### 9.4 Fleet aggregator (Layer 3)

- `services/owca/aggregation/fleet_aggregator.py` — fleet-wide stats, daily trend points

### 9.5 Trends, drift, anomalies, forecast (Layer 4)

- `services/owca/intelligence/` — `TrendAnalyzer`, `BaselineDriftDetector`, `RiskScorer`, `CompliancePredictor`, anomaly detection

### 9.6 Result caching

- `services/owca/cache/redis_cache.py` — **[LEGACY-REFERENCE]** Redis cache (Redis removed); falls back to in-process `TTLCache` via `cachetools`

---

## 10. System info / discovery

### 10.1 SystemInfoCollector

- `services/system_info/collector.py`
- Collects: packages, services, users, network interfaces, audit events, firewall rules, metrics, OS/kernel/arch, SELinux, firewall status
- Stored in `host_packages`, `host_services`, `host_users` tables

### 10.2 Discovery services

- `services/discovery/host.py` — basic host info (OS, kernel, hostname, arch)
- `services/discovery/compliance.py` — installed compliance tools (OpenSCAP, Kensa, ansible)
- `services/discovery/network.py` — interfaces, routes, DNS, firewall
- `services/discovery/security.py` — SELinux, firewall, audit daemon, SSH config

---

## 11. Licensing

- `services/licensing/service.py`
- Feature gating via `LicenseService.has_feature()` and `@requires_license()` decorator
- Free: compliance_check
- OpenWatch+: remediation, temporal_queries, structured_exceptions, priority_updates

---

## 12. Notifications

| Channel | File | Notes |
|---|---|---|
| Slack | `services/notifications/slack.py` | `slack-sdk`; webhook URL config; retry w/ exponential backoff |
| Email | `services/notifications/email.py` | `aiosmtplib`; TLS/SSL; HTML + plaintext |
| Webhook | `services/notifications/webhook.py` | HMAC-SHA256 in `X-OpenWatch-Signature` |
| Jira | `services/notifications/jira.py` | API token auth; severity → priority mapping |
| PagerDuty | `services/notifications/pagerduty.py` | Severity → urgency; dedup by rule_id+host_id |

---

## 13. Integrations & webhooks

### 13.1 Webhook service

- `services/infrastructure/webhooks.py`
- HMAC-SHA256 signing; `X-OpenWatch-Signature` + `X-OpenWatch-Timestamp` headers
- Payload templates: `create_scan_completed_payload`, `create_scan_failed_payload`

### 13.2 Jira service

- `services/infrastructure/jira_service.py`
- Issue creation/update/close from compliance findings
- Token auth, project/issue type config

### 13.3 HTTP client

- `services/infrastructure/http.py`
- Unified `httpx`-based client with circuit breaker, timeout, retry, connection pooling
- Specialized `WebhookHttpClient` with signature verification

---

## 14. Remediation

### 14.1 Recommendation engine

- `services/remediation/recommendation/`
- Generates prioritized recommendations from scan results; ORSA-compatible output
- Executors: Bash, Ansible, Kensa
- Dry-run by default; auto-generates rollback scripts for reversible operations

### 14.2 Secure automated fixes

- `services/remediation/secure_fixes.py`
- Command validation (blocklist); rollback support; full audit trail

### 14.3 Command sandbox

- `services/infrastructure/sandbox.py`
- Security levels LOW/MEDIUM/HIGH; blocks `rm -rf /`, `dd`, `format`, etc.

### 14.4 Remediation models

- `RemediationRecommendation`, `RemediationStep`, `RemediationJob`, `RemediationCategory`, `RemediationComplexity`, `RemediationPriority`, `RemediationSystemCapability`

---

## 15. Monitoring & liveness

| Service | File | Purpose |
|---|---|---|
| Health monitoring | `services/monitoring/health.py` | DB / scheduler / cache health checks |
| Host monitor | `services/monitoring/host.py` | Connectivity + last-scan tracking |
| Drift detection | `services/monitoring/drift.py` | Per-scan compliance change detection **[DUPLICATED]** with OWCA `BaselineDriftDetector` |
| Integration metrics | `services/monitoring/metrics.py` | Prometheus metrics for API, webhook, remediation |
| Adaptive scheduler | `services/monitoring/scheduler.py` | Score-based scan interval calculation |
| State machine | `services/monitoring/state.py` | Online/degraded/offline transitions w/ hysteresis |
| Liveness | `services/monitoring/liveness.py` | PostgreSQL-backed heartbeat (replaces Redis) |

---

## 16. Infrastructure services

| Service | File | Notes |
|---|---|---|
| Terminal | `infrastructure/terminal.py` | Interactive SSH terminal; TTY allocation |
| Sandbox | `infrastructure/sandbox.py` | Remediation command isolation |
| Email | `infrastructure/email.py` | Alert/report dispatch |
| HTTP | `infrastructure/http.py` | Unified `httpx` client |
| Webhooks | `infrastructure/webhooks.py` | Signature gen/verify, payload construction |
| Prometheus | `infrastructure/prometheus.py` | `/metrics` endpoint |
| Jira | `infrastructure/jira_service.py` | Ticket lifecycle |
| Config | `infrastructure/config.py` | Pydantic-validated config |
| Audit | `infrastructure/audit.py` | Structured audit logging stream |

---

## 17. Validation services

| Service | File | Notes |
|---|---|---|
| Error classification | `validation/errors.py` | SSH/scan errors → categories + remediation guidance |
| Group validation | `validation/group.py` | Pre-scan host-group compatibility check |
| Error sanitization | `validation/sanitization.py` | MINIMAL/MODERATE/STRICT levels; anti-reconnaissance |
| System info sanitization | `validation/system_sanitization.py` | Filter sensitive data from exports |
| Unified validation | `validation/unified.py` | Pre-scan validation orchestration |

---

## 18. Background work (job queue + tasks)

### 18.1 Job queue core

- `services/job_queue/service.py` (`JobQueueService`)
- PostgreSQL `SKIP LOCKED` (Celery + Redis fully removed)
- Exponential backoff: `2^retry_count * 60s`
- Schema: pending/running/completed/failed; JSONB args + result; 2000-char error
- Partial index on `(queue, priority DESC, scheduled_at ASC) WHERE status='pending'`

### 18.2 Worker

- `services/job_queue/worker.py`
- Single-threaded polling loop; round-robin across queues
- Signal-based graceful shutdown (SIGTERM/SIGINT); SIGALRM for timeout enforcement
- Concurrency setting present but unused (single-threaded)
- Poll interval: 1.0s

### 18.3 Scheduler

- `services/job_queue/scheduler.py`
- Polls `recurring_jobs`; cron parser supports `*`, lists, ranges, steps (`*/5`)
- 60-second dedup window; check interval 10s
- Background daemon thread

### 18.4 Dispatch

- `services/job_queue/dispatch.py` (`enqueue_task`) — Celery `.delay()` replacement
- Hardcoded `_TASK_QUEUES` routing table

### 18.5 Registry

- `services/job_queue/registry.py` — task name → handler mapping; wraps Celery `bind=True` tasks **[LEGACY]**

### 18.6 Job types (~30 distinct)

| Job | Trigger | Notes |
|---|---|---|
| `ping_all_managed_hosts` | Cron */5 min | Liveness check |
| `execute_kensa_scan` | API + scheduler | Kensa engine call |
| `execute_scan_celery` | API/legacy | **[LEGACY]** SCAP-era |
| `dispatch_compliance_scans` | Cron */2 min | Adaptive dispatcher |
| `run_scheduled_kensa_scan` | Enqueued by dispatcher | Per-host adaptive scan |
| `initialize_compliance_schedules` | One-shot | Bootstrap on first deploy |
| `expire_compliance_maintenance` | Cron hourly | Clear maintenance flags |
| `create_daily_posture_snapshots` | Cron 00:30 UTC | Daily aggregation |
| `cleanup_old_posture_snapshots` | Cron 03:00 UTC | Retention enforcement |
| `check_host_connectivity` | Adaptive | TCP ping |
| `dispatch_host_checks` | Cron every minute | Connectivity dispatcher |
| `detect_stale_scans` | Cron */10 min | SCAN_FAILED alert generator |
| `discover_all_hosts_os` | Cron 02:00 UTC | OS discovery sweep |
| `trigger_os_discovery` | Manual | Single-host discovery |
| `batch_os_discovery` | Manual | Batched (10/job) |
| `dispatch_alert_notifications` | Event | Slack/email/webhook fan-out |
| `execute_remediation` | API | Kensa remediation execution |
| `execute_rollback_job` | Manual/auto | Reverts remediation |
| `generate_audit_export` | API async | CSV/JSON/PDF |
| `cleanup_expired_audit_exports` | Cron daily | File + row deletion |
| `expire_compliance_exceptions` | Cron | Lifecycle |
| `backfill_posture_snapshots` | Manual | Reconstruct from transactions |
| `backfill_snapshot_rule_states` | Manual | Populate JSONB |
| `backfill_transactions_from_scans` | Manual | Convert findings → transactions |
| `backfill_host_rule_state` | Manual | 5000-row chunks |
| `enrich_scan_results` | Post-scan | **[LEGACY]** No-op |
| `import_scap_content_celery` | — | **[LEGACY]** Dead code |
| `deliver_webhook` | Event | HTTP POST + HMAC retry |
| `check_kensa_updates` | Cron nightly | Update polling |
| `perform_auto_update` | Cron conditional | Auto-upgrade Kensa |
| `cleanup_old_update_records` | Cron daily | Retention |
| `enforce_retention` | Cron 04:00 UTC | Transaction-log retention |

### 18.7 Retries & dead-letter

- Per-job `max_retries` (default 3); exponential backoff (60s, 120s, 240s, …)
- No separate dead-letter queue; failed jobs persist in `job_queue` for audit
- Manual inspection / requeue via row update

### 18.8 Observability gaps

- No built-in metrics exposition for queue depth, processing time, error rate
- No HTTP status query API; internal `JobQueueService.get_status()` only

### 18.9 Liveness service

- `services/monitoring/liveness.py`
- TCP connect to SSH port (5s timeout); no auth
- `host_liveness` table; alerts on 2 consecutive failures

---

## 19. Data layer

### 19.1 Tables (40+)

Grouped by domain. PostgreSQL-only (MongoDB fully removed PR #295).

**Identity / RBAC:**
- `users` — accounts (note: `id` is **int**, not UUID — divergence from rest of schema)
- `mfa_audit_log`, `mfa_used_codes`
- `roles`, `user_groups`, `user_group_memberships`
- `host_access`, `host_groups`, `host_group_memberships`
- `api_keys`

**Hosts & scans:**
- `hosts` (UUID PK) — inventory, encrypted credentials
- `scap_content` — **[LEGACY]** benchmark metadata
- `scans` (UUID PK)
- `scan_results` — **[LEGACY-ish]** legacy summary metrics (`host_rule_state` is now primary)
- `scan_findings` — Kensa results, JSONB evidence + framework_refs
- `scan_baselines`, `scan_drift_events`
- `system_credentials` — **[LEGACY-ish]** mostly superseded by per-host encrypted_credentials

**Compliance state (Q1 model):**
- `host_rule_state` — primary state source (per host × rule, current status)
- `transactions` — write-on-change event log; JSONB `pre_state`, `post_state`, `apply_plan`, `validate_result`, `evidence_envelope`, `framework_refs`
- `posture_snapshots` — daily compliance snapshots
- `compliance_exceptions` — waivers w/ approval workflow
- `host_compliance_schedule` — adaptive scan intervals

**Kensa & frameworks:**
- `kensa_rules` (synced metadata)
- `framework_mappings` (control → rule)

**Alerts & notifications:**
- `alert_settings`
- `alert_routing_rules`
- `notification_channels` (config_encrypted JSONB)
- `notification_deliveries`

**Auth & SSO:**
- `token_blacklist_pg`
- `signing_keys`
- `sso_providers` (config_encrypted JSONB)

**Audit & retention:**
- `audit_logs` (global)
- `audit_exports`
- `integration_audit_log`
- `retention_policies`

**Job queue:**
- `job_queue` (JSONB args + result)
- `recurring_jobs` (cron schedule)

**Liveness:**
- `host_liveness`

**System config:**
- `system_settings`
- `webhook_endpoints`, `webhook_deliveries`

### 19.2 Repositories

**No active repository pattern.** `framework_repository.py.disabled` is a legacy artifact. OpenWatch routes use direct SQL builders (`QueryBuilder`, `InsertBuilder`, `UpdateBuilder`, `DeleteBuilder`) — 100% adoption.

### 19.3 Pydantic schemas (by domain)

Auth, hosts, scans (`ScanStatus`, `RuleResultStatus`, `ScanConfiguration`, `ScanResultSummary`), compliance (`ComplianceSystemInfo`, `OperationalSystemInfo`, `AdminSystemInfo`), alerts, authorization (`ResourceType`, `ActionType`, `PermissionEffect`, `PermissionPolicy`, `AuthorizationContext`, `BulkAuthorizationRequest`), plugins (`PluginType`, `PluginStatus`, `PluginManifest`, `PluginExecutor`, `PluginPackage`), remediation (`RemediationStatus`, `RemediationTarget`, `RemediationResult`), posture, audit queries, transactions, exceptions, rule reference.

### 19.4 Recent migrations (040+)

| ID | Description |
|---|---|
| 040 | Rename Aegis → Kensa remediation_id |
| 041 | Manual remediation status |
| 042 | Make scans.content_id nullable (Kensa: no SCAP) |
| 043 | Add `has_remediation` flag |
| 044 | **transactions** table (write-on-change) |
| 045 | **host_liveness** table (heartbeat) |
| 046 | **notification_channels + notification_deliveries** |
| 047 | **sso_providers** (OIDC + SAML) |
| 048 | **host_rule_state** (primary state table) |
| 049 | **job_queue + recurring_jobs** (Celery replacement) |
| 050 | **token_blacklist_pg** (Redis replacement) |
| 051 | **signing_keys** |
| 052 | **retention_policies** |
| 053 | **alert_routing_rules** |
| 054 | Seed default recurring_jobs |

### 19.5 Connection / session management

- PostgreSQL 15+; `QueuePool` (size=10, max_overflow=20, pool_recycle=3600s)
- TLS in production (sslmode/sslcert/sslkey/sslrootcert)
- 10s connection timeout, `application_name=openwatch`
- Sync SQLAlchemy 2.0 ORM via `SessionLocal()` (NOT async)
- FastAPI `depends.get_db()` yields per-request session

---

## 20. External dependencies

| Package | Version | Use |
|---|---|---|
| Paramiko | 3.5.0 | SSH protocol |
| Kensa | v1.2.5 | **[STALE — now Go]** Compliance scanning engine; rules path discovery |
| slack-sdk | ≥3.27.0 | Slack notifications |
| aiosmtplib | 5.1.0 | Async SMTP |
| httpx | 0.28.1 | HTTP client |
| Cryptography | 46.0.5 | AES-256-GCM, RS256 JWT |
| Pydantic | 2.12.5 | Request/response validation |
| SQLAlchemy | 2.0.46 | PostgreSQL ORM |
| aiohttp | 3.13.3 | **[NARROW]** Kensa updater plugin only |

> **Note:** Memory says Kensa was migrated to Go before 2026-04-26; the inventory above reflects the Python integration as it currently lives in `backend/`. The Go rebuild will use Kensa Go directly.

---

## 21. Rebuild attention list (triage candidates)

Aggregated from the **[LEGACY]**, **[DUPLICATED]**, **[FEATURE-GATED]** flags above. This is the input to Stage 1 triage — every item below should be evaluated for MUST / MAYBE / NEVER.

### 21.1 Strong NEVER candidates (legacy, replaced, dead)

- **SCAP/XCCDF transformation chain** — `services/engine/scanners/scap.py`, `dependency_resolver.py`, `result_parsers/xccdf.py`, `kensa_mapper.py` (XCCDF → Kensa bridge). All replaced by direct Kensa execution.
- **`POST /api/scans/legacy`** — explicitly marked legacy
- **`enrich_scan_results` task** — DEPRECATED no-op
- **`import_scap_content_celery` task** — dead code
- **`execute_scan_celery` task** — SCAP-era; superseded by `execute_kensa_scan`
- **`ComplianceFrameworkMapper`** (`services/framework/mapper.py`) — superseded by Kensa `FrameworkMapper`
- **`framework_repository.py.disabled`** — legacy file, already disabled
- **OWCA `redis_cache.py` Redis path** — Redis removed; only `cachetools` fallback used
- **Celery references** in `tasks/__init__.py`, `registry.py` `_wrap_bound_task`, `dispatch.py` `_TASK_QUEUES` comment, `seed_schedule.py` "Translations from celery_app.py" comment — orphaned; cleanup-only
- **File-based audit (`SecurityAuditLogger`)** — DB audit (`audit_db.py`) is the canonical path; consolidate

### 21.2 DUPLICATED — pick one

- **Remediation endpoints** at `/api/remediation/` and `/api/compliance/remediation/` — same workflow, two surfaces
- **Scheduler config** at `/api/compliance/scheduler/` and `/api/system/scheduler/` — clarify ownership
- **Host credentials** at `/api/admin/credentials/` and `/api/system/credentials/`
- **Drift detection** — `services/monitoring/drift.py` (Drift Detection Service) and `services/owca/intelligence/baseline_drift.py` (Baseline Drift Detector)
- **Rule reference** — `RuleReferenceService` (Kensa YAML loader, authoritative) and legacy `RuleService` (cache-based, SCAP-era)

### 21.3 FEATURE-GATED — verify customer demand before rebuilding

- Audit query preview/execute (`/api/compliance/audit/queries/preview`, `/execute`)
- Audit exports (`/api/compliance/audit/exports`)
- OWCA trends / forecast (`/api/compliance/owca/trends`, `/forecast`)
- Posture history / drift / group-drift (`/api/compliance/posture/history`, `/drift`, `/drift/group`)
- Structured exceptions (full workflow)
- Priority Kensa updates

### 21.4 Architectural divergences to resolve in rebuild

- **`users.id` is `int`; everything else is UUID** — pick one in the rebuild (UUID consistent with rest of schema)
- **Sync SQLAlchemy in async FastAPI app** — Go rebuild uses pgx natively, eliminates this seam
- **`scan_results` summary table coexists with `host_rule_state`** — primary read path is `host_rule_state`; decide whether `scan_results` remains
- **`system_credentials` largely unused** — per-host encrypted_credentials is the active path

### 21.5 Implementation gaps (planned but incomplete)

- **Server Intelligence collection** — schedule and table scaffolding present, but full telemetry sweep (packages, services, users, network, audit, metrics) only partially implemented
- **Signed archive bundles** in retention policy (AC-4) — marked future enhancement
- **Baseline rolling-average auto-update** — method exists, not yet enabled
- **FIDO2 MFA** — interface scaffolded, no implementation

---

## 22. Quantitative summary

- **HTTP endpoints:** ~350 across 18 route modules
- **Database tables:** 40+ (PostgreSQL only)
- **Recent migrations:** 040–054 (15 in the Q1 wave)
- **Job types:** ~32 distinct (3 are dead code, 1 deprecated)
- **External Python packages:** 9 primary (Paramiko, Kensa, slack-sdk, aiosmtplib, httpx, Cryptography, Pydantic, SQLAlchemy, aiohttp)
- **Notification channels:** 5 (Slack, email, webhook, Jira, PagerDuty)
- **OWCA layers:** 5 (extraction, core, framework, aggregation, intelligence)
- **Compliance frameworks mapped:** 6+ (CIS, STIG, NIST 800-53, PCI-DSS, FedRAMP, SRG)
- **Roles:** 6 (SUPER_ADMIN, SECURITY_ADMIN, SECURITY_ANALYST, COMPLIANCE_OFFICER, AUDITOR, GUEST)
- **Permissions:** 33 fine-grained
- **SSO providers:** 2 (OIDC, SAML 2.0)

---

## How this informs the rebuild

This inventory is descriptive, not prescriptive. The Stage 1 triage step (per `app/docs/openwatch_roadmap.md`) takes this document plus telemetry from the running system plus operator interviews and produces three buckets:

- **MUST** — rebuild in Phase 1 (high-usage or critical-infrequent)
- **MAYBE** — rebuild only if cheap (moderate usage)
- **NEVER** — explicitly drop, log in `app/docs/not_rebuilt.md`

The "Rebuild attention list" (§21) is the pre-flagged input to that triage. Anything not flagged there still requires evidence before being considered MUST.
