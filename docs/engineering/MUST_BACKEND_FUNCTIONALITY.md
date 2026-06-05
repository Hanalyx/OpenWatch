# MUST — Backend Functionality (Phase 1 Rebuild)

> **Source:** `app/docs/BACKEND_FUNCTIONALITY.md`, triaged 2026-04-27
> **Rule:** Items here are non-negotiable for Phase 1. Rebuilding without them produces a non-viable compliance platform.
> **Method:** Static analysis from inventory + architectural reasoning. **No telemetry data yet.** Items marked **[VALIDATE]** should be confirmed against deployment evidence before final lock-in.

---

## Triage criteria for MUST

An item lands here if **any** of the following holds:

1. **Core compliance loop:** authenticate → discover host → run scan → record state → query posture. Without it, OpenWatch isn't a compliance scanner.
2. **Security baseline:** auth, encryption, RBAC, audit. Compliance product without these is dead on arrival.
3. **Data-model load-bearing:** Q1 architecture (transaction-log + write-on-change + adaptive scheduling) is the proven foundation; the schema is locked for the rebuild.
4. **Operational floor:** job queue, scheduling, liveness, health, retention. The platform can't run without these.

Anything that fails all four → MAYBE or NEVER.

---

## Authentication & Authorization

| Component | Source (current) | Why MUST |
|---|---|---|
| JWT (RS256, RSA-2048) | `auth.py` `FIPSJWTManager` | Auth foundation; FIPS-aligned |
| Password hashing (Argon2id, 64MB / 3 iter) | `auth.py` `PasswordManager` | Security baseline |
| API key auth (prefix `owk_`, SHA256-hashed) | `auth.py` | Required for agent / service-to-service auth — agent-first principle |
| MFA TOTP + backup codes | `services/auth/mfa.py` | Compliance product baseline (NIST IA-2) |
| Token blacklist (PostgreSQL) | `services/auth/token_blacklist_pg.py` | Logout / revocation; replaces Redis cleanly |
| RBAC — 6 roles, 33 permissions | `rbac.py` | Authorization foundation; map directly into Go |
| SSO — OIDC | `services/auth/sso/oidc.py` | **[VALIDATE]** Federal/enterprise customers commonly require it; lean MUST |
| SSO — SAML 2.0 | `services/auth/sso/saml.py` | **[VALIDATE]** Same reasoning as OIDC |
| SSO state storage (PostgreSQL, single-use, 5-min TTL) | `services/auth/sso_state.py` | Required by SSO providers above |

---

## Cryptography & Audit

| Component | Source | Why MUST |
|---|---|---|
| AES-256-GCM `EncryptionService` | `encryption/service.py` | Credentials, SSH keys, MFA secrets, channel configs all depend on it |
| Ed25519 `SigningService` (with key rotation) | `services/signing/signing_service.py` | Evidence integrity; matches roadmap §Phase 1 (`crypto/ed25519` stdlib in Go) |
| DB-based audit logging | `audit_db.py` | Audit-as-API contract (roadmap §Agent-First); the canonical audit path |
| Audit log table (`audit_logs`) | model | Structured event store for compliance |
| Integration audit log (`integration_audit_log`) | model | Cross-service audit trail |

---

## Middleware

| Component | Source | Why MUST |
|---|---|---|
| Authorization (Zero-Trust) | `middleware/authorization_middleware.py` | RBAC enforcement on every protected route |
| Rate limiting (token bucket) | `middleware/rate_limiting.py` | DoS protection; auth brute-force defense |
| Error handling (correlation IDs) | `middleware/error_handling.py` | Roadmap requires `X-Correlation-Id` end-to-end |
| Metrics | `middleware/metrics.py` | Observability floor |

---

## Hosts & host management

| Component | Source | Why MUST |
|---|---|---|
| Host CRUD (list, create, get, update, delete) | `routes/hosts/` | Core resource |
| Host group CRUD + member management | `routes/host_groups/` | Operational unit for scans |
| Bulk import (CSV) + analyze + export | `routes/hosts/bulk_operations.py` | **[VALIDATE]** common operator workflow |
| Basic host discovery (OS, kernel, hostname, arch) | `services/discovery/host.py` | Required to select scan profile |
| Compliance tools discovery | `services/discovery/compliance.py` | Required to confirm Kensa eligibility |
| Host connectivity check / ping | `routes/hosts/` | Operational requirement |
| Host state read (`/{id}/state`) | `routes/hosts/` | Compliance posture entry point |

---

## SSH layer

| Component | Source | Why MUST |
|---|---|---|
| Connection manager | `services/ssh/connection_manager.py` | Every scan executes over SSH |
| Key validation (RSA / Ed25519 / ECDSA, NIST SP 800-57) | `services/ssh/key_validator.py`, `key_parser.py` | Security baseline |
| Known hosts manager (DB-backed) | `services/ssh/known_hosts.py` | Host-key verification |
| SSH config / policy manager | `services/ssh/config_manager.py` | Policy enforcement (cipher allowlist, key types) |

---

## Scan engine (Kensa-only path)

| Component | Source | Why MUST |
|---|---|---|
| SSH executor | `services/engine/executors/ssh.py` | Remote scan execution |
| Platform detector | `services/engine/discovery/` | JIT OS detection per scan |
| Bulk scan orchestrator (zero-trust per-host auth) | `services/bulk_scan_orchestrator.py` | Multi-host scanning is core |
| Scan lifecycle (start, stop, cancel, recover) | `routes/scans/` | Operational |
| Scan templates (CRUD, apply, clone) | `routes/scans/` | **[VALIDATE]** Operator convenience; lean MUST |
| Scan results read API (`/scans/{id}/results`, `/failed-rules`) | `routes/scans/` | Output of every scan |
| Scan reports (HTML/JSON/CSV — content-negotiated in rebuild) | `routes/scans/` | Required artifact format |

---

## Kensa integration (Go-to-Go in rebuild)

| Component | Source | Why MUST |
|---|---|---|
| Kensa scanner adapter | `plugins/kensa/scanner.py` | The compliance engine |
| Credential bridge (encrypted creds → Kensa SSH session) | `plugins/kensa/executor.py` | Required for SSH-based scanning |
| ORSA plugin wrapper | `plugins/kensa/orsa_plugin.py` | Kensa is the reference ORSA plugin |
| Kensa rule sync service | `plugins/kensa/sync_service.py` | Keeps `kensa_rules` and `framework_mappings` current |
| Rule reference service (Kensa YAML browser) | `services/rule_reference_service.py` | Backs the rules UI |
| Framework mapper (Kensa, PG-backed) | `plugins/kensa/framework_mapper.py` | CIS/STIG/NIST/PCI-DSS/FedRAMP mapping |
| ORSA plugin interface + registry | `services/plugins/orsa/{interface,registry}.py` | Extensibility contract |

> **Note:** Implementation shape changes in the Go rebuild (Go-to-Go integration with Kensa Go), but the conceptual surface (scanner, sync, rule reference, framework mapping, ORSA interface) is unchanged.

---

## Compliance state (Q1 model — load-bearing)

| Component | Source | Why MUST |
|---|---|---|
| State writer (write-on-change pattern) | `services/compliance/state_writer.py` | Core data-flow primitive |
| `host_rule_state` table | migration 048 | Primary read source for compliance state |
| `transactions` table | migration 044 | Append-only event log; powers temporal & audit queries |
| Transaction log read API | `routes/transactions/` | Required for audit/agent-readable history |
| Posture (current) | `services/compliance/temporal.py` (current-state path) | Real-time compliance view |
| `posture_snapshots` table | model | Daily snapshots; enables historical queries |
| `host_compliance_schedule` table | model | Adaptive scheduling foundation |
| Daily posture snapshot creation (cron) | `tasks/posture_tasks.py` `create_daily_posture_snapshots` | Continuous monitoring (NIST SP 800-137) |

---

## Compliance workflow (essentials)

| Component | Source | Why MUST |
|---|---|---|
| Drift detection (basic — scan-vs-baseline) | `services/monitoring/drift.py` | Core compliance signal |
| Baseline management (manual reset, promote) | `services/compliance/baseline_management.py` | Required to manage drift events |
| `scan_baselines`, `scan_drift_events` tables | model | Drift tracking storage |
| Compliance exceptions (request, approve, reject, revoke, check) | `services/compliance/exceptions.py` | Governance baseline |
| `compliance_exceptions` table | model | Exception storage with approval workflow |
| Adaptive compliance scheduler | `services/compliance/compliance_scheduler.py` | Auto-scan engine — core to Compliance OS direction |
| Adaptive scheduler dispatcher (cron */2 min) | `tasks/compliance_scheduler_tasks.py` | Runs the scheduler |
| Maintenance window expiry (cron hourly) | `tasks/compliance_scheduler_tasks.py` `expire_compliance_maintenance` | Cleanup |
| Exception expiry task | `tasks/exception_tasks.py` `expire_compliance_exceptions` | Lifecycle |

---

## Alerts (basic lifecycle)

| Component | Source | Why MUST |
|---|---|---|
| Alert lifecycle (create, list, acknowledge, resolve) | `services/compliance/alerts.py` | Operator notification floor |
| Basic alert types (CRITICAL_FINDING, SCORE_DROP, EXCEPTION_EXPIRING, CONFIGURATION_DRIFT, HOST_UNREACHABLE) | `services/compliance/alerts.py` | The 5 alert types operators actually use |
| Alert generator | `services/compliance/alert_generator.py` | Emits alerts on signal |
| Stale-scan detector (cron */10 min) | `tasks/stale_scan_detection.py` | Generates SCAN_FAILED alerts |
| `alert_settings` table | model | Per-user alert preferences |

> Alert routing rules and the full 15-type alert taxonomy → MAYBE.

---

## Notifications (3 channels)

| Component | Source | Why MUST |
|---|---|---|
| Slack channel | `services/notifications/slack.py` | **[VALIDATE]** Most-used integration; lean MUST |
| Email channel (SMTP) | `services/notifications/email.py` | Fallback channel; always available |
| Webhook channel (HMAC-signed) | `services/notifications/webhook.py` | Generic integration path |
| Notification channels CRUD | `routes/admin/` notifications/channels | Channel configuration |
| Notification dispatch (alert → channels) | `tasks/notification_tasks.py` `dispatch_alert_notifications` | The fan-out mechanism |
| `notification_channels`, `notification_deliveries` tables | migration 046 | Storage |

> Jira and PagerDuty channels → MAYBE.

---

## OWCA (compliance scoring — minimum)

| Component | Source | Why MUST |
|---|---|---|
| Score calculator (Layer 1) | `services/owca/core/score_calculator.py` | The compliance score is the headline metric |
| Severity calculator (Layer 0) | `services/owca/extraction/severity_calculator.py` | Underlies the score |

> Layers 2–4 (framework intelligence, fleet aggregator, trends/predictions) → MAYBE.

---

## Validation & sanitization

| Component | Source | Why MUST |
|---|---|---|
| Error classification (SSH/scan errors → user guidance) | `services/validation/errors.py` | Operational UX |
| Group validation (pre-scan compatibility check) | `services/validation/group.py` | Prevents bad bulk scans |
| Error sanitization (anti-reconnaissance) | `services/validation/sanitization.py` | Security baseline |
| System info sanitization | `services/validation/system_sanitization.py` | Security baseline |
| Unified pre-scan validation | `services/validation/unified.py` | Orchestrates the above |

---

## Job queue (custom port)

| Component | Source | Why MUST |
|---|---|---|
| Queue core (`SKIP LOCKED`) | `services/job_queue/service.py` | Foundational; locked decision in roadmap |
| Worker | `services/job_queue/worker.py` | Executes jobs |
| Scheduler (cron parser, recurring_jobs poll) | `services/job_queue/scheduler.py` | Drives all periodic work |
| Dispatch (`enqueue_task`) | `services/job_queue/dispatch.py` | Public enqueue API |
| Registry (task name → handler) | `services/job_queue/registry.py` | Routing — but rebuild without Celery `bind=True` wrapping |
| `job_queue`, `recurring_jobs` tables | migration 049 | Storage |

---

## Liveness & monitoring (essentials)

| Component | Source | Why MUST |
|---|---|---|
| Liveness service (TCP ping) | `services/monitoring/liveness.py` | Heartbeat for fleet health |
| `host_liveness` table | migration 045 | Heartbeat storage |
| Health monitoring service | `services/monitoring/health.py` | `/health` endpoint backing |
| Host monitor | `services/monitoring/host.py` | Connectivity + last-scan tracking |
| Drift detection (monitoring path) | `services/monitoring/drift.py` | One drift implementation — keep this one (simpler than OWCA path) |
| Adaptive monitoring dispatcher (cron every minute) | `tasks/adaptive_monitoring_dispatcher.py` | Drives connectivity checks |
| Per-host connectivity check task | `tasks/monitoring_tasks.py` `check_host_connectivity` | The work unit |
| Ping-all task (cron */5 min) | `tasks/liveness_tasks.py` `ping_all_managed_hosts` | Fleet-wide liveness sweep |

---

## Retention (basic)

| Component | Source | Why MUST |
|---|---|---|
| Retention policy service (basic — delete by age) | `services/compliance/retention_policy.py` | Compliance + storage hygiene |
| `retention_policies` table | migration 052 | Per-resource policy storage |
| Retention enforcement task (cron 04:00 UTC) | `tasks/retention_tasks.py` `enforce_retention` | Runs the policy |

> Signed archive bundles → MAYBE (incomplete).

---

## Infrastructure (foundational)

| Component | Source | Why MUST |
|---|---|---|
| HTTP client (with circuit breaker) | `services/infrastructure/http.py` | All outbound traffic |
| Webhook signing/verification | `services/infrastructure/webhooks.py` | Webhook security |
| Email service | `services/infrastructure/email.py` | Notification baseline |
| Prometheus metrics export | `services/infrastructure/prometheus.py` | `/metrics` endpoint |
| Config service (Pydantic-validated, env-driven) | `services/infrastructure/config.py` | Replaced by TOML + env in Go (per roadmap), but the concept is MUST |
| Audit logger stream | `services/infrastructure/audit.py` | Structured audit |

---

## OS discovery (basic)

| Component | Source | Why MUST |
|---|---|---|
| OS discovery sweep (cron 02:00 UTC) | `tasks/os_discovery_tasks.py` `discover_all_hosts_os` | Required for platform_identifier accuracy |
| Single-host OS discovery (manual/scheduler) | `tasks/os_discovery_tasks.py` `trigger_os_discovery` | Operator action |
| Batch OS discovery | `tasks/os_discovery_tasks.py` `batch_os_discovery` | Bulk variant |

---

## Webhooks (delivery infrastructure)

| Component | Source | Why MUST |
|---|---|---|
| Webhook delivery worker | `tasks/background_tasks.py` `deliver_webhook` | Async webhook dispatch with HMAC + retry |
| `webhook_endpoints`, `webhook_deliveries` tables | model | Storage + delivery audit |

---

## Data layer (MUST tables)

The following tables are required by the items above. The full table list with migration numbers is in `BACKEND_FUNCTIONALITY.md` §19.1.

**Identity / RBAC:** `users`, `roles`, `user_groups`, `user_group_memberships`, `host_access`, `api_keys`, `mfa_audit_log`, `mfa_used_codes`, `sso_providers`

**Hosts & scans:** `hosts`, `host_groups`, `host_group_memberships`, `scans`, `scan_findings`, `scan_baselines`, `scan_drift_events`

**Compliance state:** `host_rule_state`, `transactions`, `posture_snapshots`, `compliance_exceptions`, `host_compliance_schedule`

**Kensa & frameworks:** `kensa_rules` (or Go equivalent), `framework_mappings`

**Alerts & notifications:** `alert_settings`, `notification_channels`, `notification_deliveries`

**Auth & SSO:** `token_blacklist_pg`, `signing_keys`, `sso_providers`

**Audit & retention:** `audit_logs`, `integration_audit_log`, `retention_policies`

**Job queue:** `job_queue`, `recurring_jobs`

**Liveness:** `host_liveness`

**System config:** `system_settings`, `webhook_endpoints`, `webhook_deliveries`

> **Schema divergence to fix in rebuild:** `users.id` is currently `int`. The Go rebuild uses UUID for everything. Plan a one-shot data migration as part of Phase 1.

---

## What this list deliberately excludes

- Anything in `MAYBE_BACKEND_FUNCTIONALITY.md` (feature-gated, planned-incomplete, or moderate-usage features).
- Anything in `NEVER_BACKEND_FUNCTIONALITY.md` (legacy, deprecated, dead code, or duplications where one path is dropped).

When in doubt, don't add to MUST. The discipline is to keep MUST small and let MAYBE catch the borderline cases.

---

## Stage 1 evidence corrections (2026-04-28)

The static-analysis pass at `app/docs/stage_1_evidence_static.md` surfaced two corrections to this list:

### Correction 1: Licensing is a fresh build, not a port

`services/licensing/service.py` has three TODO stubs for license validation (`Implement license key validation`, two for `Query database for license`). Today's `LicenseService.has_feature()` is a **config-flag check pretending to be license validation** — it does not validate license keys, query a license DB, or enforce expiry.

**Triage update:** Licensing stays in MUST, but the rebuild's licensing component must be a **fresh build with proper key validation, expiry enforcement, and DB-backed license records.** Do not port the current Python implementation; design from scratch.

### Correction 2: Test debt list — Stage 2 entry criteria

The following MUST items have **zero test coverage** in the current Python codebase. The Go rebuild must add tests for these from day one of porting — not "add tests later."

| Module | Why this matters |
|---|---|
| `services/job_queue/dispatch.py` | Used by 14+ route handlers as the enqueue API |
| `services/job_queue/registry.py` | Task name → handler mapping |
| `services/auth/credential_handler.py` | Phase 2 host credential refactor |
| `services/auth/token_blacklist_pg.py` | JWT revocation; security-critical |
| `services/baseline_service.py` | NIST SP 800-137 drift baseline |
| `plugins/kensa/scanner.py` | Core Kensa execution adapter |
| `plugins/kensa/evidence.py` | Evidence serialization for audit |
| `plugins/kensa/sync_service.py` | Rule sync after Kensa updates |

**Stage 2 entry criterion:** Slice A cannot ship without test coverage for the auth modules listed. Slice B cannot ship without test coverage for the Kensa modules listed. Slice C cannot ship without test coverage for the baseline service.

---

## Validation TODOs (before final lock)

Items marked **[VALIDATE]** above should be confirmed via:

1. **Telemetry from current OpenWatch** — endpoint hit rates over 60–90 days
2. **Operator interviews** — "what would break for me if this disappeared?"

The following [VALIDATE] items are most at risk of demotion to MAYBE if telemetry says otherwise:

- SSO OIDC + SAML (might be MAYBE if no enterprise/federal customer signal)
- Bulk CSV import/export (might be MAYBE if not used)
- Scan templates (might be MAYBE if operators don't actually use them)
- Slack channel (might be MAYBE if customers prefer email/webhook)

Other MUST items are protected by the four triage criteria and should not be questioned by usage data alone.
