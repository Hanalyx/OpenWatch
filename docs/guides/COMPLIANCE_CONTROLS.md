# Compliance Control Mapping

**Last Updated:** 2026-06-25 · **Applies to:** OpenWatch 0.2.0-rc series (Go single-binary)

This document maps OpenWatch's security controls to industry frameworks, providing evidence for compliance audits.

## Framework Coverage

| Framework | Controls Mapped | Coverage |
|-----------|----------------|----------|
| NIST SP 800-53 Rev 5 | 42 | Moderate baseline |
| CIS Controls v8 | 18 | Implementation Group 2 |
| CMMC Level 2 | 28 | Practice-level mapping |
| FedRAMP Moderate | 42 | Inherited from NIST |
| ISO 27001:2022 | 15 | Annex A controls |

## NIST SP 800-53 Control Mapping

### Access Control (AC)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| AC-2 | Account Management | User CRUD with RBAC (5 roles: viewer, auditor, ops_lead, security_admin, admin) | `internal/users/`, user audit events |
| AC-3 | Access Enforcement | Role-based permission checks on each route | `internal/auth/`, generated permission registry |
| AC-6 | Least Privilege | Five built-in roles (least-privilege viewer baseline) | `internal/auth/roles.gen.go` |
| AC-7 | Unsuccessful Logon Attempts | Per-IP sliding-window rate limit on the auth endpoints (login, MFA verify); 429 + Retry-After | `internal/server/` middleware |
| AC-8 | System Use Notification | Configurable login banner | Frontend login page |
| AC-11 | Session Lock | Inactivity timeout (default 15 min, configurable 1-480) | `internal/systemconfig/` (session-timeout) |
| AC-12 | Session Termination | Session cookie and JWT expiration (30 min access, 7 day refresh) | `internal/auth/` |
| AC-17 | Remote Access | SSH with NIST SP 800-57 key validation | `internal/ssh/` |

### Audit and Accountability (AU)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| AU-2 | Event Logging | Structured audit events for auth/scan/admin actions | `internal/audit/` |
| AU-3 | Content of Audit Records | User, timestamp, action, resource, outcome | `internal/audit/` |
| AU-6 | Audit Record Review | Audit query API (`/api/v1/audit/events`) | `internal/audit/`, `api/openapi.yaml` |
| AU-9 | Protection of Audit Information | Audit events stored append-only in PostgreSQL | `audit_events` table (`internal/db/migrations/`) |
| AU-12 | Audit Record Generation | API routes generate audit events | `internal/server/`, `internal/audit/` |

### Configuration Management (CM)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| CM-2 | Baseline Configuration | Kensa YAML rules define expected configurations | Kensa rules (338 native YAML rules) |
| CM-3 | Configuration Change Control | SQL migration tracking, git version control | `internal/db/migrations/` (run via `openwatch migrate`) |
| CM-6 | Configuration Settings | Configuration validation at startup | `internal/config/`, `openwatch check-config` |
| CM-8 | System Component Inventory | Host management with discovery and metadata | `internal/host/`, `internal/intelligence/` |

### Identification and Authentication (IA)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| IA-2 | Identification and Authentication | Session cookie and JWT auth with username/password | `internal/auth/` |
| IA-2(1) | MFA for Privileged Accounts | TOTP-based MFA with backup codes | `internal/auth/` |
| IA-5 | Authenticator Management | Argon2id hashing (64MB, 3 iterations), 8-char minimum (15 for admin) | `internal/users/` |
| IA-5(1) | Password-Based Authentication | Complexity requirements (upper, lower, digit, special) | `internal/auth/` (password policy) |

### Risk Assessment (RA)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| RA-5 | Vulnerability Monitoring | Automated compliance scanning via Kensa | `internal/kensa/` |
| RA-5(2) | Update Vulnerabilities | Kensa rule updates via rule sync | `internal/kensa/` |

### System and Communications Protection (SC)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| SC-8 | Transmission Confidentiality | TLS 1.2/1.3 for all connections | `internal/server/` (HTTPS listener) |
| SC-8(1) | Cryptographic Protection | FIPS-approved cipher suites | `internal/config/` |
| SC-10 | Network Disconnect | Configurable session timeout | `internal/systemconfig/` |
| SC-12 | Cryptographic Key Establishment | AES-256-GCM with environment-sourced keys | `internal/secretkey/`, `internal/credential/` |
| SC-13 | Cryptographic Protection | FIPS via OpenSSL 3.x FIPS provider | `internal/config/` |
| SC-23 | Session Authenticity | Session cookie plus JWT, HttpOnly cookies | `internal/auth/` |
| SC-28 | Protection of Information at Rest | AES-256-GCM encryption for credentials | `internal/credential/`, `internal/secretkey/` |

### System and Information Integrity (SI)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| SI-2 | Flaw Remediation | Single Go binary built from a maintained Go toolchain | `go.mod`, native RPM/DEB packages |
| SI-4 | System Monitoring | Health checks and fleet monitoring endpoints | `/api/v1/health`, `internal/liveness/` |
| SI-10 | Information Input Validation | Request validation at the API boundary, parameterized SQL | `internal/server/`, `sqlc`-generated queries |

## CIS Controls v8 Mapping

| CIS Control | Title | OpenWatch Implementation |
|-------------|-------|-------------------------|
| 1.1 | Enterprise Asset Inventory | Host management with system info collection |
| 2.1 | Software Inventory | Server intelligence (package collection) |
| 3.3 | Data Encryption | AES-256-GCM at rest, TLS 1.2+ in transit |
| 4.1 | Secure Configuration | Kensa compliance scanning (538-rule corpus) |
| 4.2 | Baseline Network Configuration | Network discovery and topology mapping |
| 5.2 | Unique Passwords | Argon2id hashing, 8-char minimum (15 for admin), breached-password screening |
| 5.4 | MFA | TOTP-based MFA with backup codes |
| 6.1 | Audit Log Management | Structured JSON audit logs, audit query API |
| 6.3 | Centralized Log Collection | JSON logging, configurable log aggregation |
| 8.2 | Audit Logging | All authentication and authorization events logged |
| 8.5 | Access Control Logs | JWT validation events, RBAC enforcement logged |
| 8.11 | Audit Log Retention | Configurable retention, export to CSV/JSON/PDF |
| 9.1 | Email Security | SMTP TLS for notifications |
| 10.1 | Anti-Malware | File upload validation, no executable uploads |
| 13.1 | Network Monitoring | Health check endpoints, Prometheus metrics |
| 16.1 | Application Security | Request validation at the API boundary, parameterized SQL (no raw SQL) |
| 16.9 | Security Headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options |
| 16.11 | Web Application Firewalls | Built-in rate limiting, request size limits |

## CMMC Level 2 Practice Mapping

| Practice | Domain | OpenWatch Implementation |
|----------|--------|-------------------------|
| AC.L2-3.1.1 | Access Control | RBAC with five built-in roles |
| AC.L2-3.1.2 | Access Control | Transaction-level access enforcement |
| AC.L2-3.1.5 | Access Control | Least privilege (viewer default role) |
| AC.L2-3.1.7 | Access Control | Prevent non-privileged users from executing privileged functions |
| AC.L2-3.1.8 | Access Control | Unsuccessful logon attempt limiting |
| AC.L2-3.1.10 | Access Control | Session lock after inactivity |
| AC.L2-3.1.12 | Access Control | Remote access session termination |
| AU.L2-3.3.1 | Audit | System-level audit records |
| AU.L2-3.3.2 | Audit | User accountability through audit trails |
| CA.L2-3.12.1 | Assessment | Compliance posture assessment |
| CA.L2-3.12.3 | Assessment | Continuous monitoring via scheduled scans |
| CM.L2-3.4.1 | Configuration | Baseline configurations (Kensa rules) |
| CM.L2-3.4.2 | Configuration | Security configuration enforcement |
| CM.L2-3.4.5 | Configuration | Access restrictions for configuration changes |
| IA.L2-3.5.1 | Identification | User identification and authentication |
| IA.L2-3.5.2 | Identification | Device authentication (SSH host verification) |
| IA.L2-3.5.3 | Identification | Multi-factor authentication |
| IA.L2-3.5.7 | Identification | Minimum password complexity |
| IA.L2-3.5.8 | Identification | Password reuse prevention |
| IA.L2-3.5.10 | Identification | Cryptographically-protected passwords |
| MP.L2-3.8.6 | Media Protection | Data encryption at rest |
| RA.L2-3.11.2 | Risk Assessment | Vulnerability scanning |
| RA.L2-3.11.3 | Risk Assessment | Vulnerability remediation |
| SC.L2-3.13.1 | System/Comms | Boundary protection (network segmentation) |
| SC.L2-3.13.8 | System/Comms | Cryptographic mechanisms for CUI |
| SC.L2-3.13.11 | System/Comms | FIPS-validated cryptography |
| SI.L2-3.14.1 | System Integrity | Flaw identification and remediation |
| SI.L2-3.14.6 | System Integrity | System monitoring |

## Compliance Evidence Collection

To generate evidence for an audit:

1. **Access control evidence**: Export user list and role assignments from the Users API
2. **Audit log evidence**: Use the Audit Query API to export logs for the audit period
3. **Scan evidence**: Export compliance scan results showing configuration assessment
4. **Encryption evidence**: Document FIPS mode configuration and cipher suite settings
5. **Monitoring evidence**: Export fleet health and liveness data from the monitoring endpoints

OpenWatch serves the REST API over HTTPS on port 8443. Authenticate with a session
cookie obtained from `/api/v1/auth/login`, or with a Bearer token.

```bash
# Query audit events for a date range
curl "https://localhost:8443/api/v1/audit/events?date_from=2026-01-01&date_to=2026-02-17" \
  -H "Authorization: Bearer $TOKEN" > audit_evidence.json

# Export fleet compliance score
curl https://localhost:8443/api/v1/fleet/score \
  -H "Authorization: Bearer $TOKEN" > fleet_score_evidence.json
```

> Note: dedicated compliance-posture and Kensa-framework export endpoints are pending
> a Go-era rewrite. See `api/openapi.yaml` for the current endpoint surface and `specs/`
> for the behavioral contracts.
