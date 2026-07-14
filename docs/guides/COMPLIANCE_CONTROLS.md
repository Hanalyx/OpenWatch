# Compliance control mapping

**Last updated:** 2026-07-14 · **Applies to:** OpenWatch v0.5.0 (Go single-binary)

This document maps OpenWatch's security controls to industry frameworks, providing evidence for compliance audits.

## Framework coverage

| Framework | Controls Mapped | Coverage |
|-----------|----------------|----------|
| NIST SP 800-53 Rev 5 | 32 | Moderate baseline |
| CIS Controls v8 | 16 | Implementation Group 2 |
| CMMC Level 2 | 27 | Practice-level mapping |
| FedRAMP Moderate | 32 | Inherited from NIST |

## NIST SP 800-53 control mapping

### Access control (AC)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| AC-2 | Account Management | User CRUD with RBAC (five roles: viewer, auditor, ops_lead, security_admin, admin) | User list from the Users API; user audit events |
| AC-3 | Access Enforcement | Role-based permission checks on each route | `403` denials in the audit log; permission registry served by the API |
| AC-6 | Least Privilege | Five built-in roles (least-privilege viewer baseline) | Role list from `/api/v1/roles` |
| AC-7 | Unsuccessful Logon Attempts | Per-IP sliding-window rate limit on the auth endpoints (login, MFA verify); 429 + Retry-After | `429` responses with `Retry-After`; rate-limit denials in the audit log |
| AC-11 | Session Lock | Inactivity timeout (default 15 minutes, configurable from 5 minutes to 24 hours) | Session-timeout value in the running configuration |
| AC-12 | Session Termination | Session cookie and JWT expiration (30 min access, 7 day refresh) | Token expiry observed on the API; logout audit events |
| AC-17 | Remote Access | SSH with NIST SP 800-57 key validation | Host-key validation behavior on connect |

### Audit and accountability (AU)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| AU-2 | Event Logging | Structured audit events for auth/scan/admin actions | Audit events from `/api/v1/audit/events` |
| AU-3 | Content of Audit Records | User, timestamp, action, resource, outcome | Fields in each record from `/api/v1/audit/events` |
| AU-6 | Audit Record Review | Audit query API (`/api/v1/audit/events`) | Query results from `/api/v1/audit/events` |
| AU-9 | Protection of Audit Information | Audit events stored append-only in PostgreSQL | Append-only audit records in the database |
| AU-12 | Audit Record Generation | API routes generate audit events | Events emitted per action in the audit log |

### Configuration management (CM)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| CM-2 | Baseline Configuration | Kensa YAML rules define expected configurations | Kensa rules (748 rules, Kensa v0.7.6); scan results |
| CM-3 | Configuration Change Control | Database migration tracking, version control | Migration version reported by `openwatch migrate` |
| CM-6 | Configuration Settings | Configuration validation at startup | Output of `openwatch check-config` |
| CM-8 | System Component Inventory | Host management with discovery and metadata | Host list and collected system info from the API |

### Identification and authentication (IA)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| IA-2 | Identification and Authentication | Session cookie and JWT auth with username/password | Login behavior at `/api/v1/auth/login`; auth audit events |
| IA-2(1) | MFA for Privileged Accounts | TOTP-based MFA (no backup/recovery codes) | MFA enrollment status per user; MFA audit events |
| IA-5 | Authenticator Management | Argon2id hashing (64MB, 3 iterations), 8-char minimum (15 for admin) | Password policy enforced at user creation |
| IA-5(1) | Password-Based Authentication | Length-only policy per NIST SP 800-63B (8 chars regular / 15 admin, max 128); no character-class complexity rules; new passwords screened against an embedded common/breached corpus | Password policy enforced at user creation |

### Risk assessment (RA)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| RA-5 | Vulnerability Monitoring | Automated compliance scanning via Kensa | Scan results and posture trend from the API |
| RA-5(2) | Update Vulnerabilities | Kensa rule updates via rule sync | Rule corpus version in the rule browser |

### System and communications protection (SC)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| SC-8 | Transmission Confidentiality | TLS 1.2/1.3 for all connections | HTTPS-only listener on port 8443 |
| SC-8(1) | Cryptographic Protection | The `-fips` build's cryptographic operations run through the FIPS 140-3 crypto module (Go GOFIPS140); TLS cipher-suite selection itself is the Go standard-library default and is not pinned to a FIPS-approved suite list | FIPS mode reported by `openwatch --version` |
| SC-10 | Network Disconnect | Configurable session timeout | Session-timeout value in the running configuration |
| SC-12 | Cryptographic Key Establishment | AES-256-GCM with environment-sourced keys | Key files under `/etc/openwatch/keys/` |
| SC-13 | Cryptographic Protection | FIPS via the Go-native FIPS module | FIPS mode reported by `openwatch --version` |
| SC-23 | Session Authenticity | Session cookie plus JWT, HttpOnly cookies | Cookie attributes observed on the API |
| SC-28 | Protection of Information at Rest | AES-256-GCM encryption for credentials | Secrets redacted in API responses; encrypted at rest in the database |

### System and information integrity (SI)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| SI-2 | Flaw Remediation | Single Go binary built from a maintained Go toolchain | Build metadata from `openwatch --version`; native RPM/DEB packages |
| SI-4 | System Monitoring | Health checks and fleet monitoring endpoints | `/api/v1/health` and fleet liveness responses |
| SI-10 | Information Input Validation | Request validation at the API boundary, parameterized SQL | `400` validation errors on malformed requests |

## CIS Controls v8 mapping

| CIS Control | Title | OpenWatch Implementation |
|-------------|-------|-------------------------|
| 1.1 | Enterprise Asset Inventory | Host management with system info collection |
| 2.1 | Software Inventory | Server intelligence (package collection) |
| 3.3 | Data Encryption | AES-256-GCM at rest, TLS 1.2+ in transit |
| 4.1 | Secure Configuration | Kensa compliance scanning (748 rules, Kensa v0.7.6) |
| 4.2 | Baseline Network Configuration | Network discovery and topology mapping |
| 5.2 | Unique Passwords | Argon2id hashing, 8-char minimum (15 for admin), breached-password screening |
| 5.4 | MFA | TOTP-based MFA (no backup/recovery codes) |
| 6.1 | Audit Log Management | Structured JSON audit logs, audit query API |
| 6.3 | Centralized Log Collection | JSON logging, configurable log aggregation |
| 8.2 | Audit Logging | All authentication and authorization events logged |
| 8.5 | Access Control Logs | JWT validation events, RBAC enforcement logged |
| 8.11 | Audit Log Retention | Configurable retention, export to CSV/JSON |
| 9.1 | Email Security | SMTP TLS for notifications |
| 13.1 | Network Monitoring | Health check endpoints, audit-event queries (no Prometheus endpoint) |
| 16.1 | Application Security | Request validation at the API boundary, parameterized SQL (no raw SQL) |
| 16.9 | Security Headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options |

## CMMC Level 2 practice mapping

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
| IA.L2-3.5.3 | Identification | Multi-factor authentication (TOTP, no backup/recovery codes) |
| IA.L2-3.5.7 | Identification | Minimum password length per NIST SP 800-63B (8 chars regular / 15 admin); no character-class complexity rules |
| IA.L2-3.5.10 | Identification | Cryptographically-protected passwords |
| MP.L2-3.8.6 | Media Protection | Data encryption at rest |
| RA.L2-3.11.2 | Risk Assessment | Vulnerability scanning |
| RA.L2-3.11.3 | Risk Assessment | Vulnerability remediation |
| SC.L2-3.13.1 | System/Comms | Boundary protection (network segmentation) |
| SC.L2-3.13.8 | System/Comms | Cryptographic mechanisms for CUI |
| SC.L2-3.13.11 | System/Comms | FIPS 140-3 cryptography via the Go-native FIPS module |
| SI.L2-3.14.1 | System Integrity | Flaw identification and remediation |
| SI.L2-3.14.6 | System Integrity | System monitoring |

## Compliance evidence collection

To generate evidence for an audit:

1. **Access control evidence**: Export user list and role assignments from the Users API
2. **Audit log evidence**: Use the Audit Query API to export logs for the audit period
3. **Scan evidence**: Export compliance scan results showing configuration assessment
4. **Encryption evidence**: Document FIPS mode configuration (`openwatch --version`); TLS cipher-suite selection is the Go standard-library default and is not separately configurable
5. **Monitoring evidence**: Export fleet health and liveness data from the monitoring endpoints

OpenWatch serves the REST API over HTTPS on port 8443. Authenticate with a session
cookie obtained from `/api/v1/auth/login`, or with a Bearer token.

```bash
# Query audit events for a date range
curl "https://localhost:8443/api/v1/audit/events?since=2026-01-01T00:00:00Z&until=2026-02-17T23:59:59Z" \
  -H "Authorization: Bearer $TOKEN" > audit_evidence.json

# Export fleet compliance score
curl https://localhost:8443/api/v1/fleet/score \
  -H "Authorization: Bearer $TOKEN" > fleet_score_evidence.json
```

> Per-host compliance posture and trend are also available directly:
> `GET /api/v1/hosts/{id}/compliance` and `GET /api/v1/hosts/{id}/compliance/trend`.
> The running binary serves its current API contract at `/api/v1`;
> `GET /api/v1/version` reports the build it came from.
