# Compliance Control Mapping

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
| AC-2 | Account Management | User CRUD with RBAC (admin, analyst, viewer) | `backend/app/routes/auth/`, user audit logs |
| AC-3 | Access Enforcement | Role-based route decorators, JWT validation | `backend/app/middleware/`, RBAC decorators |
| AC-6 | Least Privilege | Three-tier role model, default viewer role | `backend/app/models/sql_models.py` (UserRole enum) |
| AC-7 | Unsuccessful Logon Attempts | Rate limiting (100/min per user, 1000/min per IP) | `backend/app/middleware/rate_limiting.py` |
| AC-8 | System Use Notification | Configurable login banner | Frontend login page |
| AC-11 | Session Lock | Inactivity timeout (default 15 min, configurable 1-480) | `backend/app/routes/system/settings.py` (session-timeout) |
| AC-12 | Session Termination | JWT expiration (30 min access, 7 day refresh) | `backend/app/config.py` (jwt settings) |
| AC-17 | Remote Access | SSH with NIST SP 800-57 key validation | `backend/app/services/ssh/` |

### Audit and Accountability (AU)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| AU-2 | Event Logging | Structured audit logging for auth/scan/admin events | `openwatch.audit` logger |
| AU-3 | Content of Audit Records | User, timestamp, action, resource, outcome in JSON | `backend/app/services/infrastructure/audit.py` |
| AU-6 | Audit Record Review | Audit query API with saved queries and exports | `backend/app/routes/compliance/audit.py` |
| AU-9 | Protection of Audit Information | Logs stored in dedicated volume, append-only | `app_logs` Docker volume |
| AU-12 | Audit Record Generation | All API routes generate audit events | Middleware + decorators |

### Configuration Management (CM)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| CM-2 | Baseline Configuration | Aegis YAML rules define expected configurations | `backend/aegis/rules/` (338 rules) |
| CM-3 | Configuration Change Control | Alembic migration tracking, git version control | `backend/alembic/versions/` |
| CM-6 | Configuration Settings | Environment variable validation via Pydantic | `backend/app/config.py` (Settings class) |
| CM-8 | System Component Inventory | Host management with discovery and metadata | `backend/app/services/system_info/` |

### Identification and Authentication (IA)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| IA-2 | Identification and Authentication | JWT-based auth with username/password | `backend/app/routes/auth/login.py` |
| IA-2(1) | MFA for Privileged Accounts | TOTP-based MFA with backup codes | `backend/app/routes/auth/mfa.py` |
| IA-5 | Authenticator Management | Argon2id hashing (64MB, 3 iterations), 12-char minimum | `backend/app/services/auth/` |
| IA-5(1) | Password-Based Authentication | Complexity requirements (upper, lower, digit, special) | `backend/app/config.py` (password policy) |

### Risk Assessment (RA)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| RA-5 | Vulnerability Monitoring | Automated compliance scanning via Aegis | `backend/app/plugins/aegis/` |
| RA-5(2) | Update Vulnerabilities | Aegis rule updates via plugin updater | `backend/app/plugins/aegis/updater.py` |

### System and Communications Protection (SC)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| SC-8 | Transmission Confidentiality | TLS 1.2/1.3 for all connections | `docker/frontend/nginx.conf` |
| SC-8(1) | Cryptographic Protection | FIPS-approved cipher suites | `backend/app/config.py` (FIPS_TLS_CIPHERS) |
| SC-10 | Network Disconnect | Configurable session timeout | Session timeout API |
| SC-12 | Cryptographic Key Establishment | AES-256-GCM with environment-sourced keys | `backend/app/encryption/` |
| SC-13 | Cryptographic Protection | FIPS 140-2 mode (RHEL 9 validated OpenSSL) | `OPENWATCH_FIPS_MODE` config |
| SC-23 | Session Authenticity | JWT with RS256 (RSA-2048), HttpOnly cookies | Auth middleware |
| SC-28 | Protection of Information at Rest | AES-256-GCM encryption for credentials | `backend/app/encryption/encryption_service.py` |

### System and Information Integrity (SI)

| Control | Title | OpenWatch Implementation | Evidence |
|---------|-------|-------------------------|----------|
| SI-2 | Flaw Remediation | Python 3.12+ (security support through 2028-10) | `docker/Dockerfile.backend` |
| SI-4 | System Monitoring | Prometheus metrics, Grafana dashboards, health checks | `monitoring/`, health endpoints |
| SI-10 | Information Input Validation | Pydantic models at API boundary, SQL Builders | Schemas in `backend/app/schemas/` |

## CIS Controls v8 Mapping

| CIS Control | Title | OpenWatch Implementation |
|-------------|-------|-------------------------|
| 1.1 | Enterprise Asset Inventory | Host management with system info collection |
| 2.1 | Software Inventory | Server intelligence (package collection) |
| 3.3 | Data Encryption | AES-256-GCM at rest, TLS 1.2+ in transit |
| 4.1 | Secure Configuration | Aegis compliance scanning (338 rules) |
| 4.2 | Baseline Network Configuration | Network discovery and topology mapping |
| 5.2 | Unique Passwords | Argon2id hashing, 12-char minimum, complexity enforced |
| 5.4 | MFA | TOTP-based MFA with backup codes |
| 6.1 | Audit Log Management | Structured JSON audit logs, audit query API |
| 6.3 | Centralized Log Collection | JSON logging, configurable log aggregation |
| 8.2 | Audit Logging | All authentication and authorization events logged |
| 8.5 | Access Control Logs | JWT validation events, RBAC enforcement logged |
| 8.11 | Audit Log Retention | Configurable retention, export to CSV/JSON/PDF |
| 9.1 | Email Security | SMTP TLS for notifications |
| 10.1 | Anti-Malware | File upload validation, no executable uploads |
| 13.1 | Network Monitoring | Health check endpoints, Prometheus metrics |
| 16.1 | Application Security | Pydantic input validation, SQL Builders (no raw SQL) |
| 16.9 | Security Headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options |
| 16.11 | Web Application Firewalls | Nginx rate limiting, request size limits |

## CMMC Level 2 Practice Mapping

| Practice | Domain | OpenWatch Implementation |
|----------|--------|-------------------------|
| AC.L2-3.1.1 | Access Control | RBAC with three-tier role model |
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
| CM.L2-3.4.1 | Configuration | Baseline configurations (Aegis rules) |
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
5. **Monitoring evidence**: Export Grafana dashboard screenshots and Prometheus alert history

```bash
# Export audit logs for a date range
curl -X POST http://localhost:8000/api/compliance/audit/exports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "csv", "date_from": "2026-01-01", "date_to": "2026-02-17"}'

# Export compliance posture
curl http://localhost:8000/api/compliance/posture \
  -H "Authorization: Bearer $TOKEN" > posture_evidence.json

# List frameworks and rules
curl http://localhost:8000/api/scans/aegis/frameworks \
  -H "Authorization: Bearer $TOKEN" > frameworks_evidence.json
```
