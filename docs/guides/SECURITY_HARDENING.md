# OpenWatch Security Hardening Guide

**Last Updated**: 2026-02-17
**Applies To**: OpenWatch v1.9.0+
**Audience**: System Administrators, Security Engineers, Compliance Officers

---

## Table of Contents

1. [Overview](#1-overview)
2. [Network Security](#2-network-security)
3. [TLS Configuration](#3-tls-configuration)
4. [Security Headers](#4-security-headers)
5. [Authentication Hardening](#5-authentication-hardening)
6. [Role-Based Access Control (RBAC)](#6-role-based-access-control-rbac)
7. [Rate Limiting](#7-rate-limiting)
8. [Audit Logging](#8-audit-logging)
9. [Secret Management](#9-secret-management)
10. [FIPS 140-2 Compliance](#10-fips-140-2-compliance)
11. [Container Security](#11-container-security)
12. [Input Validation](#12-input-validation)
13. [Production Security Checklist](#13-production-security-checklist)

---

## 1. Overview

OpenWatch is built with a security-first architecture. Every layer of the platform -- from container images to API endpoints -- is designed to meet the security requirements of regulated environments. The platform follows defense-in-depth principles, applying multiple overlapping security controls so that the failure of any single control does not compromise the system.

### Design Principles

- **Defense-in-Depth**: Security controls are layered at the network, transport, application, and data levels. No single control is solely responsible for protecting a resource.
- **Principle of Least Privilege**: Containers run as non-root users, RBAC restricts API access to the minimum required role, and database credentials are scoped to the OpenWatch application.
- **Secure by Default**: FIPS mode is enabled in production container images, HTTPS is required, and all secrets must be provided via environment variables.
- **Zero Trust**: Every API request is authenticated and authorized. Internal service communication occurs over an isolated Docker network.

### Compliance Targets

OpenWatch aligns its security controls with the following frameworks:

| Framework | Scope | Key Controls |
|-----------|-------|--------------|
| **FedRAMP Moderate** | Federal cloud authorization | NIST SP 800-53 Moderate baseline, FIPS 140-2 cryptography, continuous monitoring |
| **CMMC Level 2** | DoD contractor cybersecurity | 110 practices from NIST SP 800-171 |
| **NIST SP 800-53 Rev 5** | Federal information systems | AC (Access Control), AU (Audit), IA (Authentication), SC (System/Communications), SI (System Integrity) |
| **ISO 27001:2022** | Information security management | A.8 (Asset Management), A.9 (Access Control), A.10 (Cryptography), A.12 (Operations Security) |
| **OWASP Top 10 (2021)** | Web application security | All 10 categories addressed in application code |
| **NIST SP 800-218 (SSDF)** | Secure development lifecycle | Automated security testing, code review, vulnerability management |

### Reference Files

| File | Purpose |
|------|---------|
| `backend/app/config.py` | Application settings, FIPS ciphers, security headers |
| `docker/frontend/nginx.conf` | Nginx TLS and header configuration |
| `context/SECURITY_BEST_PRACTICES.md` | Cryptography, JWT, rate limiting patterns |
| `context/SECURITY_STANDARDS_COMPLIANCE.md` | Framework control mappings |
| `docker-compose.yml` | Network isolation, container configuration |
| `docker/Dockerfile.backend` | Backend container security |
| `docker/Dockerfile.frontend` | Frontend container security |
| `.pre-commit-config.yaml` | Secret scanning, security linting |

---

## 2. Network Security

OpenWatch uses Docker network isolation to restrict communication between services. All containers are attached to a dedicated bridge network, and only the ports required for external access are exposed to the host.

### Docker Network Isolation

The `docker-compose.yml` defines an isolated bridge network with a dedicated subnet:

```yaml
networks:
  openwatch-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

All OpenWatch services (database, redis, backend, worker, celery-beat, frontend) communicate exclusively over this internal network. Containers resolve each other by service name (e.g., `database`, `redis`), and traffic between them never traverses the host network stack.

### Port Exposure

Only the minimum required ports are exposed to the host:

| Service | Internal Port | Host Binding | Purpose |
|---------|---------------|--------------|---------|
| PostgreSQL | 5432 | `127.0.0.1:5432` | Database (localhost only) |
| Backend API | 8000 | `0.0.0.0:8000` | FastAPI application |
| Frontend | 80/443 | `0.0.0.0:3000` | Nginx reverse proxy |
| Redis | 6379 | Not exposed | Internal only |
| Celery Worker | N/A | Not exposed | Internal only |
| Celery Beat | N/A | Not exposed | Internal only |

### PostgreSQL Binding

PostgreSQL is bound exclusively to the loopback interface, preventing direct access from external networks:

```yaml
database:
  image: postgres:15.14-alpine
  ports:
    - "127.0.0.1:5432:5432"
```

This means only processes on the Docker host itself (or containers on the `openwatch-network`) can reach the database. Remote database access from outside the host is blocked.

### Hardening Recommendations

- In production, remove the PostgreSQL port mapping entirely. The backend connects via the internal Docker network (`database:5432`), so the host binding is only needed for local debugging.
- If Redis must be accessible outside the container network, bind it to `127.0.0.1` like PostgreSQL.
- Use firewall rules (iptables/nftables) on the host to restrict access to exposed ports (8000, 3000) to authorized networks only.

---

## 3. TLS Configuration

OpenWatch enforces TLS for all external communication. The Nginx frontend proxy handles TLS termination with a configuration that restricts protocol versions and cipher suites to those approved for federal use.

### Nginx SSL Settings

From `docker/frontend/nginx.conf`:

```nginx
# SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

Key points:

- **TLSv1.2 and TLSv1.3 only**: TLS 1.0 and 1.1 are disabled. These older protocols have known vulnerabilities and are prohibited by NIST SP 800-52 Rev 2.
- **Server cipher preference**: The server selects the cipher suite, not the client. This prevents downgrade attacks where a client negotiates a weaker cipher.
- **Session tickets disabled**: `ssl_session_tickets off` prevents session ticket key compromise from enabling retrospective decryption of past sessions.
- **OCSP stapling enabled**: The server fetches and caches OCSP responses, reducing client-side latency and preventing OCSP responder tracking of client connections.
- **Nginx version hidden**: `server_tokens off` suppresses the Nginx version in HTTP response headers and error pages.

### FIPS-Approved Cipher Suites

The backend defines FIPS-approved cipher suites in `backend/app/config.py` for use in application-level TLS (database connections, Redis, outbound API calls):

```python
FIPS_TLS_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
]
```

All listed ciphers use AES-GCM authenticated encryption with SHA-256 or SHA-384 for message authentication. These ciphers are approved under NIST SP 800-52 Rev 2 and FIPS 140-2.

### Certificate Setup

TLS certificates and private keys are stored in the `security/` directory and mounted into containers as read-only volumes:

```yaml
# docker-compose.yml
backend:
  volumes:
    - ./security/certs:/openwatch/security/certs:ro
    - ./security/keys:/openwatch/security/keys

frontend:
  volumes:
    - ./security/certs/frontend.crt:/etc/ssl/certs/frontend.crt:ro
    - ./security/keys/frontend.key:/etc/ssl/private/frontend.key:ro
```

| Path | Contents | Permissions |
|------|----------|-------------|
| `security/certs/` | TLS certificates (public) | Read-only mount (`:ro`) |
| `security/keys/` | Private keys | `700` (owner only, set in Dockerfile) |
| `security/certs/frontend.crt` | Frontend TLS certificate | Read-only mount |
| `security/keys/frontend.key` | Frontend TLS private key | Read-only mount |

### Database SSL

The backend supports SSL connections to PostgreSQL:

```python
# backend/app/config.py
database_ssl_mode: str = "require"
database_ssl_cert: Optional[str] = None
database_ssl_key: Optional[str] = None
database_ssl_ca: Optional[str] = None
```

In production, set `database_ssl_mode` to `verify-full` and provide the CA certificate to prevent man-in-the-middle attacks on the database connection.

### Redis SSL

Redis SSL is supported but disabled by default for Docker development:

```python
# backend/app/config.py
redis_ssl: bool = False
redis_ssl_cert: Optional[str] = None
redis_ssl_key: Optional[str] = None
redis_ssl_ca: Optional[str] = None
```

Enable Redis SSL in production by setting `OPENWATCH_REDIS_SSL=true` and providing the certificate paths.

---

## 4. Security Headers

OpenWatch applies security headers at two layers: the Nginx reverse proxy (frontend) and the FastAPI middleware (backend API). This provides defense-in-depth -- even if one layer is bypassed, the other still enforces header policies.

### Nginx Security Headers

From `docker/frontend/nginx.conf`:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://localhost:8000; frame-ancestors 'none';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Backend Security Headers

From `backend/app/config.py`:

```python
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}
```

### Header Comparison

| Header | Nginx (Frontend) | Backend (API) | Notes |
|--------|-------------------|---------------|-------|
| X-Frame-Options | `SAMEORIGIN` | `DENY` | Backend is stricter -- API responses should never be framed. Nginx allows same-origin framing for the frontend UI. |
| X-Content-Type-Options | `nosniff` | `nosniff` | Prevents MIME-type sniffing attacks |
| X-XSS-Protection | `1; mode=block` | `1; mode=block` | Legacy XSS filter (modern CSP is the primary defense) |
| HSTS | `max-age=31536000; includeSubDomains` | `max-age=31536000; includeSubDomains` | Forces HTTPS for 1 year, includes subdomains |
| Referrer-Policy | `strict-origin-when-cross-origin` | `strict-origin-when-cross-origin` | Sends origin only for cross-origin requests |
| Permissions-Policy | `geolocation=(), microphone=(), camera=()` | `geolocation=(), microphone=(), camera=()` | Disables browser APIs not used by OpenWatch |

### Content Security Policy Differences

The frontend CSP is slightly more permissive than the backend CSP because it must support the React single-page application:

| Directive | Nginx (Frontend) | Backend (API) |
|-----------|-------------------|---------------|
| `script-src` | `'self' 'unsafe-inline' 'unsafe-eval'` | `'self' 'unsafe-inline'` |
| `img-src` | `'self' data: https:` | `'self' data:` |
| `connect-src` | `'self' https://localhost:8000` | `'self'` |
| `frame-ancestors` | `'none'` | Not set (uses X-Frame-Options) |
| `frame-src` | Not set | `'none'` |
| `object-src` | Not set | `'none'` |

The frontend allows `unsafe-eval` for React development tooling and `connect-src https://localhost:8000` for API calls. In production, update `connect-src` to the actual API domain.

---

## 5. Authentication Hardening

### Password Hashing (Argon2id)

OpenWatch uses Argon2id for password hashing. Argon2id is a memory-hard, side-channel-resistant algorithm that is resistant to both GPU-based and timing attacks.

Configuration:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Algorithm | Argon2id | Hybrid of Argon2i (side-channel resistant) and Argon2d (GPU resistant) |
| Memory cost | 64 MB (65536 KB) | Makes GPU/ASIC attacks prohibitively expensive |
| Time cost | 3 iterations | Increases computation time per hash |
| Parallelism | 1 | Single-threaded to prevent parallel attack optimization |

```python
from app.auth import pwd_context

# Hash a password
hashed = pwd_context.hash("user_password")

# Verify a password
is_valid = pwd_context.verify("user_password", hashed)
```

### Password Policy

Default password policy settings (configurable by administrators):

| Setting | Default Value | Configuration |
|---------|---------------|---------------|
| Minimum length | 12 characters | `minimum_password_length` in security policy |
| Complexity required | Yes | `require_complex_passwords` in security policy |
| Uppercase required | Yes (when complexity enabled) | At least one uppercase letter |
| Lowercase required | Yes (when complexity enabled) | At least one lowercase letter |
| Digit required | Yes (when complexity enabled) | At least one digit |
| Special character required | Yes (when complexity enabled) | At least one special character |

Password validation is enforced in `backend/app/services/auth/validation.py`. If complexity is disabled, the minimum length should be increased to at least 16 characters.

### JWT Configuration

OpenWatch uses RS256 (RSA-2048 + SHA-256) for JWT signing, which is a FIPS-approved algorithm.

```python
# backend/app/config.py
algorithm: str = "RS256"
access_token_expire_minutes: int = 30
refresh_token_expire_days: int = 7
```

| Token Type | Default Lifetime | Behavior |
|------------|------------------|----------|
| Access token | 30 minutes | Short-lived, used for API authentication |
| Refresh token | 7 days | Rotated on each use to prevent token replay |

Token creation and verification:

```python
from app.core.security import create_access_token, verify_token
from datetime import timedelta

token = create_access_token(
    data={"sub": str(user.id), "role": user.role},
    expires_delta=timedelta(minutes=30)
)
payload = verify_token(token)
```

### Session Timeout

OpenWatch enforces inactivity-based session timeouts to comply with NIST SP 800-53 AC-11 and FedRAMP SC-10:

| Setting | Default | Range |
|---------|---------|-------|
| Inactivity timeout | 15 minutes | 1 - 480 minutes (configurable by admin) |

The frontend `ActivityTracker` monitors user activity (mouse, keyboard, scroll) and the `SessionManager` component displays a warning before the session expires.

---

## 6. Role-Based Access Control (RBAC)

OpenWatch implements permission-based RBAC. Each role maps to a set of granular permissions, and every protected API endpoint requires a specific role or permission via decorators.

### Role Hierarchy

Roles are defined in `backend/app/rbac.py`:

| Role | Purpose | Access Level |
|------|---------|--------------|
| `GUEST` | Default minimal access | Read-only on limited resources |
| `AUDITOR` | External audit support | Read-only on hosts, scans, compliance, and reports |
| `COMPLIANCE_OFFICER` | Compliance reporting | Read-only plus compliance export |
| `SECURITY_ANALYST` | Day-to-day operations | View, scan execution, host management |
| `SECURITY_ADMIN` | Full administrative access | User management, configuration, all operations |
| `SUPER_ADMIN` | System-level access | All permissions including system configuration |

The `AUDITOR` role is intentionally restricted to read-only access. Auditors can view hosts, scans, compliance results, and reports but cannot modify any data or trigger scans.

### Enforcing RBAC

Every protected endpoint must use the `@require_role()` or `@require_permission()` decorator:

```python
from app.rbac import require_role, require_permission, UserRole, Permission

# Require specific roles (list of allowed roles)
@router.get("/api/scans")
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def list_scans(current_user=Depends(get_current_user)):
    ...

# Require a specific permission
@router.delete("/api/users/{user_id}")
@require_permission(Permission.USER_DELETE)
async def delete_user(user_id: UUID, current_user=Depends(get_current_user)):
    ...

# Convenience decorators
@require_admin()          # SUPER_ADMIN or SECURITY_ADMIN
@require_super_admin()    # SUPER_ADMIN only
@require_analyst_or_above()  # SUPER_ADMIN, SECURITY_ADMIN, or SECURITY_ANALYST
```

### Implementation Notes

- Endpoints without RBAC decorators are a security vulnerability. Code review must verify that every route handler has appropriate authorization.
- The `current_user` dependency is injected via FastAPI's dependency injection and validated from the JWT token.
- Role checks happen at the decorator level before the route handler executes, ensuring unauthorized requests are rejected early.

---

## 7. Rate Limiting

OpenWatch applies rate limiting to prevent brute-force attacks and API abuse.

| Scope | Limit | Purpose |
|-------|-------|---------|
| Per user | 100 requests/minute | Prevents individual account abuse |
| Per IP | 1000 requests/minute | Prevents distributed attacks from a single source |
| Auth endpoints | Stricter limits | Mitigates credential brute-force attempts |

Rate limiting on authentication endpoints is critical. Failed login attempts should be tracked and subject to lower thresholds than general API traffic. When a rate limit is exceeded, the server returns HTTP 429 (Too Many Requests) with a `Retry-After` header.

### Configuration Recommendations

- Set auth endpoint limits to 10 requests/minute per IP to make brute-force attacks impractical.
- Log all rate limit violations to the audit log for security monitoring.
- Consider implementing progressive delays (exponential backoff) after repeated failed authentication attempts.

---

## 8. Audit Logging

OpenWatch logs all security-relevant events via the dedicated `openwatch.audit` logger. Audit logs are stored separately from application logs to support security monitoring and compliance evidence collection.

### Configuration

```python
# backend/app/config.py
audit_log_file: str = "/openwatch/logs/audit.log"
```

The audit log file is stored at `/openwatch/logs/audit.log` inside the container. The `/openwatch/logs` directory is backed by a Docker volume (`app_logs`) for persistence across container restarts.

### Logger Usage

```python
import logging

audit_logger = logging.getLogger("openwatch.audit")

# Authentication success
audit_logger.info("SECURITY_AUTH_SUCCESS", extra={
    "user_id": str(user.id),
    "ip_address": request.client.host,
})

# Authentication failure
audit_logger.warning("SECURITY_AUTH_FAILURE", extra={
    "username": attempted_username,
    "ip_address": request.client.host,
    "reason": "invalid_password",
})
```

### Events to Log

The following events must be logged per NIST SP 800-53 AU-2:

| Category | Events |
|----------|--------|
| Authentication | Login success, login failure, logout, token refresh, MFA challenge/response |
| Authorization | Access denied (insufficient role/permission), privilege escalation attempts |
| Privilege changes | Role assignment, role removal, permission grants, user creation/deletion |
| Data access | Sensitive data reads (credentials, SSH keys, encryption keys), scan result exports |
| Configuration changes | Security policy updates, RBAC changes, threshold updates, scheduler configuration |
| Scan operations | Scan initiated, scan completed, scan failed, exception requested/approved/rejected |
| System events | Application startup/shutdown, health check failures, rate limit violations |

### Log Format Recommendations

- Include a timestamp (ISO 8601, UTC), event type, user ID, source IP, and a description for every audit entry.
- Never log sensitive data (passwords, tokens, private keys) in audit records.
- Forward audit logs to a SIEM (Security Information and Event Management) system for real-time alerting and long-term retention.
- Set retention policies appropriate to your compliance framework (typically 1 year minimum for FedRAMP).

---

## 9. Secret Management

All secrets in OpenWatch are provided via environment variables prefixed with `OPENWATCH_`. No secrets are hardcoded in source code, configuration files, or container images.

### Required Secrets

| Environment Variable | Purpose | Minimum Requirements |
|----------------------|---------|----------------------|
| `OPENWATCH_SECRET_KEY` | JWT signing and session security | At least 32 characters (validated at startup) |
| `OPENWATCH_MASTER_KEY` | AES-256-GCM encryption key for credential storage | At least 32 characters (validated at startup) |
| `OPENWATCH_ENCRYPTION_KEY` | Additional encryption operations | Provided at deployment |
| `POSTGRES_PASSWORD` | PostgreSQL database authentication | Strong random password |
| `REDIS_PASSWORD` | Redis authentication (`--requirepass`) | Strong random password |

### Validation at Startup

The `Settings` class in `backend/app/config.py` validates secret strength on application startup:

```python
@validator("secret_key")
def secret_key_must_be_strong(cls, v: str) -> str:
    if len(v) < 32:
        raise ValueError("Secret key must be at least 32 characters long")
    return v

@validator("master_key")
def master_key_must_be_strong(cls, v: str) -> str:
    if len(v) < 32:
        raise ValueError("Master key must be at least 32 characters long")
    return v
```

If either key is shorter than 32 characters, the application will refuse to start.

### Data Encryption

Sensitive data at rest (SSH credentials, API keys, private keys) is encrypted using AES-256-GCM via the `EncryptionService`:

```python
from app.encryption.encryption_service import EncryptionService

enc_service = EncryptionService()
encrypted = await enc_service.encrypt_data("sensitive_value")
decrypted = await enc_service.decrypt_data(encrypted)
```

The master key (`OPENWATCH_MASTER_KEY`) is used to derive the encryption key. Never store plaintext passwords, API keys, SSH private keys, or tokens in the database.

### Secret Detection in Source Code

The `.pre-commit-config.yaml` includes the `detect-secrets` hook from Yelp to prevent accidental secret commits:

```yaml
- repo: https://github.com/Yelp/detect-secrets
  rev: v1.5.0
  hooks:
    - id: detect-secrets
      args: ['--baseline', '.secrets.baseline']
      exclude: ^(package-lock\.json|.*\.lock)$
```

This hook scans all staged files for patterns that resemble secrets (API keys, passwords, tokens) and blocks the commit if any are detected. The `.secrets.baseline` file tracks known false positives.

Additionally, the `detect-private-key` hook from `pre-commit-hooks` checks for accidentally committed SSH private keys.

### Recommendations

- Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) in production rather than plain environment variables.
- Rotate `OPENWATCH_SECRET_KEY` and `OPENWATCH_MASTER_KEY` periodically. The application supports key rotation without downtime.
- Generate secrets with a cryptographically secure random generator: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
- Never pass secrets via command-line arguments (visible in process listings).

---

## 10. FIPS 140-2 Compliance

OpenWatch supports FIPS 140-2 mode for environments that require NIST-validated cryptographic modules. When enabled, all cryptographic operations use FIPS-validated implementations from the underlying operating system.

### Enabling FIPS Mode

Set the environment variable in your deployment:

```bash
OPENWATCH_FIPS_MODE=true
```

In the production Dockerfile, FIPS mode is enabled by default:

```dockerfile
# docker/Dockerfile.backend
ENV OPENWATCH_FIPS_MODE=true

# Enable FIPS mode in the OS
RUN fips-mode-setup --enable || echo "FIPS mode setup completed"
```

Note: The development `docker-compose.yml` sets `OPENWATCH_FIPS_MODE=false` for local development convenience. Production deployments must override this to `true`.

### FIPS Cryptographic Stack

| Component | Implementation | FIPS Status |
|-----------|----------------|-------------|
| Base OS | Red Hat UBI9 (ubi:9.7) | FIPS-validated OpenSSL from RHEL 9 |
| Python | 3.12.1 on UBI9 | Uses system OpenSSL for crypto operations |
| Password hashing | Argon2id | FIPS-compatible (memory-hard KDF) |
| Data encryption | AES-256-GCM | FIPS-approved (NIST SP 800-38D) |
| JWT signing | RS256 (RSA-2048 + SHA-256) | FIPS-approved |
| TLS cipher suites | See `FIPS_TLS_CIPHERS` list | All FIPS-approved (AES-GCM with ECDHE/DHE) |

### FIPS Cipher Suites

When FIPS mode is enabled, only the following cipher suites are permitted for TLS connections:

```python
FIPS_TLS_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",       # TLS 1.3
    "TLS_AES_128_GCM_SHA256",       # TLS 1.3
    "ECDHE-RSA-AES256-GCM-SHA384",  # TLS 1.2
    "ECDHE-RSA-AES128-GCM-SHA256",  # TLS 1.2
    "DHE-RSA-AES256-GCM-SHA384",    # TLS 1.2
    "DHE-RSA-AES128-GCM-SHA256",    # TLS 1.2
]
```

### Validation

OpenWatch includes a FIPS validation script:

```bash
python3 backend/scripts/validate_fips_compliance.py
```

This script verifies that the FIPS cryptographic module is active and that all cryptographic operations use FIPS-approved algorithms.

---

## 11. Container Security

OpenWatch containers are built with security as a primary requirement. Both the backend and frontend containers follow container security best practices.

### Non-Root User

Both containers create and run as a dedicated `openwatch` user with a high UID to avoid collisions with system accounts:

**Backend** (`docker/Dockerfile.backend`):

```dockerfile
RUN useradd -m -u 10001 openwatch && \
    mkdir -p /openwatch /openwatch/data /openwatch/logs /openwatch/security && \
    chown -R openwatch:openwatch /openwatch

# ... (build steps as root) ...

USER openwatch
```

**Frontend** (`docker/Dockerfile.frontend`):

```dockerfile
RUN addgroup -g 10002 openwatch && \
    adduser -D -u 10002 -G openwatch openwatch

# ... (build steps as root) ...

USER openwatch
```

The `USER` directive is the last root-level command in each Dockerfile. All subsequent commands (including `CMD`) run as the non-root user.

### File Permissions

The backend Dockerfile sets restrictive permissions on sensitive directories:

```dockerfile
RUN chown -R openwatch:openwatch /openwatch && \
    chmod -R 755 /openwatch && \
    chmod -R 700 /openwatch/security
```

| Directory | Permissions | Contents |
|-----------|-------------|----------|
| `/openwatch/` | 755 (rwxr-xr-x) | Application code, data |
| `/openwatch/security/` | 700 (rwx------) | TLS certificates, SSH keys, encryption keys |
| `/openwatch/logs/` | 755 (rwxr-xr-x) | Application and audit logs |

### Read-Only Certificate Mounts

Certificates are mounted as read-only volumes to prevent runtime modification:

```yaml
volumes:
  - ./security/certs:/openwatch/security/certs:ro
```

### Minimal Base Images

| Container | Base Image | Rationale |
|-----------|-----------|-----------|
| Backend | `registry.access.redhat.com/ubi9/ubi:9.7` | FIPS-validated OpenSSL, Red Hat security patches |
| Frontend | `nginx:1.29.5-alpine` | Minimal Alpine-based image for static file serving |
| PostgreSQL | `postgres:15.14-alpine` | Minimal Alpine-based database image |
| Redis | `redis:7.4.6-alpine` | Minimal Alpine-based cache image |

### Health Checks

Every container includes a health check for orchestration and monitoring:

```dockerfile
# Backend
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Frontend
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f https://localhost/health || exit 1
```

Health checks verify database connectivity, Redis connectivity, FIPS status, and available disk space.

### Container Restart Policy

All containers use `restart: unless-stopped` to automatically recover from crashes while respecting intentional shutdowns.

---

## 12. Input Validation

OpenWatch validates all input at multiple layers to prevent injection attacks.

### Pydantic at the API Boundary

Every API endpoint uses Pydantic schemas for request validation. Invalid input is rejected before it reaches business logic:

```python
from pydantic import BaseModel, Field, validator
from uuid import UUID

class ScanCreateRequest(BaseModel):
    host_id: UUID
    profile_id: str = Field(..., min_length=1, max_length=500)
    timeout: int = Field(default=3600, ge=60, le=86400)

    @validator("profile_id")
    def validate_profile_id(cls, v):
        if not v.startswith("xccdf_"):
            raise ValueError("Profile ID must start with 'xccdf_'")
        return v
```

Pydantic enforces type coercion, length constraints, range validation, and custom validators. UUID fields are automatically validated for format correctness.

### SQL Injection Prevention (QueryBuilder)

All PostgreSQL queries use the `QueryBuilder` pattern, which generates parameterized SQL. Direct string interpolation into SQL is prohibited:

```python
# CORRECT - Parameterized via QueryBuilder
from app.utils.query_builder import QueryBuilder

builder = (QueryBuilder("hosts h")
    .where("h.status = :status", "online", "status")
    .search("h.hostname", user_input)
)
query, params = builder.build()
result = await session.execute(text(query), params)

# WRONG - SQL injection vulnerability
query = f"SELECT * FROM hosts WHERE status = '{user_input}'"
```

QueryBuilder adoption is at 100% across the codebase. The `InsertBuilder`, `UpdateBuilder`, and `DeleteBuilder` classes provide the same parameterization for write operations. `UpdateBuilder` and `DeleteBuilder` require a `WHERE` clause by default; using `build_unsafe()` (no WHERE) requires explicit opt-in.

### Command Injection Prevention

All subprocess calls use argument lists instead of shell string interpolation:

```python
import subprocess

# CORRECT - Argument list prevents injection
result = subprocess.run(
    ["oscap", "xccdf", "eval", "--profile", profile_id, datastream_path],
    shell=False,
    capture_output=True,
    text=True,
)

# WRONG - shell=True enables command injection
result = subprocess.run(
    f"oscap xccdf eval --profile {profile_id} {datastream_path}",
    shell=True,
    capture_output=True,
)
```

The use of `shell=True` is prohibited unless inputs are rigorously validated and there is no alternative. The `bandit` security scanner (configured in `.pre-commit-config.yaml`) flags `shell=True` usage during pre-commit checks.

### CORS Validation

Allowed CORS origins are validated at startup to ensure HTTPS is used (except for localhost development):

```python
@validator("allowed_origins")
def validate_origins(cls, v: List[str]) -> List[str]:
    for origin in v:
        if not origin.startswith(("https://", "http://localhost")):
            raise ValueError("All origins must use HTTPS (except localhost)")
    return v
```

### File Upload Restrictions

File uploads are constrained by type and size:

```python
max_upload_size: int = 100 * 1024 * 1024  # 100MB
allowed_file_types: List[str] = [".xml", ".zip", ".bz2", ".gz"]
```

Nginx also enforces a `client_max_body_size 10M` limit at the reverse proxy layer.

---

## 13. Production Security Checklist

Use this checklist before deploying OpenWatch to a production environment. Each item corresponds to a security control described in the sections above.

### Network Security

- [ ] Docker network uses a dedicated subnet (`172.20.0.0/16`)
- [ ] PostgreSQL port (`5432`) is bound to `127.0.0.1` or not exposed to the host at all
- [ ] Redis port (`6379`) is not exposed to the host
- [ ] Host firewall restricts access to exposed ports (8000, 3000/443) to authorized networks
- [ ] No unnecessary ports are exposed in `docker-compose.yml`

### TLS Configuration

- [ ] TLS certificates are installed in `security/certs/` and `security/keys/`
- [ ] Nginx is configured with `ssl_protocols TLSv1.2 TLSv1.3` only
- [ ] `ssl_session_tickets off` is set
- [ ] `ssl_stapling on` and `ssl_stapling_verify on` are set
- [ ] `server_tokens off` is set to hide Nginx version
- [ ] Backend `OPENWATCH_REQUIRE_HTTPS` is set to `true`
- [ ] Database SSL mode is set to `verify-full` with CA certificate provided
- [ ] Redis SSL is enabled (`OPENWATCH_REDIS_SSL=true`) with certificates

### Security Headers

- [ ] All security headers are present in Nginx configuration
- [ ] Backend `SECURITY_HEADERS` dictionary is applied via middleware
- [ ] HSTS `max-age` is at least `31536000` (1 year)
- [ ] CSP `connect-src` is updated to the production API domain (not `localhost`)
- [ ] `X-Frame-Options` is set (`SAMEORIGIN` for frontend, `DENY` for API)

### Authentication

- [ ] `OPENWATCH_SECRET_KEY` is at least 32 characters, randomly generated
- [ ] `OPENWATCH_MASTER_KEY` is at least 32 characters, randomly generated
- [ ] Access token lifetime is appropriate (default: 30 minutes)
- [ ] Refresh token lifetime is appropriate (default: 7 days)
- [ ] Password policy enforces minimum 12 characters with complexity
- [ ] Session inactivity timeout is configured (default: 15 minutes)
- [ ] Argon2id is the password hashing algorithm (64MB memory, 3 iterations)

### RBAC

- [ ] Every API endpoint has a `@require_role()` or `@require_permission()` decorator
- [ ] Default user role is the least privileged role needed
- [ ] AUDITOR role is confirmed as read-only
- [ ] SUPER_ADMIN accounts are limited to the minimum necessary

### Rate Limiting

- [ ] Per-user rate limit is configured (default: 100 req/min)
- [ ] Per-IP rate limit is configured (default: 1000 req/min)
- [ ] Authentication endpoints have stricter limits
- [ ] Rate limit violations are logged to the audit log

### Audit Logging

- [ ] Audit log file path is configured (`/openwatch/logs/audit.log`)
- [ ] `app_logs` Docker volume is configured for persistence
- [ ] Authentication events (success/failure) are logged
- [ ] Authorization failures are logged
- [ ] Privilege changes are logged
- [ ] Configuration changes are logged
- [ ] Audit logs are forwarded to a SIEM or centralized logging system
- [ ] Log retention policy meets compliance requirements (minimum 1 year for FedRAMP)

### Secret Management

- [ ] All secrets are provided via `OPENWATCH_*` environment variables
- [ ] No secrets are hardcoded in source code or configuration files
- [ ] `detect-secrets` pre-commit hook is installed and active
- [ ] `detect-private-key` pre-commit hook is installed and active
- [ ] `.secrets.baseline` file is maintained and reviewed
- [ ] Secret rotation procedures are documented and tested
- [ ] `POSTGRES_PASSWORD` and `REDIS_PASSWORD` are strong random values

### FIPS 140-2

- [ ] `OPENWATCH_FIPS_MODE` is set to `true` in production
- [ ] Backend container uses Red Hat UBI9 base image with FIPS-validated OpenSSL
- [ ] FIPS validation script passes: `python3 backend/scripts/validate_fips_compliance.py`
- [ ] Only FIPS-approved cipher suites are in use (see `FIPS_TLS_CIPHERS`)
- [ ] JWT signing uses RS256 (RSA-2048 + SHA-256)

### Container Security

- [ ] All containers run as non-root users (`USER openwatch`)
- [ ] Security directory permissions are `700` (owner only)
- [ ] Certificate volumes are mounted as read-only (`:ro`)
- [ ] Container health checks are configured for all services
- [ ] `OPENWATCH_DEBUG` is set to `false` in production
- [ ] Base images are pinned to specific versions (not `latest`)
- [ ] Container images are scanned for vulnerabilities before deployment

### Input Validation

- [ ] All API endpoints use Pydantic schemas for request validation
- [ ] All PostgreSQL queries use QueryBuilder (no raw SQL string interpolation)
- [ ] All subprocess calls use argument lists (`shell=False`)
- [ ] File uploads are restricted by type (`.xml`, `.zip`, `.bz2`, `.gz`) and size (100MB)
- [ ] CORS origins are validated to require HTTPS
- [ ] `bandit` security scanner is configured in pre-commit hooks

### Pre-Commit Security Hooks

- [ ] `detect-secrets` (v1.5.0) with baseline file
- [ ] `detect-private-key` from pre-commit-hooks
- [ ] `bandit` (v1.7.6) security scanner for Python
- [ ] `hadolint` for Dockerfile linting
- [ ] `shellcheck` for shell script safety

---

**End of Security Hardening Guide**
