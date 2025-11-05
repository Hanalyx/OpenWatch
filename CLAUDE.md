# CLAUDE.md - OpenWatch AI Development Guide

> **Purpose**: This file provides comprehensive guidance to AI assistants (Claude Code, GitHub Copilot, etc.) when working with the OpenWatch compliance scanning platform.

**Last Updated**: 2025-11-04
**Working Directory**: `/home/rracine/hanalyx/openwatch/`

---

## 🎯 Project Overview

**OpenWatch** is an enterprise-grade, security-first SCAP (Security Content Automation Protocol) compliance scanning platform designed for:
- FedRAMP compliance environments
- CMMC assessments
- ISO 27001 security controls
- NIST SP 800-53 compliance frameworks
- DOD STIG baseline verification

### Security-First Principles

OpenWatch is built with **security as the primary requirement**, not an afterthought:
- ✅ FIPS 140-2 compliant cryptography
- ✅ Zero-trust architecture
- ✅ Defense-in-depth layering
- ✅ Principle of least privilege
- ✅ Comprehensive audit logging
- ✅ Input validation at all layers
- ✅ Secure by default configuration

---

## 📋 Table of Contents

1. [Security Standards & Compliance](#security-standards--compliance)
2. [Architecture Overview](#architecture-overview)
3. [Modular Code Architecture](#modular-code-architecture)
4. [Code Documentation Standards](#code-documentation-standards)
5. [Development Workflow](#development-workflow)
6. [Code Quality Standards](#code-quality-standards)
7. [Testing Strategy](#testing-strategy)
8. [Common Patterns](#common-patterns)
9. [Security Best Practices](#security-best-practices)
10. [Agentic Coding Principles](#agentic-coding-principles)
11. [Troubleshooting](#troubleshooting)

---

## 🔐 Security Standards & Compliance

### OWASP Top 10 (2021) Compliance

OpenWatch implements controls for all OWASP Top 10 vulnerabilities:

#### A01:2021 - Broken Access Control
- **Control**: Role-Based Access Control (RBAC) with 6 predefined roles
- **Implementation**: `backend/app/middleware/rbac_middleware.py`
- **Verification**: Every endpoint decorated with `@require_role()` or `@require_permission()`
- **Audit**: All access attempts logged to `openwatch.audit` logger

#### A02:2021 - Cryptographic Failures
- **Encryption**: AES-256-GCM only (FIPS 140-2 compliant)
- **Key Derivation**: Argon2id with 64MB memory cost
- **JWT Signing**: RS256 with RSA-2048 keys
- **TLS**: TLS 1.2+ only, strong cipher suites
- **Storage**: All sensitive data encrypted at rest

#### A03:2021 - Injection
- **SQL Injection**: SQLAlchemy ORM with parameterized queries (NEVER raw SQL)
- **Command Injection**: subprocess calls with explicit argument lists (NO shell=True)
- **LDAP Injection**: Input sanitization for LDAP queries
- **XML Injection**: lxml with defusedxml for SCAP content parsing

#### A04:2021 - Insecure Design
- **Threat Modeling**: Documented in `docs/COMPREHENSIVE_SECURITY_AND_CODE_ANALYSIS.md`
- **Secure Defaults**: HTTPS required, authentication mandatory, encryption enabled
- **Rate Limiting**: 100 requests/minute per user, 1000/minute per IP
- **Resource Limits**: File uploads max 100MB, request timeout 30s

#### A05:2021 - Security Misconfiguration
- **Hardening**: FIPS mode enabled in containers
- **Secrets**: NO secrets in code, environment variables only
- **Headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Error Handling**: Generic error messages to clients, detailed logs server-side

#### A06:2021 - Vulnerable Components
- **Scanning**: Dependabot, Trivy, Grype, SonarCloud in CI/CD
- **Updates**: Automated triage system processes 8,756+ alerts
- **Policy**: No components with known HIGH/CRITICAL CVEs
- **Verification**: `docs/SECURITY_UPDATES.md` tracks remediation

#### A07:2021 - Authentication Failures
- **MFA**: TOTP-based 2FA mandatory for admins
- **Password**: Argon2id hashing, 12+ char minimum, complexity rules
- **Session**: JWT with 1-hour expiry, refresh tokens with rotation
- **Brute Force**: Account lockout after 5 failed attempts

#### A08:2021 - Data Integrity Failures
- **Signature Verification**: RSA-PSS signatures for compliance bundles
- **Checksums**: SHA-512 verification for all uploads
- **Immutability**: Compliance rules versioned and immutable
- **Audit Trail**: Complete change history in MongoDB

#### A09:2021 - Logging Failures
- **Coverage**: All authentication, authorization, input validation failures
- **Format**: Structured JSON logs with correlation IDs
- **Protection**: Log injection prevention, PII redaction
- **Retention**: 90 days minimum, configurable retention policy

#### A10:2021 - SSRF
- **URL Validation**: Whitelist-based URL validation
- **Network Segmentation**: Internal services not exposed
- **Webhook Validation**: HMAC signature verification
- **DNS Rebinding**: DNS resolution caching

### NIST SP 800-218 - Secure Software Development Framework (SSDF)

#### PO.1: Define Security Requirements
- **Location**: `docs/COMPREHENSIVE_SECURITY_AND_CODE_ANALYSIS.md`
- **Practice**: Security requirements defined before development
- **Verification**: Security checklists in PR templates

#### PO.2: Implement Secure Design
- **Threat Modeling**: STRIDE methodology applied
- **Architecture**: Defense-in-depth with multiple security layers
- **Patterns**: Centralized authentication, authorization, encryption services

#### PO.3: Secure Development Environment
- **Tool Security**: Only signed, verified tools and dependencies
- **Access Control**: Role-based access to repositories and CI/CD
- **Secrets Management**: No secrets in code or containers

#### PW.1: Secure Code
- **SAST**: Bandit security scanning on every commit
- **Linting**: Black, Flake8, MyPy, ESLint enforce quality
- **Reviews**: All code reviewed before merge

#### PW.2: Manual Code Review
- **Coverage**: 100% of changes reviewed by humans
- **Security Focus**: Dedicated security review checklist
- **Documentation**: Changes documented in commit messages

#### PW.4: Review Code
- **Automated**: CodeQL, SonarCloud, Trivy scans
- **Manual**: Security-focused PR reviews
- **Threshold**: No HIGH/CRITICAL findings allowed

#### PW.7: Review/Analyze Third-Party Software
- **SCA**: Software Composition Analysis with Trivy/Grype
- **Triage**: Automated risk-based triage system
- **Policy**: No known vulnerabilities in production

#### PW.8: Test Code
- **Unit Tests**: Pytest with 80% coverage minimum
- **Integration**: End-to-end Playwright tests
- **Security**: DAST scanning of running application

#### RV.1: Verify Compliance
- **Continuous**: Security scans in CI/CD pipeline
- **Reporting**: Compliance reports generated automatically
- **Audit**: All findings tracked to resolution

### ISO 27001:2022 Controls

OpenWatch implements technical controls from Annex A:

- **A.5.1**: Information Security Policies
- **A.8.1-8.34**: Asset Management and Access Control
- **A.10.1**: Cryptographic Controls (AES-256-GCM, Argon2id, RSA-2048)
- **A.12.1-12.7**: Operations Security (logging, monitoring, backup)
- **A.14.1-14.3**: System Acquisition and Development
- **A.17.1**: Business Continuity (backup, disaster recovery)
- **A.18.1**: Compliance Monitoring

### CMMC Level 2 Compliance

OpenWatch supports CMMC 2.0 Level 2 practices:

- **AC.L2**: Access Control with RBAC
- **AU.L2**: Audit and Accountability (comprehensive logging)
- **IA.L2**: Identification and Authentication (MFA, strong passwords)
- **SC.L2**: System and Communications Protection (TLS, encryption)
- **SI.L2**: System and Information Integrity (input validation, patching)

### FedRAMP Moderate Baseline

Security controls aligned with FedRAMP Moderate requirements:

- **AC-2**: Account Management (user lifecycle)
- **AC-6**: Least Privilege (role-based permissions)
- **AU-2**: Audit Events (comprehensive logging)
- **IA-2**: Identification and Authentication (MFA)
- **SC-13**: Cryptographic Protection (FIPS 140-2)
- **SC-28**: Protection of Information at Rest (AES-256-GCM)

---

## 🏗️ Architecture Overview

### Technology Stack

#### Backend
- **Framework**: FastAPI 0.119.1+ (async-first)
- **Language**: Python 3.9+ with strict type hints
- **Databases**:
  - PostgreSQL 15+ (relational data, SQLAlchemy ORM)
  - MongoDB 7.0+ (document store, Beanie ODM)
  - Redis 7.4+ (cache, message broker)
- **Task Queue**: Celery 5.4+ (async background jobs)
- **Authentication**: JWT (RS256) with RSA-2048 keys
- **Encryption**: cryptography library (FIPS 140-2 compliant)
- **SCAP**: OpenSCAP 1.3.12+

#### Frontend
- **Framework**: React 18+ with TypeScript 5+
- **UI Library**: Material-UI v5 (Material Design 3)
- **State Management**:
  - Redux Toolkit (auth state)
  - TanStack React Query (server state, 5min stale time)
- **Routing**: React Router v6
- **HTTP Client**: Axios with JWT interceptors
- **Charts**: Recharts + Chart.js
- **Terminal**: XTerm.js (for remote shell access)
- **Testing**: Playwright (E2E tests)

#### Infrastructure
- **Container**: Docker / Podman (rootless supported)
- **Orchestration**: Docker Compose
- **Reverse Proxy**: Nginx (TLS termination)
- **Monitoring**: Custom health monitoring with MongoDB storage

### Dual Database Architecture

**CRITICAL**: OpenWatch uses TWO databases for different purposes.

#### PostgreSQL (Relational Data)
**Purpose**: Transactional data requiring ACID guarantees

**Models**: `backend/app/models/`
- **Users**: Authentication, roles, permissions
- **Hosts**: Target systems for scanning
- **Scans**: Scan metadata, status, scheduling
- **Credentials**: Encrypted SSH/system credentials
- **Groups**: Host grouping and organization
- **Webhooks**: Integration with external systems

**Key Pattern**: UUID primary keys (NOT integers!)
```python
# CORRECT
class Host(Base):
    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)

# WRONG - DO NOT USE
class Host(Base):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
```

#### MongoDB (Document Store)
**Purpose**: Large, flexible documents and complex queries

**Collections**: `backend/app/models/mongo_models.py`
- **compliance_rules**: SCAP compliance rules (immutable, versioned)
- **scan_results**: Detailed scan findings and evidence
- **rule_intelligence**: Rule metadata, false positive rates
- **remediation_scripts**: Automated fix scripts
- **health_monitoring**: System health metrics and events

**Key Pattern**: Repository pattern (NO direct MongoDB access!)
```python
# CORRECT - Use repository
from backend.app.repositories.compliance_rule_repository import ComplianceRuleRepository

repo = ComplianceRuleRepository()
rules = await repo.find_by_framework("nist_800_53")

# WRONG - Direct MongoDB access
from backend.app.models.mongo_models import ComplianceRule
rules = await ComplianceRule.find({"framework": "nist_800_53"})
```

### Repository Pattern (MongoDB)

**MANDATORY**: All MongoDB access MUST use repository pattern.

**Base Repository**: `backend/app/repositories/base_repository.py`
- Generic CRUD with type safety
- Automatic performance logging (warns on >1s queries)
- Pagination support
- Aggregation pipeline helpers

**Example Repository**:
```python
from backend.app.repositories.base_repository import BaseRepository
from backend.app.models.mongo_models import ComplianceRule

class ComplianceRuleRepository(BaseRepository[ComplianceRule]):
    async def find_by_severity(self, severity: str) -> List[ComplianceRule]:
        return await self.find_many({"severity": severity})
```

**Benefits**:
- Centralized query logging and monitoring
- Consistent error handling
- Easy to add caching layer
- Testable (mock repositories)
- Performance metrics included

### Authentication & Authorization Flow

```
┌─────────────┐
│   Client    │
│  (Browser)  │
└──────┬──────┘
       │ 1. POST /api/v1/auth/login
       │    {username, password, totp_code}
       ↓
┌──────────────────────────────────────┐
│  FastAPI Backend                     │
│  ┌─────────────────────────────────┐ │
│  │ 1. Validate credentials         │ │
│  │    - Argon2id password verify   │ │
│  │    - TOTP code verify (if MFA)  │ │
│  │ 2. Generate JWT                 │ │
│  │    - Sign with RSA private key  │ │
│  │    - Include user_id, roles     │ │
│  │ 3. Return tokens                │ │
│  │    - Access token (1h expiry)   │ │
│  │    - Refresh token (7d expiry)  │ │
│  └─────────────────────────────────┘ │
└──────┬───────────────────────────────┘
       │ 2. {access_token, refresh_token}
       ↓
┌──────────────┐
│   Client     │
│  localStorage│
│  .setItem(   │
│   'auth_token'│  ← IMPORTANT: Key name is 'auth_token' NOT 'token'
│  )           │
└──────┬───────┘
       │ 3. Subsequent requests
       │    Authorization: Bearer <access_token>
       ↓
┌──────────────────────────────────────┐
│  RBAC Middleware                     │
│  ┌─────────────────────────────────┐ │
│  │ 1. Verify JWT signature         │ │
│  │    - RSA public key validation  │ │
│  │ 2. Check expiration             │ │
│  │ 3. Extract user_id, roles       │ │
│  │ 4. Verify role permissions      │ │
│  │ 5. Log access attempt           │ │
│  └─────────────────────────────────┘ │
└──────┬───────────────────────────────┘
       │ 4. Request with user context
       ↓
┌──────────────┐
│  API Route   │
│  Handler     │
└──────────────┘
```

**CRITICAL localStorage Key**: Frontend uses `auth_token` NOT `token`!

```typescript
// CORRECT
const token = localStorage.getItem('auth_token');

// WRONG
const token = localStorage.getItem('token');
```

### SCAP Scanning Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Scan Request Flow                            │
└─────────────────────────────────────────────────────────────────┘

1. API Request
   POST /api/v1/scans
   {
     "host_id": "uuid",
     "profile": "xccdf_org.ssgproject.content_profile_stig",
     "schedule": "immediate"
   }

2. Validation Layer (FastAPI endpoint)
   ✓ User has scan permission
   ✓ Host exists and accessible
   ✓ Profile valid
   ✓ No conflicting scans running

3. Credential Resolution (AuthService)
   ✓ Resolve host-specific credentials
   ✓ Fallback to system credentials
   ✓ Decrypt credentials from storage

4. SSH Pre-flight Check (UnifiedSSHService)
   ✓ Test SSH connectivity
   ✓ Verify sudo access (if required)
   ✓ Check oscap installed on target
   ✓ Validate network reachability

5. Task Queuing (Celery)
   → execute_scan_task.delay(scan_id)
   → Queued to Redis
   → Picked up by worker

6. Scan Execution (Celery Worker)
   ┌─────────────────────────────────────┐
   │ Progress: 0% - Initializing         │
   │ Progress: 10% - Uploading SCAP      │
   │ Progress: 20% - Starting oscap      │
   │ Progress: 50% - Scanning (oscap)    │
   │ Progress: 90% - Downloading results │
   │ Progress: 95% - Parsing results     │
   │ Progress: 100% - Complete           │
   └─────────────────────────────────────┘

7. Result Parsing
   XML (XCCDF/ARF) → Python dict → Database
   ├─ PostgreSQL: scan metadata, status, timing
   └─ MongoDB: detailed findings, evidence, metadata

8. File Storage
   /app/data/results/
   ├─ {scan_id}_xccdf.xml       (XCCDF results)
   ├─ {scan_id}_arf.xml         (ARF format)
   └─ {scan_id}_report.html     (Human-readable)

9. Webhook Notification (if configured)
   POST https://external-system/webhook
   {
     "scan_id": "uuid",
     "status": "completed",
     "pass_rate": 87.5,
     "timestamp": "2025-10-26T02:00:00Z"
   }
```

### Service Layer Patterns

**MANDATORY**: Use centralized services for common operations.

#### UnifiedSSHService (SSH Operations)
**Location**: `backend/app/services/unified_ssh_service.py`

**Purpose**: Single source of truth for ALL SSH operations.

```python
# CORRECT - Use UnifiedSSHService
from backend.app.services.unified_ssh_service import UnifiedSSHService

ssh_service = UnifiedSSHService()
result = await ssh_service.test_connection(host, credentials)
if result.success:
    await ssh_service.execute_command(host, credentials, "oscap --version")

# WRONG - Direct paramiko usage
import paramiko
client = paramiko.SSHClient()
client.connect(hostname=host.ip_address, username="root", password="...")
```

**Why Centralized**:
- Consistent credential handling
- Standardized error handling
- Audit logging built-in
- Connection pooling
- Timeout management
- Host key verification

#### AuthService (Credential Management)
**Location**: `backend/app/services/auth_service.py`

**Purpose**: Resolve and decrypt credentials for hosts.

```python
# CORRECT - Use AuthService
from backend.app.services.auth_service import AuthService

auth_service = AuthService()
credentials = await auth_service.resolve_credentials(host_id, db)

# WRONG - Direct credential access
from backend.app.models import Host
host = db.query(Host).filter(Host.id == host_id).first()
password = decrypt(host.encrypted_credentials)  # Missing fallback logic!
```

**Credential Resolution Order**:
1. Host-specific credentials (if configured)
2. System credentials (fallback)
3. Error if neither exists

#### EncryptionService (Cryptography)
**Location**: `backend/app/services/encryption_service.py`

**Purpose**: All encryption/decryption operations.

```python
# CORRECT - Use EncryptionService
from backend.app.services.encryption_service import EncryptionService

enc_service = EncryptionService()
encrypted = enc_service.encrypt(plaintext)
decrypted = enc_service.decrypt(encrypted)

# WRONG - Direct cryptography library usage
from cryptography.fernet import Fernet
cipher = Fernet(key)
encrypted = cipher.encrypt(data)  # No key rotation, no versioning!
```

**Encryption Details**:
- Algorithm: AES-256-GCM (FIPS 140-2 compliant)
- Key Derivation: PBKDF2-HMAC-SHA256 (100,000 iterations)
- Nonce: 96-bit random (never reused)
- Authentication: GCM provides authenticated encryption

#### QueryBuilder (PostgreSQL Query Construction)
**Location**: `backend/app/utils/query_builder.py`

**Purpose**: Safe, fluent interface for building SQL queries with automatic parameterization.

**MANDATORY for all new PostgreSQL queries**: OpenWatch has standardized on QueryBuilder for 94% of database queries to eliminate SQL injection risks and maintain consistency.

```python
# CORRECT - Use QueryBuilder
from backend.app.utils.query_builder import QueryBuilder
from sqlalchemy import text

def list_users(db: Session, search: str = None, page: int = 1, per_page: int = 20):
    """List users with optional search and pagination."""
    builder = (
        QueryBuilder("users")
        .select("id", "username", "email", "role", "is_active")
        .order_by("created_at", "DESC")
        .paginate(page=page, per_page=per_page)
    )

    # Add optional search filter
    if search:
        builder.where("(username ILIKE :search OR email ILIKE :search)", f"%{search}%", "search")

    query, params = builder.build()
    result = db.execute(text(query), params)
    return [dict(row._mapping) for row in result]

# WRONG - Raw SQL string construction
def list_users_unsafe(db: Session, search: str = None):
    # DO NOT DO THIS!
    query = f"SELECT * FROM users WHERE username ILIKE '%{search}%'"
    return db.execute(text(query)).fetchall()
```

**QueryBuilder Benefits**:
- **Security**: Automatic SQL injection protection via parameterization
- **Readability**: Fluent interface is self-documenting
- **Maintainability**: Easy to add filters, pagination, joins
- **Consistency**: 94% of OpenWatch endpoints use this pattern
- **Testing**: Easy to mock and unit test

**Common Patterns**:

```python
# Conditional filtering
builder = QueryBuilder("hosts").select("*")
if status:
    builder.where("status = :status", status, "status")
if group_id:
    builder.where("group_id = :group_id", group_id, "group_id")

# Joins
builder = (
    QueryBuilder("scans s")
    .select("s.id", "s.status", "h.hostname")
    .join("hosts h", "s.host_id = h.id", "LEFT")
    .where("s.status = :status", "completed", "status")
)

# Pagination
builder = (
    QueryBuilder("users")
    .select("*")
    .order_by("created_at", "DESC")
    .paginate(page=1, per_page=20)  # Automatic LIMIT/OFFSET
)

# Count queries
count_builder = QueryBuilder("users")
count_query, count_params = count_builder.count_query()
total = db.execute(text(count_query), count_params).fetchone().total

# INSERT
insert_builder = QueryBuilder("users").insert({
    "username": "newuser",
    "email": "user@example.com",
    "role": "analyst",
    "is_active": True
})
query, params = insert_builder.build()
db.execute(text(query), params)

# UPDATE
update_builder = (
    QueryBuilder("users")
    .update({"is_active": False})
    .where("id = :id", user_id, "id")
)
query, params = update_builder.build()
db.execute(text(query), params)

# DELETE
delete_builder = (
    QueryBuilder("users")
    .delete()
    .where("id = :id", user_id, "id")
)
query, params = delete_builder.build()
db.execute(text(query), params)
```

**Migration Status** (as of 2025-11-04):
- **Phase 1**: Hosts GET endpoint (1 endpoint)
- **Phase 2**: Hosts CRUD endpoints (4 endpoints)
- **Phase 3**: Scans endpoints (5 endpoints, 100% coverage)
- **Phase 4**: Users endpoints (6 endpoints, 100% coverage)
- **Total**: 16/17 endpoints (94%)
- **Documentation**: `docs/QUERYBUILDER_EXPLANATION.md`

**When NOT to use QueryBuilder**:
- PostgreSQL-specific features like LATERAL JOIN (use raw SQL with parameterization)
- Very complex queries requiring CTEs or window functions (use raw SQL with parameterization)
- ORM operations requiring full model instances with relationships (use SQLAlchemy ORM)

---

## 🧩 Modular Code Architecture

### Principles of Modularity

OpenWatch follows **strict modular architecture** to ensure code maintainability, reusability, and scalability. Every module in the codebase should adhere to these core principles:

#### 1. Separation of Concerns

**Definition**: Each module handles ONE specific responsibility and does it well.

**Why It Matters**:
- Easier to debug (problems are isolated to specific modules)
- Simpler to test (test one responsibility at a time)
- Reduces cognitive load (developers only need to understand one module)
- Prevents cascading failures (bugs don't spread across the system)

**Good Example** (OpenWatch Encryption Module):
```python
# backend/app/encryption/
# Each file has a SINGLE, clear responsibility

encryption/
├── service.py           # ONLY encryption/decryption logic
├── config.py            # ONLY configuration data structures
├── exceptions.py        # ONLY error handling
└── __init__.py          # ONLY public API exposure

# service.py - Does ONE thing: encrypt/decrypt data
class EncryptionService:
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data. Nothing else."""
        pass

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data. Nothing else."""
        pass
```

**Bad Example** (Anti-Pattern):
```python
# DON'T DO THIS - mixing concerns
class EncryptionServiceBad:
    def encrypt(self, data: bytes) -> bytes:
        # Encryption logic
        pass

    def save_to_database(self, data):  # ❌ Database concern
        pass

    def send_email_notification(self):  # ❌ Email concern
        pass

    def validate_user_permissions(self):  # ❌ Authorization concern
        pass
```

#### 2. Single Responsibility Principle (SRP)

**Rule**: A module should have ONE reason to change.

**Examples in OpenWatch**:

```python
# CORRECT - Each service has one responsibility

# backend/app/services/auth_service.py
# Reason to change: Authentication logic changes
class AuthService:
    def resolve_credential(self, target_id: str) -> CredentialData:
        """Resolve and decrypt credentials. That's it."""
        pass

# backend/app/services/unified_ssh_service.py
# Reason to change: SSH connection logic changes
class UnifiedSSHService:
    def test_connection(self, host: str, credentials: dict) -> bool:
        """Test SSH connectivity. That's it."""
        pass

# backend/app/services/host_monitor.py
# Reason to change: Monitoring logic changes
class HostMonitor:
    def comprehensive_host_check(self, host_data: dict) -> dict:
        """Check host status. That's it."""
        pass
```

**Wrong Example**:
```python
# DON'T DO THIS - multiple reasons to change
class GodService:  # ❌ Anti-pattern
    def authenticate_user(self):  # Changes when auth logic changes
        pass

    def connect_ssh(self):  # Changes when SSH logic changes
        pass

    def monitor_host(self):  # Changes when monitoring logic changes
        pass

    def send_email(self):  # Changes when email logic changes
        pass
```

#### 3. Reusability

**Definition**: Modules should be designed to work in multiple contexts without modification.

**Example: Encryption Service**

```python
# backend/app/encryption/ is used by:
# 1. Auth service (encrypting credentials)
# 2. System settings (encrypting config)
# 3. Scan tasks (encrypting scan data)
# 4. Host monitoring (encrypting host secrets)

# The encryption module doesn't know or care WHO uses it
# It just encrypts/decrypts data - pure, reusable functionality

from backend.app.encryption import create_encryption_service

# Can be used anywhere
encryption_service = create_encryption_service(master_key="...")

# Works in auth context
encrypted_password = encryption_service.encrypt(b"user_password")

# Works in monitoring context
encrypted_credentials = encryption_service.encrypt(b"ssh_key_data")

# Works in settings context
encrypted_config = encryption_service.encrypt(b"api_token")
```

**Design for Reusability Checklist**:
- ✅ Module takes inputs as parameters (not hardcoded)
- ✅ Module doesn't depend on specific calling context
- ✅ Module has clear, documented public API
- ✅ Module handles its own errors internally
- ✅ Module is well-tested in isolation

#### 4. Maintainability

**Definition**: Code should be easy to understand, update, and fix.

**Modular Maintainability Benefits**:

**Example Scenario**: Fix a bug in SSH connection logic

**With Modularity** (OpenWatch approach):
```bash
# Bug: SSH connections timing out

# Step 1: Identify the module
ls backend/app/services/
# → unified_ssh_service.py  ← Found it!

# Step 2: Open ONE file
vim backend/app/services/unified_ssh_service.py

# Step 3: Fix the timeout parameter in ONE place
def connect(self, timeout: int = 30):  # Changed from 10 to 30
    pass

# Step 4: Test ONE module
pytest tests/unit/test_unified_ssh_service.py

# Done! One file, one fix, easy to review
```

**Without Modularity** (monolithic anti-pattern):
```bash
# Bug: SSH connections timing out

# Step 1: Find SSH code scattered across files
grep -r "ssh" backend/  # 237 files with SSH code!

# Step 2: Fix in multiple places
vim backend/app/scan_service.py      # Has SSH code
vim backend/app/monitoring.py        # Has SSH code
vim backend/app/terminal.py          # Has SSH code
vim backend/app/discovery.py         # Has SSH code

# Step 3: Test everything (can't test in isolation)
pytest tests/  # 2000+ tests run because everything is coupled

# Result: High risk, hard to review, time-consuming
```

#### 5. Scalability

**Definition**: Modules should support independent development and deployment.

**Team Collaboration Benefits**:

```
OpenWatch Team Structure (Modular):

Developer A: Works on encryption/
  └─ Changes: backend/app/encryption/service.py
  └─ Tests: tests/unit/test_encryption_service.py
  └─ PR: "feat: Add AES-256-GCM encryption support"
  └─ Impact: Only encryption module affected

Developer B: Works on scanning/
  └─ Changes: backend/app/services/scan_service.py
  └─ Tests: tests/integration/test_scan_service.py
  └─ PR: "feat: Add RHEL 9 scan support"
  └─ Impact: Only scan service affected

Developer C: Works on monitoring/
  └─ Changes: backend/app/services/host_monitor.py
  └─ Tests: tests/unit/test_host_monitor.py
  └─ PR: "feat: Add adaptive monitoring intervals"
  └─ Impact: Only monitoring module affected

Result: All 3 developers work in parallel with ZERO merge conflicts
```

### OpenWatch Module Organization

#### Backend Modules

```
backend/app/
├── encryption/              # Cryptography operations (ONLY)
│   ├── service.py          # Encrypt/decrypt
│   ├── config.py           # Configuration
│   ├── exceptions.py       # Errors
│   └── __init__.py         # Public API
│
├── services/               # Business logic services
│   ├── auth_service.py     # Credential resolution (ONLY)
│   ├── unified_ssh_service.py  # SSH operations (ONLY)
│   ├── host_monitor.py     # Host monitoring (ONLY)
│   ├── scan_service.py     # Scan execution (ONLY)
│   └── compliance_rules_service.py  # Rule management (ONLY)
│
├── repositories/           # Data access layer (ONLY)
│   ├── base_repository.py  # Generic CRUD
│   ├── compliance_rule_repository.py  # Rule queries
│   └── scan_result_repository.py  # Result queries
│
├── routes/                 # API endpoints (ONLY)
│   ├── auth.py            # Authentication endpoints
│   ├── hosts.py           # Host management endpoints
│   ├── scans.py           # Scan endpoints
│   └── monitoring.py      # Monitoring endpoints
│
├── models/                # Data models (ONLY)
│   ├── database_models.py  # SQLAlchemy ORM
│   └── mongo_models.py    # Beanie ODM
│
└── tasks/                 # Async background tasks (ONLY)
    ├── scan_tasks.py      # Scan execution
    └── monitoring_tasks.py  # Host monitoring
```

**Key Principles**:
1. **No cross-contamination**: Encryption logic NEVER appears in routes/ or tasks/
2. **Clear dependencies**: Services depend on repositories, NOT the reverse
3. **One-way flow**: Routes → Services → Repositories → Models
4. **Testability**: Each module can be tested in isolation

### Module Communication Patterns

#### Dependency Injection (Preferred)

```python
# CORRECT - Dependencies passed explicitly

from backend.app.encryption import EncryptionService
from backend.app.services.auth_service import AuthService

def create_auth_service(
    db: Session,
    encryption_service: EncryptionService  # ← Injected dependency
) -> AuthService:
    """Factory function with explicit dependencies."""
    return AuthService(db, encryption_service)

# Usage
encryption_service = create_encryption_service(master_key="...")
auth_service = create_auth_service(db, encryption_service)
```

**Benefits**:
- Easy to test (inject mock dependencies)
- Clear what each module needs
- No hidden global state
- Thread-safe

#### Global Singletons (Anti-Pattern)

```python
# WRONG - Hidden global dependencies

# Don't do this in OpenWatch
_global_encryption_service = None  # ❌ Hidden state

def get_encryption_service():
    global _global_encryption_service
    if _global_encryption_service is None:
        _global_encryption_service = EncryptionService()
    return _global_encryption_service

# Problems:
# - Hard to test (can't inject mocks)
# - Hidden dependencies (what uses this?)
# - Thread-safety issues
# - Tight coupling
```

### Module Refactoring Example

**Before** (Monolithic, 500 lines):
```python
# backend/app/services/crypto.py (LEGACY - DELETED)

class CryptoService:  # ❌ Does too many things
    def encrypt_fernet(self, data):
        """Old Fernet encryption"""
        pass

    def encrypt_aesgcm(self, data):
        """New AES-GCM encryption"""
        pass

    def decrypt_dual_format(self, data):
        """Try both formats"""
        pass

    def migrate_credentials(self, host):
        """Migration logic"""
        pass

    def validate_key_strength(self, key):
        """Key validation"""
        pass

# Result: 500 lines, multiple responsibilities, hard to maintain
```

**After** (Modular, 3 separate modules):
```python
# backend/app/encryption/service.py (120 lines)
class EncryptionService:
    """ONLY handles encryption/decryption"""
    def encrypt(self, data: bytes) -> bytes:
        pass

    def decrypt(self, encrypted_data: bytes) -> bytes:
        pass

# backend/app/encryption/config.py (80 lines)
class EncryptionConfig:
    """ONLY handles configuration"""
    kdf_iterations: int = 100000
    kdf_algorithm: KDFAlgorithm = KDFAlgorithm.SHA256

# backend/app/encryption/exceptions.py (40 lines)
class EncryptionError(Exception):
    """ONLY handles errors"""
    pass

# Result: 240 lines total (52% reduction), clear responsibilities
```

### Module Design Checklist

Before creating or modifying a module, verify:

- [ ] **Single Responsibility**: Module has ONE clear purpose
- [ ] **No Side Effects**: Module doesn't modify global state
- [ ] **Clear Interface**: Public API is documented and minimal
- [ ] **No Hidden Dependencies**: All dependencies are explicit (injected)
- [ ] **Testable in Isolation**: Can test without running entire system
- [ ] **Reusable**: Could be used in different context without changes
- [ ] **Well-Named**: Name clearly describes what module does
- [ ] **Properly Organized**: In correct directory (services/, routes/, etc.)
- [ ] **Small Size**: Ideally <200 lines, definitely <500 lines
- [ ] **No Duplication**: Doesn't repeat logic from other modules

**If you answer "NO" to any of these, refactor before continuing!**

---

## 📝 Code Documentation Standards

### Documentation Philosophy

**Rule**: Comments explain WHY, code explains WHAT.

```python
# GOOD - Explains WHY (non-obvious business logic)
# Use Argon2id instead of bcrypt for FIPS 140-2 compliance
# NIST SP 800-63B recommends memory-hard functions
pwd_context = CryptContext(schemes=["argon2"])

# BAD - Explains WHAT (already obvious from code)
# Create a password context
pwd_context = CryptContext(schemes=["argon2"])
```

### 1. Module-Level Documentation

**Every Python file** must start with a module docstring explaining:
1. What the module does
2. When to use it
3. What NOT to use it for (if applicable)

```python
"""
Host Monitoring Service

Provides comprehensive health checks for remote hosts including:
- ICMP ping tests
- TCP port connectivity
- SSH authentication verification
- Response time measurement

This service is used by:
- Adaptive monitoring dispatcher (scheduled checks)
- JIT connectivity checks (user-triggered)
- Pre-scan validation (before SCAP scans)

DO NOT use this service for:
- Actual SCAP scanning (use scan_service.py instead)
- Credential storage (use auth_service.py instead)
- SSH command execution (use unified_ssh_service.py instead)

Example:
    >>> from backend.app.services.host_monitor import get_host_monitor
    >>> monitor = get_host_monitor(db, encryption_service)
    >>> result = await monitor.comprehensive_host_check(host_data, db)
    >>> print(result['status'])  # 'online', 'offline', 'degraded'
"""
```

### 2. Function/Method Documentation

**Every public function** must have a docstring with:
1. Brief description (one line)
2. Detailed explanation (if complex)
3. Args with types
4. Returns with type
5. Raises (exceptions)
6. Example usage

```python
def resolve_credential(
    self,
    target_id: str,
    use_default: bool = False
) -> Optional[CredentialData]:
    """
    Resolve effective credentials for a target using inheritance logic.

    This function implements the credential resolution waterfall:
    1. If use_default=True → return system default credential
    2. If target has host-specific credential → return it
    3. If no host credential → fallback to system default
    4. If no credentials at all → return None

    This is the ONLY function that should be used for credential resolution
    to ensure consistent behavior across the entire application.

    Args:
        target_id: UUID of the host to resolve credentials for
        use_default: If True, skip host-specific lookup and use system default

    Returns:
        CredentialData object with decrypted credentials, or None if no
        credentials are configured

    Raises:
        DecryptionError: If credential decryption fails
        DatabaseError: If database query fails

    Example:
        >>> # Resolve host-specific credentials with system fallback
        >>> cred = auth_service.resolve_credential(target_id="host-uuid-123")
        >>> if cred:
        ...     print(f"Using {cred.source} credentials for {cred.username}")
        ... else:
        ...     print("No credentials configured")

        >>> # Force use of system default
        >>> default_cred = auth_service.resolve_credential(
        ...     target_id="any-id",
        ...     use_default=True
        ... )
    """
```

### 3. Inline Comments - When and How

#### When to Use Inline Comments

**✅ USE for**:
1. Non-obvious business logic
2. Security considerations
3. Performance optimizations
4. Workarounds for external library bugs
5. TODO items with context

```python
# ✅ GOOD - Explains WHY (security decision)
# Limit to 1000 chars to prevent log injection attacks
sanitized = str(value)[:1000]

# ✅ GOOD - Explains WHY (performance)
# Use set for O(1) lookup instead of list O(n) lookup
# With 10k+ rules, this saves 2 seconds per scan
active_rule_ids = set(rule.id for rule in rules)

# ✅ GOOD - Explains WHY (business logic)
# FedRAMP requires 90-day retention minimum for audit compliance
retention_days = max(90, user_specified_retention)

# ✅ GOOD - Explains workaround
# NOTE: paramiko 2.12.0 has a bug with Ed25519 keys
# Using RSA until paramiko 3.0 is released
# See: https://github.com/paramiko/paramiko/issues/2017
if key_type == "Ed25519":
    logger.warning("Ed25519 keys not fully supported, using RSA fallback")
```

#### When NOT to Use Inline Comments

**❌ DON'T USE for**:
1. Obvious code behavior
2. Repeating variable names
3. Commenting out code (delete it instead)
4. Vague placeholder comments

```python
# ❌ BAD - States the obvious
# Increment counter
counter += 1

# ❌ BAD - Repeats variable name
# Get the user from database
user = db.query(User).first()

# ❌ BAD - Commented code (use git instead)
# old_encryption = fernet.encrypt(data)
new_encryption = aesgcm.encrypt(data)

# ❌ BAD - Vague, no context
# TODO: Fix this later
# HACK: This needs work
# XXX: Not sure about this
```

### 4. TODO Comments

**Format**: `TODO(context): Description`

```python
# ✅ GOOD - Specific, actionable, with context
# TODO(security): Implement certificate pinning for webhook requests
# Priority: HIGH
# Blocked by: Need to determine certificate rotation strategy
# Reference: OWASP ASVS 9.2.1

# TODO(performance): Add caching layer for compliance rules
# Priority: MEDIUM
# Benchmark shows 2s query time for 10k rules
# Consider Redis cache with 5min TTL

# ❌ BAD - Vague, no context
# TODO: Fix this
# FIXME: Broken
```

### 5. Type Hints (Code-Level Documentation)

**MANDATORY**: All function signatures must have type hints.

```python
# ✅ EXCELLENT - Complete type information
from typing import Dict, List, Optional
from uuid import UUID

async def get_scan_results(
    scan_id: UUID,
    severity: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Fetch scan results with optional severity filter."""
    pass

# ❌ BAD - No type hints
async def get_scan_results(scan_id, severity=None, limit=100):
    """Fetch scan results."""
    pass
```

### 6. Complex Logic Documentation

For complex algorithms or business logic, add explanatory comments:

```python
def calculate_risk_score(
    findings: List[Finding]
) -> float:
    """
    Calculate composite risk score using NIST SP 800-30 methodology.

    Risk scoring formula:
    - Critical findings: 10 points each
    - High findings: 5 points each
    - Medium findings: 2 points each
    - Low findings: 0.5 points each

    Score interpretation:
    - 0-20: Low risk
    - 21-50: Medium risk
    - 51-100: High risk
    - 100+: Critical risk

    Returns:
        Float risk score (0-infinity, typically 0-200)
    """
    score = 0.0

    # Weight findings by severity per NIST guidelines
    for finding in findings:
        if finding.severity == "critical":
            score += 10.0
        elif finding.severity == "high":
            score += 5.0
        elif finding.severity == "medium":
            score += 2.0
        else:  # low or informational
            score += 0.5

    # Apply diminishing returns for large finding counts
    # Prevents score inflation from scanning large hosts
    if len(findings) > 100:
        score *= 0.9  # 10% penalty for bulk findings

    return score
```

### 7. Security-Sensitive Code

**ALWAYS document security-related decisions**:

```python
def hash_password(password: str) -> str:
    """
    Hash password using Argon2id (FIPS 140-2 compliant).

    Security parameters:
    - Memory cost: 64MB (prevents GPU attacks)
    - Time cost: 3 iterations (balances security/performance)
    - Parallelism: 4 threads (uses multi-core for key derivation)

    Why Argon2id over bcrypt:
    - NIST SP 800-63B recommends memory-hard functions
    - Resistant to GPU/ASIC attacks
    - Winner of Password Hashing Competition 2015

    Reference: OWASP Password Storage Cheat Sheet
    """
    return pwd_context.hash(
        password,
        memory_cost=65536,  # 64MB
        time_cost=3,
        parallelism=4
    )
```

### Documentation Anti-Patterns to Avoid

```python
# ❌ ANTI-PATTERN 1: Outdated comments
# This function uses Fernet encryption  ← LIE! Uses AES-GCM now
def encrypt_data(data: bytes) -> bytes:
    return aesgcm.encrypt(data)

# ❌ ANTI-PATTERN 2: Commented-out code
def process_scan(scan_id: str):
    # old_method(scan_id)
    # legacy_processing(scan_id)
    # deprecated_scanner(scan_id)
    new_method(scan_id)

# ❌ ANTI-PATTERN 3: Obvious comments
# Check if user is None
if user is None:
    # Raise an exception
    raise ValueError("User not found")

# ❌ ANTI-PATTERN 4: Jargon without explanation
# Apply the TCP handshake optimistic backpressure algorithm
# (What does this mean? No one knows!)
apply_tcp_optimization()

# ❌ ANTI-PATTERN 5: Misleading function names (no comment can save this)
def get_user():  # Actually DELETES user!
    """Delete a user from database"""  # ← Function name lies
    db.delete(user)
```

### Documentation Coverage Standards

**Minimum requirements**:
- ✅ 100% of modules have module docstrings
- ✅ 100% of public functions have docstrings
- ✅ 100% of functions have type hints
- ✅ Complex algorithms have explanatory comments
- ✅ Security decisions are documented
- ✅ No commented-out code in production

**Verification**:
```bash
# Check docstring coverage
pydocstyle backend/app/services/

# Check type hint coverage
mypy backend/app/ --strict

# Check for commented-out code
grep -r "^[[:space:]]*#.*\(def\|class\|import\)" backend/app/
```

### Example: Well-Documented Module

See `backend/app/encryption/service.py` for a perfect example of:
- Clear module docstring with examples
- Complete function docstrings
- Type hints on all functions
- Security decisions documented
- No commented-out code
- Inline comments explain WHY, not WHAT

---

## 🔧 Development Workflow

### Quick Start

```bash
# Clone and navigate
cd /home/rracine/hanalyx/openwatch/

# Start all services (Docker)
./start-openwatch.sh --runtime docker --build

# Start all services (Podman - rootless)
./start-openwatch.sh --runtime podman --build

# Check service health
docker ps  # All containers should show (healthy)

# Access services
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/api/docs
```

### Container Operations

```bash
# Stop services (SAFE - preserves data by default)
./stop-openwatch.sh

# Deep clean (DANGEROUS - deletes ALL data, volumes, images)
./stop-openwatch.sh --deep-clean

# View logs
docker logs openwatch-backend --tail 100 --follow
docker logs openwatch-worker --tail 100 --follow
docker logs openwatch-frontend --tail 50
docker logs openwatch-db --tail 50
docker logs openwatch-mongodb --tail 50

# Execute commands in containers
docker exec -it openwatch-backend bash
docker exec -it openwatch-db psql -U openwatch -d openwatch

# Restart individual services
docker restart openwatch-backend
docker restart openwatch-worker openwatch-celery-beat
```

### Frontend Development

```bash
cd frontend/

# Development server (hot reload on http://localhost:3001)
npm run dev

# Production build
npm run build

# Linting
npm run lint              # Check for issues
npm run lint:fix          # Auto-fix issues

# Testing
npm run test:e2e          # Headless E2E tests
npm run test:e2e:ui       # Interactive test UI
npm run test:e2e:debug    # Debug with browser open
npm run test:e2e:headed   # Watch tests run
```

**Frontend Code Changes**: Hot reload enabled (Vite dev server).

### Backend Development

```bash
cd backend/

# Code quality checks
black --check app/                    # Format checking (100 char line length)
black app/                           # Auto-format
flake8 app/                          # Linting
mypy app/                            # Type checking
bandit -r app/                       # Security scanning

# Run all quality checks
black app/ && flake8 app/ && mypy app/ && bandit -r app/

# Testing
pytest -v                            # All tests
pytest -m unit                       # Unit tests only
pytest -m integration                # Integration tests
pytest -m "not slow"                 # Exclude slow tests
pytest --cov=app --cov-report=html   # Coverage report (80% minimum)
pytest -v --tb=short                 # Short traceback format
```

**Backend Code Changes**: NO auto-reload in Docker containers!

**Hot-reload workaround**:
```bash
# Option 1: Copy file into container and restart
docker cp backend/app/services/scan_service.py openwatch-backend:/app/backend/app/services/scan_service.py
docker restart openwatch-backend

# Option 2: Rebuild container
./stop-openwatch.sh
./start-openwatch.sh --runtime docker --build
```

### Database Operations

#### PostgreSQL (Relational Data)

```bash
# Create migration
cd backend/
alembic revision --autogenerate -m "Add new column to hosts"

# Apply migrations
alembic upgrade head

# Check current migration version
alembic current

# Downgrade one version
alembic downgrade -1

# Access PostgreSQL console
docker exec -it openwatch-db psql -U openwatch -d openwatch

# Example queries
SELECT id, hostname, ip_address FROM hosts;
SELECT id, status, created_at FROM scans ORDER BY created_at DESC LIMIT 10;
```

#### MongoDB (Document Store)

```bash
# Access MongoDB shell
docker exec -it openwatch-mongodb mongosh

# Use OpenWatch database
use openwatch_rules;

# Example queries
db.compliance_rules.countDocuments();
db.compliance_rules.find({severity: "high"}).limit(5);
db.scan_results.find({scan_id: "uuid-here"});

# Show collections
show collections;

# Show indexes on compliance_rules
db.compliance_rules.getIndexes();
```

**IMPORTANT**: As of 2025-10-26, **Beanie ODM manages ALL MongoDB indexes**, NOT the init script!

#### MongoDB Index Management Policy

**Single Source of Truth**: All MongoDB indexes are defined in Beanie model classes (`backend/app/models/mongo_models.py`).

**Why Beanie-Only**:
- ✅ Single source of truth for index definitions
- ✅ Automatic index creation/updates on application startup
- ✅ No naming conflicts between init script and ODM
- ✅ Version control for all index changes
- ✅ Type-safe index definitions in Python

**When adding new indexes**:
```python
# In backend/app/models/mongo_models.py
from pymongo import IndexModel, TEXT

class ComplianceRule(Document):
    # ... field definitions ...

    class Settings:
        name = "compliance_rules"
        indexes = [
            # Unique index with explicit name
            IndexModel([("rule_id", 1)], unique=True, name="idx_rule_id"),

            # Compound index
            IndexModel([
                ("category", 1),
                ("severity", -1)
            ], name="idx_category_severity"),

            # Text search index with weights
            IndexModel([
                ("metadata.name", TEXT),
                ("metadata.description", TEXT)
            ], name="idx_text_search", weights={
                "metadata.name": 10,
                "metadata.description": 5
            }),

            # Simple index (Beanie auto-generates name)
            "tags",
        ]
```

**Collections with Beanie-managed indexes**:
- `compliance_rules`: 17 indexes (including text search)
- `rule_intelligence`: 6 indexes (including unique rule_id)
- `remediation_scripts`: 3 indexes

**⚠️ IMPORTANT: Adding New Indexes**

When you need to add a new index to any MongoDB collection:

✅ **DO**: Add the index to the Beanie model's `Settings.indexes` array in [mongo_models.py](backend/app/models/mongo_models.py)
```python
# Example: Adding a new index to ComplianceRule
class ComplianceRule(Document):
    class Settings:
        indexes = [
            # ... existing indexes ...
            IndexModel([("new_field", 1)], name="idx_new_field"),  # ← Add here
        ]
```

❌ **DO NOT**: Add indexes to the MongoDB init script ([01-init-openwatch-user.js](backend/app/data/mongo/init/01-init-openwatch-user.js))

The init script only creates collections and validation schemas. All index management is handled by Beanie ODM.

#### MongoDB Test/Mock Data Policy

**🚫 NEVER insert mock or test data into MongoDB compliance rule collections.**

**Why**:
- Compliance rules must come from verified sources (ComplianceAsCode, SCAP content)
- Mock data pollutes production databases and can cause false positive scan results
- Test data may not conform to the strict validation schema required for compliance rules
- Mixing real and fake rules creates compliance audit issues

**What NOT to do**:
```javascript
// ❌ WRONG - Never insert mock rules in init script
db.compliance_rules.insertOne({
    rule_id: 'test-rule',
    metadata: { name: 'Test Rule' },
    // ... fake data
});
```

**Correct approach for testing**:
```python
# ✅ CORRECT - Use pytest fixtures with test database
@pytest.fixture
async def test_compliance_rule():
    """Create test rule in isolated test database"""
    rule = ComplianceRule(
        rule_id=f"test-{uuid.uuid4()}",
        # ... proper test data
    )
    await rule.insert()  # Only in test database
    yield rule
    await rule.delete()  # Cleanup after test
```

**For development testing**:
- Use the actual build pipeline: `./scripts/build_compliance_rules.sh rhel8`
- Import real SCAP content bundles via the upload API
- Run pytest with isolated test databases (not production MongoDB)

**MongoDB init script should ONLY**:
- ✅ Create databases and collections
- ✅ Define validation schemas
- ✅ Set up users and permissions
- ❌ NEVER insert any data (test or otherwise)

---

## ✅ Code Quality Standards

### **CRITICAL: NO EMOJIS IN CODE**

**Policy**: Emojis are **STRICTLY PROHIBITED** in all OpenWatch codebase files.

**Why**:
1. **YAML Parsing**: Emojis in YAML files (especially GitHub Actions workflows) cause parsing errors
2. **Encoding Issues**: Emojis can cause UTF-8 encoding problems in logs, terminals, and CI/CD pipelines
3. **Professional Standards**: Enterprise-grade software should use clear, professional language
4. **Accessibility**: Screen readers and accessibility tools may misinterpret emojis
5. **Git Diffs**: Emojis make code reviews and diffs harder to read
6. **Database Compatibility**: Some database encodings don't support emoji characters

**Enforcement**:
- ❌ NEVER use emojis in: Python code, TypeScript/JavaScript code, YAML files, shell scripts, documentation
- ✅ ALWAYS use: Clear text descriptions, standard ASCII characters, professional language
- ✅ PRE-COMMIT HOOK: Blocks commits containing emojis (except in this policy document)

**Examples**:

```python
# ❌ WRONG - Using emojis
logger.info("✅ Database connection successful")
logger.error("❌ Failed to connect")
raise HTTPException(status_code=500, detail="🚨 Critical error")

# ✅ CORRECT - Clear text
logger.info("Database connection successful")
logger.error("Failed to connect to database")
raise HTTPException(status_code=500, detail="Critical error occurred")
```

```yaml
# ❌ WRONG - Emojis in YAML
name: 🚀 Deploy Production
run: echo "✅ Build successful"

# ✅ CORRECT - Plain text
name: Deploy Production
run: echo "Build successful"
```

```bash
# ❌ WRONG - Emojis in shell scripts
echo "🔍 Scanning for vulnerabilities..."
echo "✅ All tests passed!"

# ✅ CORRECT - Plain text
echo "Scanning for vulnerabilities..."
echo "All tests passed"
```

**Exceptions**:
- This policy document (CLAUDE.md) - for illustration purposes only
- User-facing UI text files (frontend/src/locales/) - if explicitly required for UX

**Pre-commit Hook** (`scripts/pre-commit-quality-check.sh`):
```bash
# Check for emojis in staged files
if git diff --cached --name-only | xargs grep -P "[\x{1F300}-\x{1F9FF}]" 2>/dev/null | grep -v "CLAUDE.md"; then
    echo "ERROR: Emojis detected in code. Use plain text instead."
    exit 1
fi
```

### Python Backend Standards

#### Formatting (Black)
- **Line Length**: 100 characters
- **String Quotes**: Double quotes preferred
- **Configuration**: `pyproject.toml`

```bash
# Check formatting
black --check app/

# Auto-format
black app/

# Format specific file
black app/services/scan_service.py
```

#### Linting (Flake8)
- **Max Line Length**: 100
- **Max Complexity**: 15
- **Ignore**: E203, E501, W503 (Black compatibility)

```bash
# Check linting
flake8 app/

# Check specific file
flake8 app/services/scan_service.py
```

#### Type Checking (MyPy)
- **Strict Mode**: Enabled
- **Python Version**: 3.9+
- **Configuration**: `pyproject.toml`

```python
# CORRECT - Full type annotations
async def get_host(db: AsyncSession, host_id: UUID) -> Optional[Host]:
    result = await db.execute(select(Host).filter(Host.id == host_id))
    return result.scalar_one_or_none()

# WRONG - Missing type hints
async def get_host(db, host_id):
    result = await db.execute(select(Host).filter(Host.id == host_id))
    return result.scalar_one_or_none()
```

#### Security Scanning (Bandit)
- **Severity**: HIGH, MEDIUM
- **Confidence**: HIGH, MEDIUM
- **Exclude**: tests/ directory

```bash
# Scan for security issues
bandit -r app/

# Generate detailed report
bandit -r app/ -f html -o security_report.html
```

#### Import Sorting (isort)
- **Profile**: Black
- **Line Length**: 100

```python
# CORRECT - Sorted imports
import asyncio
import logging
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.models import Host, Scan

# WRONG - Unsorted imports
from backend.app.models import Host, Scan
import logging
from uuid import UUID
from fastapi import Depends, HTTPException
import asyncio
```

### TypeScript Frontend Standards

#### ESLint
- **Parser**: @typescript-eslint/parser
- **Extends**:
  - eslint:recommended
  - plugin:@typescript-eslint/recommended
  - plugin:react/recommended
  - plugin:react-hooks/recommended

```bash
# Check linting
npm run lint

# Auto-fix
npm run lint:fix
```

#### TypeScript Configuration
- **Strict Mode**: Enabled
- **Target**: ES2020
- **Module**: ESNext
- **JSX**: react-jsx

```typescript
// CORRECT - Explicit types
interface HostResponse {
  id: string;
  hostname: string;
  ip_address: string;
  status: 'active' | 'inactive';
}

async function fetchHost(id: string): Promise<HostResponse> {
  const response = await api.get<HostResponse>(`/api/v1/hosts/${id}`);
  return response.data;
}

// WRONG - Implicit any
async function fetchHost(id) {
  const response = await api.get(`/api/v1/hosts/${id}`);
  return response.data;
}
```

### Code Review Checklist

Before submitting a PR, verify:

- [ ] All tests pass (`pytest -v` for backend, `npm run test:e2e` for frontend)
- [ ] Code formatted (`black app/` for backend, `npm run lint:fix` for frontend)
- [ ] Type checking passes (`mypy app/` for backend, `tsc --noEmit` for frontend)
- [ ] No security findings (`bandit -r app/`)
- [ ] No new OWASP Top 10 vulnerabilities introduced
- [ ] Sensitive data not logged
- [ ] Input validation added for all user inputs
- [ ] Error messages generic (no sensitive info leaked)
- [ ] SQL queries use ORM (no raw SQL)
- [ ] Shell commands use argument lists (no shell=True)
- [ ] All new endpoints have RBAC decorators
- [ ] All new functions have docstrings
- [ ] Complex logic has inline comments
- [ ] Breaking changes documented

---

## 🧪 Testing Strategy

### Test Pyramid

```
        ┌─────────────┐
        │     E2E     │  ← Playwright (Frontend), API integration tests
        │   (Slow)    │     Run in CI, critical user flows
        └─────────────┘
             ▲
    ┌────────────────────┐
    │   Integration      │  ← Database, external services, API endpoints
    │   (Medium)         │     Run before commit
    └────────────────────┘
             ▲
┌──────────────────────────────┐
│       Unit Tests             │  ← Pure functions, business logic
│       (Fast)                 │     Run on every file save
└──────────────────────────────┘
```

### Backend Testing (Pytest)

#### Test Organization
```
backend/tests/
├── unit/                      # Fast, isolated tests
│   ├── test_encryption.py
│   ├── test_validation.py
│   └── test_utils.py
├── integration/               # Database, Redis, external services
│   ├── test_database.py
│   ├── test_repositories.py
│   └── test_api_endpoints.py
├── regression/                # Prevent known bugs from reoccurring
│   ├── test_regression_unified_credentials.py
│   └── test_regression_uuid_serialization.py
└── conftest.py                # Pytest fixtures
```

#### Test Markers
```python
import pytest

@pytest.mark.unit
def test_pure_function():
    """Fast test with no dependencies."""
    assert calculate_risk_score(high=2, medium=5, low=10) == 45

@pytest.mark.integration
async def test_database_query(db_session):
    """Test with database."""
    host = await create_host(db_session, hostname="test-host")
    assert host.id is not None

@pytest.mark.slow
async def test_full_scap_scan(db_session):
    """Long-running test."""
    result = await execute_scan(host_id, profile="stig")
    assert result.status == "completed"
```

#### Running Tests
```bash
# All tests
pytest -v

# By marker
pytest -m unit              # Fast unit tests only
pytest -m integration       # Integration tests
pytest -m "not slow"        # Exclude slow tests

# By file/directory
pytest tests/unit/
pytest tests/regression/test_regression_unified_credentials.py

# With coverage
pytest --cov=app --cov-report=html
open htmlcov/index.html

# Stop on first failure
pytest -x

# Show detailed output
pytest -v --tb=long

# Parallel execution (if pytest-xdist installed)
pytest -n auto
```

### Frontend Testing (Playwright)

#### E2E Test Organization
```
frontend/tests/e2e/
├── auth/
│   ├── login.spec.ts
│   ├── mfa.spec.ts
│   └── logout.spec.ts
├── hosts/
│   ├── host-list.spec.ts
│   ├── host-create.spec.ts
│   └── host-delete.spec.ts
├── scans/
│   ├── scan-execute.spec.ts
│   └── scan-results.spec.ts
└── playwright.config.ts
```

#### Example E2E Test
```typescript
import { test, expect } from '@playwright/test';

test.describe('Host Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'admin123');
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('create new host', async ({ page }) => {
    // Navigate to hosts
    await page.click('a[href="/hosts"]');

    // Click create button
    await page.click('button:has-text("Add Host")');

    // Fill form
    await page.fill('input[name="hostname"]', 'test-server-01');
    await page.fill('input[name="ip_address"]', '192.168.1.100');
    await page.selectOption('select[name="group"]', 'production');

    // Submit
    await page.click('button:has-text("Create")');

    // Verify success
    await expect(page.locator('text=Host created successfully')).toBeVisible();
    await expect(page.locator('td:has-text("test-server-01")')).toBeVisible();
  });
});
```

#### Running E2E Tests
```bash
# Headless (CI mode)
npm run test:e2e

# Interactive UI
npm run test:e2e:ui

# Debug mode (browser visible)
npm run test:e2e:debug

# Specific test file
npx playwright test auth/login.spec.ts

# Generate report
npx playwright show-report
```

### Regression Tests (Critical)

**Purpose**: Prevent known bugs from reoccurring.

**Example**: `tests/regression/test_regression_unified_credentials.py`
```python
import pytest
from sqlalchemy import inspect

@pytest.mark.regression
async def test_unified_credentials_table_exists(db_session):
    """
    Regression test for: Fresh OpenWatch install fails with 500 error

    Root cause: unified_credentials table was created by init script,
    not ORM, so migrations didn't know about it.

    Fix: Created proper SQLAlchemy model with migrations.

    This test ensures the table exists on fresh installations.
    """
    inspector = inspect(db_session.bind)
    tables = inspector.get_table_names()

    assert "unified_credentials" in tables, \
        "unified_credentials table missing - ORM model or migration broken"
```

### Pre-commit Hooks

**Setup**:
```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
set -e

echo "🔍 Running pre-commit checks..."

# Backend checks
cd backend/
echo "  ✓ Running pytest..."
pytest tests/regression/ -x -q
echo "  ✓ Running black..."
black --check app/
echo "  ✓ Running flake8..."
flake8 app/

# Frontend checks
cd ../frontend/
echo "  ✓ Running ESLint..."
npm run lint

echo "✅ All checks passed!"
EOF

chmod +x .git/hooks/pre-commit
```

---

## 🔐 Security Best Practices

### Input Validation (Defense Layer 1)

**MANDATORY**: Validate ALL user inputs at API boundary.

```python
from pydantic import BaseModel, Field, validator, constr
from typing import Optional
import re

class HostCreateRequest(BaseModel):
    hostname: constr(min_length=1, max_length=255) = Field(
        ...,
        description="DNS hostname or FQDN"
    )
    ip_address: constr(regex=r"^(\d{1,3}\.){3}\d{1,3}$") = Field(
        ...,
        description="IPv4 address"
    )
    description: Optional[constr(max_length=1000)] = None

    @validator('ip_address')
    def validate_ip_address(cls, v):
        # Additional validation beyond regex
        octets = v.split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            raise ValueError('Invalid IP address range')
        if v.startswith('127.'):
            raise ValueError('Localhost addresses not allowed')
        return v

    @validator('hostname')
    def validate_hostname(cls, v):
        # Prevent command injection via hostname
        if any(char in v for char in ['`', '$', ';', '|', '&', '<', '>']):
            raise ValueError('Invalid characters in hostname')
        return v
```

### SQL Injection Prevention (Defense Layer 2)

**MANDATORY**: Use QueryBuilder or SQLAlchemy ORM. NEVER use raw SQL strings.

#### Preferred: QueryBuilder Pattern (94% of OpenWatch endpoints)

**Why QueryBuilder**: OpenWatch has standardized on QueryBuilder for all PostgreSQL queries. It provides:
- Automatic SQL injection protection through parameterization
- Fluent, readable interface
- Consistent patterns across the codebase
- Easy to test and maintain

```python
# BEST PRACTICE - QueryBuilder (OpenWatch standard)
from backend.app.utils.query_builder import QueryBuilder
from sqlalchemy import text

def get_hosts_by_group(db: Session, group_name: str) -> List[dict]:
    """
    Get hosts filtered by group using QueryBuilder.

    Why QueryBuilder: Consistent with 94% of OpenWatch endpoints,
    automatic parameterization, easy to read and maintain.
    """
    builder = (
        QueryBuilder("hosts h")
        .select("h.id", "h.hostname", "h.ip_address", "h.status")
        .join("host_group_memberships hgm", "h.id = hgm.host_id", "LEFT")
        .join("host_groups hg", "hg.id = hgm.group_id", "LEFT")
        .where("hg.name = :group_name", group_name, "group_name")
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    return [dict(row._mapping) for row in result]

# ACCEPTABLE - SQLAlchemy ORM (for complex relationships)
from sqlalchemy import select
from backend.app.models import Host

async def get_hosts_by_group_orm(db: AsyncSession, group_name: str) -> List[Host]:
    """
    Use ORM when you need full model instances with relationships.

    Why ORM: Good for complex object graphs, but QueryBuilder is
    preferred for most query operations in OpenWatch.
    """
    result = await db.execute(
        select(Host)
        .join(Host.groups)
        .filter(HostGroup.name == group_name)  # ← Parameterized
    )
    return result.scalars().all()

# WRONG - Raw SQL (vulnerable to injection)
def get_hosts_by_group_unsafe(db: Session, group_name: str) -> List[dict]:
    # DO NOT DO THIS! NO RAW SQL STRINGS!
    query = f"SELECT * FROM hosts WHERE group_name = '{group_name}'"
    result = db.execute(text(query))  # ← SQL INJECTION VULNERABILITY!
    return result.fetchall()
```

**Migration Status** (as of 2025-11-04):
- 16 out of 17 endpoints (94%) use QueryBuilder
- Hosts: 5/6 endpoints (83%)
- Scans: 5/5 endpoints (100%)
- Users: 6/6 endpoints (100%)
- See `docs/QUERYBUILDER_EXPLANATION.md` for full details

### Command Injection Prevention (Defense Layer 3)

**MANDATORY**: NEVER use `shell=True`. Use argument lists.

```python
import subprocess

# CORRECT - Argument list (safe)
def get_oscap_version() -> str:
    result = subprocess.run(
        ['oscap', '--version'],  # ← List of arguments
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout

# WRONG - Shell command (vulnerable)
def get_oscap_version() -> str:
    # DO NOT DO THIS!
    result = subprocess.run(
        'oscap --version',  # ← String passed to shell
        shell=True,         # ← DANGEROUS!
        capture_output=True,
        text=True
    )
    return result.stdout
```

### Password Storage (Argon2id)

**MANDATORY**: Use Argon2id for password hashing.

```python
from passlib.context import CryptContext

# Configuration
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64MB
    argon2__time_cost=3,
    argon2__parallelism=4,
)

# Hash password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Verify password
def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False
```

### Encryption (AES-256-GCM)

**MANDATORY**: Use EncryptionService for all encryption.

```python
from backend.app.services.encryption_service import EncryptionService

# Encrypt
enc_service = EncryptionService()
encrypted_data = enc_service.encrypt("sensitive_password")

# Decrypt
decrypted_data = enc_service.decrypt(encrypted_data)

# Store in database
host.encrypted_credentials = encrypted_data
```

### JWT Token Security

**Configuration**: `backend/app/services/jwt_manager.py`
- Algorithm: RS256 (asymmetric)
- Key Size: RSA-2048
- Access Token: 1 hour expiry
- Refresh Token: 7 days expiry, rotation on use

```python
from backend.app.services.jwt_manager import JWTManager

jwt_manager = JWTManager()

# Create tokens
tokens = jwt_manager.create_tokens(
    user_id=user.id,
    username=user.username,
    roles=[role.name for role in user.roles]
)

# Verify token
try:
    payload = jwt_manager.verify_token(token)
    user_id = payload['user_id']
except JWTError:
    raise HTTPException(status_code=401, detail="Invalid token")
```

### Rate Limiting

**Configuration**: `backend/app/middleware/rate_limiter.py`
- Per User: 100 requests/minute
- Per IP: 1000 requests/minute
- Per Endpoint: Custom limits

```python
from fastapi import Depends
from backend.app.middleware.rate_limiter import rate_limit

@router.post("/auth/login")
@rate_limit(requests=5, window=60)  # 5 attempts per minute
async def login(credentials: LoginRequest):
    # Login logic
    pass
```

### Audit Logging

**MANDATORY**: Log all security-relevant events.

```python
import logging
from backend.app.utils.audit_logger import audit_log

audit_logger = logging.getLogger('openwatch.audit')

# Log authentication attempt
audit_log(
    event_type="AUTH_LOGIN_SUCCESS",
    user_id=user.id,
    username=user.username,
    ip_address=request.client.host,
    user_agent=request.headers.get("User-Agent"),
    details={"method": "password"}
)

# Log authorization failure
audit_log(
    event_type="AUTH_PERMISSION_DENIED",
    user_id=current_user.id,
    resource=f"/api/v1/hosts/{host_id}",
    action="delete",
    reason="missing_permission",
    ip_address=request.client.host
)

# Log data access
audit_log(
    event_type="DATA_ACCESS",
    user_id=current_user.id,
    resource="scan_results",
    resource_id=scan_id,
    action="read",
    ip_address=request.client.host
)
```

### Secrets Management

**MANDATORY**: NO secrets in code or containers.

```python
# CORRECT - Environment variables
import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str
    MASTER_KEY: str
    DATABASE_URL: str

    class Config:
        env_file = ".env"

settings = Settings()

# WRONG - Hardcoded secrets
SECRET_KEY = "hardcoded-secret-key-123"  # DO NOT DO THIS!
MASTER_KEY = "another-secret"            # DO NOT DO THIS!
```

**Generate Secrets**:
```bash
# Generate random secrets
openssl rand -hex 32  # SECRET_KEY
openssl rand -hex 32  # MASTER_KEY

# Generate RSA key pair
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

---

## 🤖 Agentic Coding Principles

Based on [Anthropic's Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices):

### 1. Write Tests Before Implementation

**Pattern**: Test-Driven Development (TDD)

```python
# STEP 1: Write failing test
@pytest.mark.unit
async def test_calculate_compliance_score():
    """Test compliance score calculation."""
    score = calculate_compliance_score(
        pass_count=87,
        fail_count=13,
        total_count=100
    )
    assert score == 87.0

# STEP 2: Implement function to pass test
def calculate_compliance_score(
    pass_count: int,
    fail_count: int,
    total_count: int
) -> float:
    if total_count == 0:
        return 0.0
    return (pass_count / total_count) * 100.0

# STEP 3: Run test and verify
pytest tests/unit/test_scoring.py -v
```

### 2. Incremental Development

**Pattern**: Small, working increments with verification.

```bash
# STEP 1: Create minimal working feature
# - Add model
# - Add endpoint stub
# - Add basic test
git add backend/app/models/vulnerability.py
git commit -m "feat: Add Vulnerability model (minimal)"

# STEP 2: Add business logic
# - Implement service layer
# - Add validation
git add backend/app/services/vulnerability_service.py
git commit -m "feat: Add vulnerability scoring service"

# STEP 3: Add API endpoint
# - Wire up controller
# - Add integration test
git add backend/app/routes/vulnerabilities.py
git commit -m "feat: Add vulnerability API endpoints"

# STEP 4: Add frontend
# - Create component
# - Add to routing
git add frontend/src/components/vulnerabilities/
git commit -m "feat: Add vulnerability management UI"
```

### 3. Verify After Every Change

**Pattern**: Continuous verification loop.

```bash
# After each code change:
1. Run related tests
   pytest tests/unit/test_vulnerability.py -v

2. Check code quality
   black backend/app/services/vulnerability_service.py
   flake8 backend/app/services/vulnerability_service.py

3. Manual smoke test
   curl http://localhost:8000/api/v1/vulnerabilities

4. Commit if passing
   git add .
   git commit -m "feat: ..."
```

### 4. Use Type Hints Everywhere

**Pattern**: Explicit types for AI-assisted development.

```python
# GOOD - Explicit types help AI understand intent
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

async def get_scan_results(
    scan_id: UUID,
    severity: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Fetch scan results with optional severity filter.

    Args:
        scan_id: UUID of the scan
        severity: Filter by severity (high, medium, low)
        limit: Maximum number of results to return

    Returns:
        List of scan result dictionaries
    """
    # Implementation...
    pass
```

### 5. Document Intent with Docstrings

**Pattern**: Clear documentation for AI context.

```python
def validate_scap_profile(profile_id: str, datastream_path: str) -> bool:
    """
    Validate that a SCAP profile exists in the given datastream.

    This function parses the SCAP datastream XML and verifies:
    1. The profile ID is present in the benchmark
    2. The profile has at least one selected rule
    3. The profile is not marked as deprecated

    Args:
        profile_id: Full profile ID (e.g., 'xccdf_org.ssgproject.content_profile_stig')
        datastream_path: Absolute path to SCAP datastream file

    Returns:
        True if profile is valid and usable, False otherwise

    Raises:
        FileNotFoundError: If datastream file doesn't exist
        XMLParseError: If datastream is malformed XML

    Example:
        >>> validate_scap_profile(
        ...     'xccdf_org.ssgproject.content_profile_stig',
        ...     '/app/data/scap/ssg-rhel8-ds.xml'
        ... )
        True
    """
    # Implementation...
    pass
```

### 6. Error Handling with Context

**Pattern**: Rich error messages for debugging.

```python
class ScanExecutionError(Exception):
    """Raised when SCAP scan execution fails."""

    def __init__(
        self,
        message: str,
        scan_id: UUID,
        host_id: UUID,
        exit_code: Optional[int] = None,
        stderr: Optional[str] = None
    ):
        self.scan_id = scan_id
        self.host_id = host_id
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(
            f"{message} (scan_id={scan_id}, host_id={host_id}, "
            f"exit_code={exit_code})"
        )

# Usage
try:
    result = await execute_oscap_scan(host, profile)
except subprocess.CalledProcessError as e:
    raise ScanExecutionError(
        message="oscap scan failed",
        scan_id=scan.id,
        host_id=host.id,
        exit_code=e.returncode,
        stderr=e.stderr
    )
```

### 7. Consistent Naming Conventions

**Pattern**: Clear, predictable naming.

```python
# Database models: PascalCase singular
class Host(Base): pass
class Scan(Base): pass
class ComplianceRule(Document): pass

# Services: PascalCase + "Service" suffix
class ScanService: pass
class EncryptionService: pass
class UnifiedSSHService: pass

# Repositories: PascalCase + "Repository" suffix
class HostRepository(BaseRepository): pass
class ScanRepository(BaseRepository): pass

# API endpoints: kebab-case
@router.get("/api/v1/compliance-rules")
@router.post("/api/v1/scans/execute")

# Functions: snake_case verbs
async def create_scan(...): pass
async def get_host_by_id(...): pass
async def execute_scan_task(...): pass

# Variables: snake_case nouns
scan_result = ...
compliance_score = ...
```

### 8. Refactor Fearlessly with Tests

**Pattern**: Safe refactoring with test safety net.

```bash
# BEFORE refactoring:
# 1. Ensure tests exist and pass
pytest tests/integration/test_scan_service.py -v
# ✓ test_create_scan PASSED
# ✓ test_execute_scan PASSED
# ✓ test_cancel_scan PASSED

# 2. Refactor code (e.g., extract method)
# 3. Re-run tests
pytest tests/integration/test_scan_service.py -v
# ✓ test_create_scan PASSED
# ✓ test_execute_scan PASSED
# ✓ test_cancel_scan PASSED

# If tests still pass, refactor is safe!
```

### 9. Use TODO Comments Strategically

**Pattern**: Structured TODOs for tracking technical debt.

```python
# TODO(security): Implement certificate pinning for webhook requests
# Priority: HIGH
# Blocked by: Need to determine certificate rotation strategy
# Reference: OWASP ASVS 9.2.1

# TODO(performance): Add caching layer for compliance rules
# Priority: MEDIUM
# Benchmark shows 2s query time for 10k rules
# Consider Redis cache with 5min TTL

# TODO(refactor): Extract SSH connection pooling to separate service
# Priority: LOW
# Current implementation in UnifiedSSHService works but could be cleaner
# See: docs/ARCHITECTURE.md section on service layer
```

### 10. Leverage AI for Code Review

**Pattern**: Clear commit messages for AI context.

```bash
# GOOD commit message (AI can understand context)
git commit -m "fix(auth): Prevent timing attack in password verification

Changed password comparison from == to constant-time compare
to prevent attackers from determining password length via timing.

Security Impact: Fixes potential information disclosure (CWE-208)
Testing: Added test_password_timing_attack_prevention

References:
- OWASP Testing Guide v4.2 Section 4.4.9
- docs/SECURITY_AUDIT_REPORT.md#auth-001
"

# BAD commit message (AI cannot help review)
git commit -m "fixed bug"
```

---

## 🚨 Troubleshooting

### Backend Code Changes Not Reflecting

**Symptom**: Modified Python code not taking effect in running container.

**Root Cause**: Backend containers don't have hot-reload enabled.

**Solution**:
```bash
# Option 1: Copy file and restart
docker cp backend/app/services/scan_service.py \
    openwatch-backend:/app/backend/app/services/scan_service.py
docker restart openwatch-backend

# Option 2: Rebuild container
./stop-openwatch.sh
./start-openwatch.sh --runtime docker --build
```

### Authentication Failures (localStorage Key)

**Symptom**: "Unauthorized" errors despite successful login.

**Root Cause**: Frontend using wrong localStorage key.

**Solution**: Verify correct key in API client:
```typescript
// CORRECT
const token = localStorage.getItem('auth_token');

// WRONG
const token = localStorage.getItem('token');
```

**Check**: `frontend/src/services/api.ts` should have:
```typescript
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');  // ← Must be 'auth_token'
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

### UUID vs Integer Confusion

**Symptom**: "Invalid UUID format" or type errors.

**Root Cause**: Treating UUID as integer.

**Solution**:
```python
# WRONG
host_id = 12345
host = await db.get(Host, host_id)  # TypeError!

# CORRECT
from uuid import UUID
host_id = UUID("550e8400-e29b-41d4-a716-446655440000")
host = await db.get(Host, host_id)

# Frontend: UUIDs are strings
const hostId: string = "550e8400-e29b-41d4-a716-446655440000";
await api.get(`/api/v1/hosts/${hostId}`);
```

### Database Connection Errors

**Symptom**: "Could not connect to PostgreSQL/MongoDB"

**Check**:
```bash
# Verify containers running
docker ps | grep -E "postgres|mongo"

# Check PostgreSQL
docker exec -it openwatch-db psql -U openwatch -d openwatch -c "SELECT 1;"

# Check MongoDB
docker exec -it openwatch-mongodb mongosh --eval "db.adminCommand('ping')"

# Review logs
docker logs openwatch-db --tail 50
docker logs openwatch-mongodb --tail 50
```

### Celery Tasks Not Executing

**Symptom**: Scans stuck in "queued" status.

**Check**:
```bash
# Verify worker running
docker ps | grep worker

# Check worker logs
docker logs openwatch-worker --tail 100 --follow

# Verify Redis connection
docker exec -it openwatch-redis redis-cli ping
# Should return: PONG

# Check Celery queue
docker exec -it openwatch-backend bash
celery -A app.tasks inspect active
```

### SCAP Scan Failures

**Symptom**: Scans fail with "oscap command not found" or permission errors.

**Check**:
```bash
# Verify oscap installed on target
ssh user@target "which oscap && oscap --version"

# Verify sudo access (if required)
ssh user@target "sudo -n oscap --version"

# Check scan logs
docker logs openwatch-worker --tail 200 | grep -i "oscap\|scan"

# Review scan result in database
docker exec -it openwatch-db psql -U openwatch -d openwatch \
  -c "SELECT id, status, error_message FROM scans ORDER BY created_at DESC LIMIT 5;"
```

### MongoDB Index Conflicts

**Symptom**: "Index already exists with a different name" or "duplicate key error"

**Root Cause**: Historically, both MongoDB init script and Beanie ODM created indexes, causing naming conflicts.

**Solution**: **RESOLVED as of 2025-10-26** - Beanie ODM now manages ALL indexes exclusively.

**What Changed**:
1. ✅ All index definitions migrated to `backend/app/models/mongo_models.py`
2. ✅ MongoDB init script (`01-init-openwatch-user.js`) no longer creates indexes
3. ✅ Beanie creates indexes automatically on application startup
4. ✅ 21 indexes across 3 collections now managed by Beanie

**Verify Beanie Index Management**:
```bash
# Check backend logs for successful Beanie initialization
docker logs openwatch-backend | grep -i "beanie\|index"

# Should see: "Beanie ODM initialized successfully"
# Should NOT see: "Index already exists with a different name"

# Verify indexes in MongoDB
docker exec -it openwatch-mongodb mongosh openwatch_rules --eval "db.compliance_rules.getIndexes()"

# Should show 17 indexes including:
# - idx_rule_id (unique)
# - idx_nist_r4, idx_nist_r5 (framework queries)
# - idx_text_search (full-text search)
```

**If index conflicts occur**:
```bash
# 1. Deep clean to reset MongoDB
./stop-openwatch.sh --deep-clean

# 2. Rebuild with no cache to ensure latest code
./start-openwatch.sh --runtime docker --build

# 3. Verify Beanie created all indexes
docker logs openwatch-backend | grep "Beanie"
```

### Container Health Check Failures

**Symptom**: Container shows "unhealthy" status.

**Check**:
```bash
# Inspect health check
docker inspect openwatch-backend | grep -A 10 "Health"

# View health check logs
docker logs openwatch-backend 2>&1 | grep -i "health"

# Manual health check
curl http://localhost:8000/health
# Should return: {"status": "healthy"}
```

---

## 📚 Additional Resources

### Documentation
- **Main README**: `README.md`
- **API Documentation**: http://localhost:8000/api/docs (Swagger UI)
- **Architecture Docs**: `docs/` directory
- **Security Guides**:
  - `docs/COMPREHENSIVE_SECURITY_AND_CODE_ANALYSIS.md`
  - `docs/FIPS_COMPLIANCE_VALIDATION.md`
  - `docs/SECURITY_AUDIT_API_2025.md`
- **Development Guides**:
  - `docs/DEVELOPMENT_WORKFLOW.md`
  - `docs/TESTING_STRATEGY.md`
  - `docs/STOP_BREAKING_THINGS.md`

### External Standards
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **NIST SP 800-53**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **NIST SP 800-218 SSDF**: https://csrc.nist.gov/publications/detail/sp/800-218/final
- **ISO 27001**: https://www.iso.org/isoiec-27001-information-security.html
- **CMMC 2.0**: https://www.acq.osd.mil/cmmc/
- **FedRAMP**: https://www.fedramp.gov/
- **SCAP Specification**: https://csrc.nist.gov/projects/security-content-automation-protocol

### AI Development
- **Claude Code Best Practices**: https://www.anthropic.com/engineering/claude-code-best-practices
- **Anthropic Prompt Engineering**: https://docs.anthropic.com/claude/docs/prompt-engineering

---

## 🔄 Version History

- **v1.0.0** (2025-10-26): Initial CLAUDE.md for OpenWatch
  - Added comprehensive security standards (OWASP, NIST, ISO 27001, CMMC, FedRAMP)
  - Documented dual database architecture with repository pattern
  - Added agentic coding principles from Anthropic best practices
  - Included troubleshooting guide for common issues

---

## 📝 Notes for AI Assistants

When working with OpenWatch:

1. **Security First**: Always consider security implications before functionality
2. **Use Existing Patterns**: Follow established patterns (repositories, services, etc.)
3. **Test Everything**: Write tests before implementation (TDD)
4. **Type Safety**: Full type annotations required (Python MyPy, TypeScript strict mode)
5. **No Shortcuts**: Don't bypass validation, encryption, or audit logging
6. **Document Intent**: Clear docstrings and comments explaining "why" not just "what"
7. **Verify Incrementally**: Test after every change, commit small working increments
8. **Ask Questions**: If unsure about security implications, ASK before implementing

---

**END OF CLAUDE.md**
