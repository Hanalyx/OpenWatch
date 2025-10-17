# Security Assessment Phase 3: Medium Priority - Assessment

**Date:** 2025-10-16
**Assessment Reference:** SECURITY_ASSESSMENT_COMPLETE.md Phase 3
**Status:** ❌ **NOT STARTED** (0 of 6 tasks complete)

---

## Executive Summary

Phase 3 (Medium Priority - Weeks 2-3) consists of **6 security enhancement tasks** that will further harden the OpenWatch application. These are classified as "medium priority" because:

1. **Phases 1 & 2 are complete** - Critical and high-priority vulnerabilities have been addressed
2. **Current risk level is LOW** - The application is already secure from the most serious threats
3. **These are enhancements** - Not fixing active vulnerabilities, but adding defense-in-depth

**Current Status:** ❌ 0/6 tasks complete (0%)
**Estimated Effort:** 15-25 hours (2-3 weeks)
**Priority:** MEDIUM (can be scheduled after deprecation work)

---

## Phase 3 Tasks Overview

| # | Task | Effort | Risk if Not Done | Priority |
|---|------|--------|------------------|----------|
| 1 | Rate limiting on authentication | 3-4 hours | MEDIUM | HIGH |
| 2 | CORS configuration | 2-3 hours | LOW | MEDIUM |
| 3 | Path traversal in file uploads | 3-4 hours | MEDIUM-HIGH | HIGH |
| 4 | Input validation decorators | 4-6 hours | MEDIUM | MEDIUM |
| 5 | Request size limits | 2-3 hours | LOW | LOW |
| 6 | TLS configuration update | 2-3 hours | LOW | MEDIUM |

**Total Effort:** 16-23 hours

---

## Task 1: Add Rate Limiting to Authentication Endpoints

### Current Status: ❌ NOT IMPLEMENTED

**Risk Level:** MEDIUM
**Priority:** HIGH (should be done first in Phase 3)
**Estimated Effort:** 3-4 hours

### Problem Statement

**Security Finding:**
- **Issue:** No rate limiting on authentication endpoints (login, token refresh, MFA)
- **Risk:** Brute-force attacks, credential stuffing, DDoS on auth endpoints
- **Impact:** Attackers can make unlimited login attempts

**Current State:**
- Login endpoint: `/api/v1/auth/login` - No rate limiting
- Token refresh: `/api/v1/auth/refresh` - No rate limiting
- MFA verification: `/api/v1/auth/mfa/verify` - No rate limiting

### Recommended Implementation

**Option A: FastAPI Rate Limiting Middleware (Recommended)**

```python
# backend/app/middleware/rate_limiter.py
from fastapi import Request, HTTPException
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio

class RateLimiter:
    def __init__(self, requests: int = 5, window_seconds: int = 60):
        self.requests = requests
        self.window_seconds = window_seconds
        self.request_counts = defaultdict(list)
        self.lock = asyncio.Lock()

    async def check_rate_limit(self, identifier: str) -> bool:
        """Check if request should be rate limited"""
        async with self.lock:
            now = datetime.utcnow()
            window_start = now - timedelta(seconds=self.window_seconds)

            # Clean old requests
            self.request_counts[identifier] = [
                req_time for req_time in self.request_counts[identifier]
                if req_time > window_start
            ]

            # Check limit
            if len(self.request_counts[identifier]) >= self.requests:
                return True  # Rate limited

            # Record this request
            self.request_counts[identifier].append(now)
            return False  # Allowed

# Middleware
auth_rate_limiter = RateLimiter(requests=5, window_seconds=60)

async def rate_limit_auth(request: Request, call_next):
    """Rate limit authentication endpoints"""
    if request.url.path.startswith("/api/v1/auth"):
        # Use IP address as identifier
        client_ip = request.client.host

        if await auth_rate_limiter.check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Too many authentication attempts. Please try again later."
            )

    return await call_next(request)
```

**Option B: slowapi Library (Simpler)**

```bash
pip install slowapi
```

```python
# backend/app/main.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# In auth routes
@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginRequest):
    ...
```

### Benefits
- ✅ Prevents brute-force attacks
- ✅ Mitigates credential stuffing
- ✅ Protects against DDoS on auth endpoints
- ✅ Improves overall security posture

### Integration with Our Credentials Work

Our recent unified_credentials work makes rate limiting easier:
- ✅ `CentralizedAuthService` provides single point for rate limiting
- ✅ `last_used_at` field tracks credential access
- ✅ Can implement per-credential rate limiting

**Enhanced Implementation:**
```python
# Rate limiting per credential, not just per IP
async def check_credential_rate_limit(credential_id: str) -> bool:
    """Check if credential is being accessed too frequently"""
    credential = auth_service.get_credential(credential_id)

    if credential.last_used_at:
        time_since_last_use = datetime.utcnow() - credential.last_used_at
        if time_since_last_use < timedelta(seconds=5):
            return True  # Rate limited

    return False
```

---

## Task 2: Implement CORS Configuration

### Current Status: ❌ NOT IMPLEMENTED

**Risk Level:** LOW
**Priority:** MEDIUM
**Estimated Effort:** 2-3 hours

### Problem Statement

**Security Finding:**
- **Issue:** Missing CORS configuration
- **Risk:** Frontend from unauthorized domains could access the API
- **Impact:** Potential data leakage if API accessed from malicious sites

**Current State:**
- No CORS middleware configured
- API accessible from any origin (default behavior)

### Recommended Implementation

```python
# backend/app/main.py
from fastapi.middleware.cors import CORSMiddleware

# CORS Configuration
allowed_origins = [
    "http://localhost:3000",  # Development
    "http://localhost:3001",  # Development (Vite)
    "https://openwatch.yourdomain.com",  # Production
    "https://app.yourdomain.com",  # Production
]

# Allow environment variable override
import os
custom_origins = os.getenv("ALLOWED_ORIGINS")
if custom_origins:
    allowed_origins.extend(custom_origins.split(","))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count", "X-Deprecation-Warning"],  # Custom headers
)
```

### Benefits
- ✅ Prevents unauthorized frontend access
- ✅ Protects against CSRF attacks
- ✅ Controls which domains can access the API
- ✅ Industry best practice

### Complexity
**Low** - FastAPI has built-in CORS middleware

---

## Task 3: Fix Path Traversal in File Uploads

### Current Status: ❌ NOT FIXED

**Risk Level:** MEDIUM-HIGH
**Priority:** HIGH (should be 2nd priority in Phase 3)
**Estimated Effort:** 3-4 hours

### Problem Statement

**Security Finding:**
- **Endpoint:** `/api/v1/scap-import/upload`
- **Issue:** Insufficient filename sanitization
- **Risk:** Arbitrary file write via path traversal (e.g., `../../etc/passwd`)
- **Impact:** Attackers could overwrite system files

**Example Attack:**
```bash
curl -X POST http://localhost:8000/api/v1/scap-import/upload \
  -F "file=@malicious.xml;filename=../../../tmp/evil.xml"
```

### Recommended Implementation

```python
# backend/app/services/file_upload_service.py
import os
from pathlib import Path
import uuid

class SecureFileUploadService:
    def __init__(self, upload_dir: str = "/app/data/scap"):
        self.upload_dir = Path(upload_dir).resolve()
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Remove any directory components
        filename = os.path.basename(filename)

        # Remove null bytes
        filename = filename.replace("\x00", "")

        # Remove path separators
        filename = filename.replace("/", "").replace("\\", "")

        # Remove leading dots
        filename = filename.lstrip(".")

        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext

        # If empty, generate random name
        if not filename:
            filename = f"{uuid.uuid4()}.xml"

        return filename

    def save_uploaded_file(self, file_content: bytes, original_filename: str) -> Path:
        """Safely save uploaded file"""
        # Sanitize filename
        safe_filename = self.sanitize_filename(original_filename)

        # Create full path
        file_path = self.upload_dir / safe_filename

        # Verify path is within upload directory (double-check)
        if not str(file_path.resolve()).startswith(str(self.upload_dir)):
            raise ValueError("Path traversal attempt detected")

        # Check if file exists (prevent overwrite)
        if file_path.exists():
            name, ext = os.path.splitext(safe_filename)
            safe_filename = f"{name}_{uuid.uuid4().hex[:8]}{ext}"
            file_path = self.upload_dir / safe_filename

        # Write file
        file_path.write_bytes(file_content)

        # Set restrictive permissions
        file_path.chmod(0o644)

        return file_path
```

**Usage in endpoint:**
```python
@router.post("/api/v1/scap-import/upload")
async def upload_scap_file(file: UploadFile = File(...)):
    # Read file content
    content = await file.read()

    # Save securely
    upload_service = SecureFileUploadService()
    saved_path = upload_service.save_uploaded_file(content, file.filename)

    return {"filename": saved_path.name, "path": str(saved_path)}
```

### Benefits
- ✅ Prevents path traversal attacks
- ✅ Prevents file overwrite
- ✅ Restricts upload directory
- ✅ Sets secure file permissions

---

## Task 4: Add Input Validation Decorators

### Current Status: ❌ NOT IMPLEMENTED

**Risk Level:** MEDIUM
**Priority:** MEDIUM
**Estimated Effort:** 4-6 hours

### Problem Statement

**Security Finding:**
- **Issue:** Insufficient input validation (8 endpoints)
- **Risk:** SQL injection, XSS, command injection
- **Impact:** Various injection attacks possible

**Current State:**
- Input validation scattered across endpoints
- No consistent validation pattern
- Code duplication (from assessment: 550 lines duplicate)

### Recommended Implementation

**Create reusable validation decorators:**

```python
# backend/app/validators/decorators.py
from functools import wraps
from fastapi import HTTPException
import re

def validate_uuid(field_name: str):
    """Decorator to validate UUID format"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            value = kwargs.get(field_name)
            if value:
                uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                if not re.match(uuid_pattern, str(value), re.IGNORECASE):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid UUID format for {field_name}"
                    )
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def sanitize_input(field_name: str, max_length: int = 1000):
    """Decorator to sanitize user input"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            value = kwargs.get(field_name)
            if value and isinstance(value, str):
                # Remove null bytes
                value = value.replace("\x00", "")

                # Limit length
                if len(value) > max_length:
                    raise HTTPException(
                        status_code=400,
                        detail=f"{field_name} exceeds maximum length of {max_length}"
                    )

                # Remove control characters (except newlines/tabs)
                value = ''.join(char for char in value if char.isprintable() or char in '\n\r\t')

                kwargs[field_name] = value
            return await func(*args, **kwargs)
        return wrapper
    return decorator
```

**Usage:**
```python
@router.get("/api/v1/hosts/{host_id}")
@validate_uuid("host_id")
async def get_host(host_id: str, db: Session = Depends(get_db)):
    ...

@router.post("/api/v1/scans")
@sanitize_input("scan_name", max_length=255)
async def create_scan(scan_name: str, ...):
    ...
```

### Benefits
- ✅ Consistent validation across endpoints
- ✅ Reduces code duplication
- ✅ Prevents injection attacks
- ✅ Easier to maintain

---

## Task 5: Implement Request Size Limits

### Current Status: ⚠️ PARTIALLY IMPLEMENTED

**Risk Level:** LOW
**Priority:** LOW
**Estimated Effort:** 2-3 hours

### Problem Statement

**Security Finding:**
- **Issue:** No request size limits (potential DoS)
- **Risk:** Large requests could exhaust memory/disk
- **Impact:** Denial of service

**Current State:**
- Starlette DoS vulnerability (CVE-2025-59343) noted
- Mitigation mentioned: "Request size limits implemented"
- Need to verify and document

### Verification Needed

```python
# Check if already implemented in main.py or middleware
# Look for:
# - app.add_middleware(LimitUploadSize, max_upload_size=...)
# - Request body size limits
```

### Recommended Implementation (if not present)

```python
# backend/app/middleware/request_size_limiter.py
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_upload_size: int = 100 * 1024 * 1024):  # 100MB
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        # Check content-length header
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_upload_size:
            raise HTTPException(
                status_code=413,
                detail=f"Request too large. Maximum size: {self.max_upload_size} bytes"
            )

        return await call_next(request)

# In main.py
app.add_middleware(RequestSizeLimitMiddleware, max_upload_size=100 * 1024 * 1024)
```

### Benefits
- ✅ Prevents memory exhaustion
- ✅ Mitigates DoS attacks
- ✅ Protects disk space

---

## Task 6: Update TLS Configuration

### Current Status: ⚠️ UNKNOWN

**Risk Level:** LOW
**Priority:** MEDIUM
**Estimated Effort:** 2-3 hours

### Problem Statement

**Security Finding:**
- **Issue:** TLS configuration may need hardening
- **Risk:** Weak ciphers, old protocols
- **Impact:** Man-in-the-middle attacks

### Areas to Review

1. **Nginx/Reverse Proxy TLS Configuration**
2. **MongoDB TLS Configuration**
3. **PostgreSQL TLS Configuration**
4. **Inter-service communication TLS**

### Recommended TLS Configuration

**Nginx (if used):**
```nginx
# Strong TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**MongoDB TLS:**
- Already configured with new certificates (Phase 1)
- Verify TLS 1.2+ only

**PostgreSQL TLS:**
- Verify ssl_min_protocol_version = 'TLSv1.2'
- Ensure strong ciphers

### Benefits
- ✅ Prevents downgrade attacks
- ✅ Ensures forward secrecy
- ✅ Industry best practice

---

## Summary & Recommendations

### Phase 3 Status Matrix

| Task | Status | Risk | Priority | Effort | Recommendation |
|------|--------|------|----------|--------|----------------|
| 1. Rate limiting | ❌ Not done | MEDIUM | HIGH | 3-4h | Do first |
| 2. CORS | ❌ Not done | LOW | MEDIUM | 2-3h | Do third |
| 3. Path traversal | ❌ Not done | MEDIUM-HIGH | HIGH | 3-4h | Do second |
| 4. Input validation | ❌ Not done | MEDIUM | MEDIUM | 4-6h | Do fourth |
| 5. Request limits | ⚠️ Verify | LOW | LOW | 2-3h | Verify first, then implement if needed |
| 6. TLS config | ⚠️ Unknown | LOW | MEDIUM | 2-3h | Review and document |

### Recommended Implementation Order

**If doing Phase 3 now:**
1. **Rate limiting** (3-4h) - Prevents brute-force attacks
2. **Path traversal** (3-4h) - Prevents file system attacks
3. **CORS** (2-3h) - Quick win, industry standard
4. **Input validation** (4-6h) - Reduces code duplication
5. **Request limits** (2-3h) - Verify/implement DoS protection
6. **TLS config** (2-3h) - Review and harden

**Total: 16-23 hours (2-3 weeks)**

### Alternative: Defer Phase 3

**Rationale for deferring:**
- ✅ Phase 1 & 2 complete (all critical/high items done)
- ✅ Current risk level: LOW
- ✅ system_credentials deprecation is well-planned (3 weeks)
- ✅ Phase 3 items are enhancements, not urgent fixes

**Suggested Timeline:**
1. **Now:** Complete system_credentials deprecation (3 weeks)
2. **After deprecation:** Implement Phase 3 security enhancements (2-3 weeks)
3. **Then:** Move to Phase 4 code refactoring (4-6 weeks)

This approach:
- ✅ Completes one major project before starting another
- ✅ Maintains focus and momentum
- ✅ Delivers value incrementally
- ✅ Reduces context switching

---

## Conclusion

**Phase 3 Status:** ❌ **NOT STARTED** (0/6 tasks complete)

All Phase 3 tasks are **enhancements** rather than critical fixes. With Phases 1 & 2 complete, the application has a **LOW risk** security posture.

**Recommendation:** **Defer Phase 3 until after system_credentials deprecation is complete.** This allows focused execution on the deprecation work (already planned with GitHub issues, milestone, and automation), then tackle Phase 3 as a cohesive security enhancement project.

**Estimated Timeline:**
- Weeks 1-3: system_credentials deprecation
- Weeks 4-6: Phase 3 security enhancements
- Weeks 7-12: Phase 4 code refactoring (optional)

This provides a clear, sequential roadmap with measurable milestones.

---

**Assessment Date:** October 16, 2025
**Status:** Ready for decision - Continue with deprecation or start Phase 3
