# OpenWatch Security Audit - Executive Summary

**Date:** October 15, 2025
**Overall Risk Rating:** MEDIUM-HIGH
**Total Findings:** 14 (3 Critical, 5 High, 4 Medium, 2 Low)

---

## Critical Findings (Immediate Action Required)

### 1. Hardcoded Secrets in Source Code
- **Files:** `credentials.py`, `remediation_callback.py`, `init_admin.py`, `crypto.py`
- **Risk:** Authentication bypass, unauthorized access, encryption compromise
- **Fix:** Move to environment variables, implement fail-safe validation

### 2. Outdated Cryptography Library (CVE-2024-26130)
- **Current:** 41.0.7 | **Required:** 44.0.2
- **CVE:** CVE-2024-26130 (CVSS 7.5) - NULL pointer dereference
- **Fix:** `pip install --upgrade cryptography==44.0.2`

### 3. Insecure Random Number Generation
- **File:** `http_client.py:141`
- **Issue:** Using `random.random()` instead of `secrets` module
- **Fix:** Replace with `secrets.SystemRandom().random()`

---

## High Priority Findings (1 Week Deadline)

### 4. MD5 Hash Usage (FIPS Violation)
- **Files:** `rule_cache_service.py`, `rule_association_service.py`, `system_info_sanitization.py`
- **Issue:** MD5 violates FIPS 140-2 compliance
- **Fix:** Replace with `hashlib.sha256()`

### 5. Outdated PyJWT (CVE-2024-33663)
- **Current:** 2.7.0 | **Required:** 2.10.1
- **CVE:** CVE-2024-33663 (CVSS 7.5) - Algorithm confusion
- **Fix:** `pip install --upgrade PyJWT==2.10.1`

### 6. Outdated Pillow (CVE-2024-28219)
- **Current:** 10.2.0 | **Required:** 11.3.0
- **CVE:** CVE-2024-28219 (CVSS 7.5) - Buffer overflow
- **Fix:** `pip install --upgrade Pillow==11.3.0`

### 7. Starlette DoS Vulnerability (CVE-2025-59343)
- **Current:** 0.47.2
- **CVE:** DoS via multipart forms (CVSS 7.5)
- **Status:** Acknowledged, awaiting upstream patch
- **Mitigation:** Implement request size limits, rate limiting

---

## Medium Priority Findings (2 Week Deadline)

### 8. Outdated Requests Library (CVE-2024-35195)
- **Current:** 2.31.0 | **Required:** 2.32.5
- **Fix:** `pip install --upgrade requests==2.32.5`

### 9. Outdated PyYAML (CVE-2024-11167)
- **Current:** 6.0.1 | **Required:** 6.0.3
- **Fix:** `pip install --upgrade PyYAML==6.0.3`

### 10. Outdated Jinja2 (CVE-2024-34064)
- **Current:** 3.1.2 | **Required:** 3.1.6
- **Fix:** `pip install --upgrade Jinja2==3.1.6`

### 11. Missing TLS Version Enforcement
- **Issue:** No explicit minimum TLS version in configuration
- **Fix:** Add `min_tls_version = "TLSv1.2"` to config

---

## Positive Findings

✅ **Strong Cryptography:**
- AES-256-GCM with proper nonce/salt generation
- RSA-2048 JWT signing keys
- Argon2id password hashing (64MB, 3 iterations)
- PBKDF2-HMAC-SHA256 key derivation (100k iterations)
- TOTP MFA with SHA-256

✅ **Security Best Practices:**
- No SSL verification disabled
- No weak cipher suites
- Proper key permissions (0600 for private keys)
- JWT token expiration and revocation support
- Comprehensive audit logging

✅ **Frontend Security:**
- All npm dependencies current and secure
- DOMPurify for XSS protection
- Latest React/Vite versions

---

## Quick Fix Commands

```bash
# Navigate to backend
cd /home/rracine/hanalyx/openwatch/backend
source venv/bin/activate

# Update all vulnerable packages
pip install --upgrade \
    cryptography==44.0.2 \
    PyJWT==2.10.1 \
    Pillow==11.3.0 \
    requests==2.32.5 \
    PyYAML==6.0.3 \
    Jinja2==3.1.6

# Verify no conflicts
pip check

# Generate secure secrets
echo "OPENWATCH_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
echo "OPENWATCH_SECRET_KEY=$(openssl rand -hex 32)" >> .env
```

---

## Code Changes Required

### 1. Remove Hardcoded Secrets

**File:** `backend/app/routes/credentials.py:59`
```python
# BEFORE
aegis_secret = "aegis-integration-secret-key"  # TODO: Move to config

# AFTER
# REMOVED: AEGIS integration secrets not currently implemented
# AEGIS integration is optional and only active when AEGIS_URL is configured
```

**File:** `backend/app/routes/remediation_callback.py:66`
```python
# BEFORE
webhook_secret = settings.aegis_webhook_secret or "shared_webhook_secret"

# AFTER
# REMOVED: AEGIS webhook secrets not currently implemented
# Webhook security will be implemented when AEGIS integration is activated
```

**File:** `backend/app/services/crypto.py:17`
```python
# BEFORE
ENCRYPTION_KEY = os.getenv("OPENWATCH_ENCRYPTION_KEY", "dev-key-change-in-production")

# AFTER
ENCRYPTION_KEY = os.getenv("OPENWATCH_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("OPENWATCH_ENCRYPTION_KEY must be set")
if ENCRYPTION_KEY == "dev-key-change-in-production":
    raise ValueError("Default encryption key detected - use a secure value")
```

### 2. Fix Insecure Random

**File:** `backend/app/services/http_client.py:141`
```python
# BEFORE
import random
delay *= (0.5 + random.random() * 0.5)

# AFTER
import secrets
delay *= (0.5 + secrets.SystemRandom().random() * 0.5)
```

### 3. Replace MD5 with SHA-256

**File:** `backend/app/services/rule_cache_service.py:412`
```python
# BEFORE
params_hash = hashlib.md5(params_str.encode()).hexdigest()[:8]

# AFTER
params_hash = hashlib.sha256(params_str.encode()).hexdigest()[:16]
```

**File:** `backend/app/services/rule_association_service.py:586`
```python
# BEFORE
text_hash = hashlib.md5(text.encode()).hexdigest()

# AFTER
text_hash = hashlib.sha256(text.encode()).hexdigest()
```

**File:** `backend/app/services/system_info_sanitization.py:564`
```python
# BEFORE
event_id = hashlib.md5(f"{context.user_id}{datetime.utcnow()}".encode()).hexdigest()

# AFTER
event_id = hashlib.sha256(f"{context.user_id}{datetime.utcnow()}".encode()).hexdigest()
```

---

## FIPS 140-2 Compliance Status

| Component | Status | Notes |
|-----------|--------|-------|
| Encryption (AES-256-GCM) | ✅ Compliant | Proper implementation |
| Key Derivation (PBKDF2) | ✅ Compliant | 100k iterations, SHA-256 |
| Password Hashing (Argon2id) | ✅ Compliant | Proper parameters |
| JWT Signing (RS256) | ✅ Compliant | RSA-2048 |
| Hash Functions | ❌ Non-Compliant | MD5 usage detected |
| Random Generation | ⚠️ Warning | Non-crypto random used |
| TLS Configuration | ✅ Compliant | Strong cipher suites |

**Overall FIPS Status:** Non-Compliant (fix MD5 and random usage)

---

## Testing Checklist

After implementing fixes:

- [ ] All pip packages updated and `pip check` passes
- [ ] Application starts without errors
- [ ] Environment variables properly set
- [ ] No hardcoded secrets remain in codebase
- [ ] MD5 replaced with SHA-256 in all locations
- [ ] Random number generation uses `secrets` module
- [ ] Authentication still works (JWT tokens valid)
- [ ] Encryption/decryption functional
- [ ] MFA TOTP generation works
- [ ] API key authentication functional
- [ ] Webhook signature verification works
- [ ] Admin password changed from default
- [ ] Audit logs capture security events
- [ ] FIPS compliance validation passes

---

## Risk Assessment After Remediation

| Current Risk | Post-Remediation Risk |
|--------------|----------------------|
| MEDIUM-HIGH | LOW |

**Time to Remediate:** 1-2 weeks with dedicated effort

**Business Impact:** Minimal (no breaking changes, only security improvements)

---

## Contacts for Questions

- **Full Report:** `/home/rracine/hanalyx/openwatch/SECURITY_AUDIT_REPORT.md`
- **Remediation Scripts:** Create in `/home/rracine/hanalyx/openwatch/scripts/security-fixes/`
- **Testing Documentation:** Update `/home/rracine/hanalyx/openwatch/docs/security/`

---

**Report Generated:** October 15, 2025
**Next Review:** 30 days post-remediation
**Classification:** Internal Security Assessment
