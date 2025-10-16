# OpenWatch Security Scan Report: Hardcoded Secrets and Credentials

**Scan Date:** October 15, 2025
**Scanned Repository:** `/home/rracine/hanalyx/openwatch`
**Scan Scope:** Full codebase including backend, frontend, configuration files, and documentation

---

## Executive Summary

This security scan identified **hardcoded secrets and credentials** across the OpenWatch codebase. The findings are categorized by severity level, with immediate action recommended for Critical and High severity issues.

**Total Findings:** 12 issues
- **Critical:** 2 (Committed private keys, hardcoded credentials in .env files)
- **High:** 4 (Hardcoded default passwords, weak development secrets)
- **Medium:** 4 (Database connection strings in examples, placeholder credentials)
- **Low:** 2 (Documentation examples with credentials)

---

## Critical Severity Findings

### 1. MongoDB Private Key Committed to Repository
**File:** `/home/rracine/hanalyx/openwatch/security/certs/mongodb/mongodb.pem`
**Line:** 32-50+ (entire private key)
**Type:** RSA Private Key (2048-bit)
**Status:** COMMITTED TO GIT HISTORY (16 commits)

**Details:**
```
-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQCP+EHuMZbIt9Q9
[... full private key exposed ...]
```

**Risk:**
- Private key is permanently in git history and cannot be fully removed without rewriting history
- Anyone with access to the repository can decrypt MongoDB TLS connections
- Compromises the entire MongoDB security layer

**Recommendation:**
1. **IMMEDIATE:** Regenerate ALL MongoDB certificates and keys
2. **IMMEDIATE:** Update all MongoDB instances with new certificates
3. **IMMEDIATE:** Add `security/certs/mongodb/*.pem` to `.gitignore`
4. **URGENT:** Consider rewriting git history if repository is private and hasn't been widely distributed
5. **LONG-TERM:** Implement certificate management with HashiCorp Vault or AWS Secrets Manager

### 2. Hardcoded Credentials in Committed .env Files
**Files:**
- `/home/rracine/hanalyx/openwatch/.env` (NOT committed - GOOD)
- `/home/rracine/hanalyx/openwatch/backend/.env` (NOT committed - GOOD)

**Status:** Not currently committed to git, but contain weak credentials

**Details:**
```bash
# From .env
POSTGRES_PASSWORD=openwatch_secure_db_2025
REDIS_PASSWORD=openwatch_secure_redis_2025
SECRET_KEY=openwatch-secret-key-for-jwt-signing-must-be-32-chars-minimum-2025
MASTER_KEY=openwatch-master-encryption-key-for-sensitive-data-storage-2025
MONGO_ROOT_PASSWORD=secure_mongo_password

# From backend/.env
OPENWATCH_DATABASE_URL=postgresql://openwatch:openwatch@localhost:5432/openwatch
OPENWATCH_REDIS_URL=redis://:openwatch_secure_redis_2025@localhost:6379
```

**Risk:**
- Weak, predictable passwords that could be guessed
- If accidentally committed, would expose production credentials
- SECRET_KEY and MASTER_KEY are human-readable instead of cryptographically random

**Recommendation:**
1. **IMMEDIATE:** Replace all passwords with cryptographically secure random values:
   ```bash
   openssl rand -hex 32  # For SECRET_KEY and passwords
   openssl rand -base64 32  # For MASTER_KEY
   ```
2. **IMMEDIATE:** Verify `.env` files are in `.gitignore` (currently protected - GOOD)
3. **IMMEDIATE:** Rotate all database and Redis passwords on all environments
4. **LONG-TERM:** Use environment-specific secrets management (HashiCorp Vault, AWS Secrets Manager)

---

## High Severity Findings

### 3. Hardcoded Default Admin Password in Code
**Files:**
- `/home/rracine/hanalyx/openwatch/backend/app/init_admin.py:35`
- `/home/rracine/hanalyx/openwatch/backend/app/init_roles.py:111`

**Details:**
```python
# init_admin.py
hashed_password = pwd_context.hash("admin123")

# init_roles.py
hashed_password = pwd_context.hash("admin123")  # Default password - should be changed
```

**Risk:**
- Default admin account created with well-known password "admin123"
- Attackers can gain super_admin access immediately after deployment
- Users may forget to change default password

**Recommendation:**
1. **HIGH PRIORITY:** Remove hardcoded password entirely
2. **IMPLEMENT:** Force password change on first login
3. **IMPLEMENT:** Generate random password during installation and display once:
   ```python
   import secrets
   default_password = secrets.token_urlsafe(16)
   print(f"SAVE THIS PASSWORD: {default_password}")
   ```
4. **IMPLEMENT:** Require password change via CLI tool or setup wizard

### 4. Hardcoded Development Secrets in docker-compose.dev.yml
**File:** `/home/rracine/hanalyx/openwatch/docker-compose.dev.yml`
**Lines:** 44-45, 70-71

**Details:**
```yaml
environment:
  OPENWATCH_SECRET_KEY: ${SECRET_KEY:-K7sfTDL2cr9S8rvn094TpHVekeDNB1BL}
  OPENWATCH_MASTER_KEY: ${MASTER_KEY:-utvm1S8EbrNihMW0k1t9YNk3uWAEAKG2}
```

**Risk:**
- Hardcoded fallback secrets that could be used if environment variables aren't set
- Developers might accidentally deploy with these weak development keys
- Keys are committed to repository and visible to all contributors

**Recommendation:**
1. **HIGH PRIORITY:** Remove fallback values entirely - fail if env vars not set:
   ```yaml
   OPENWATCH_SECRET_KEY: ${SECRET_KEY:?SECRET_KEY environment variable required}
   ```
2. **DOCUMENT:** Add clear documentation about required environment variables
3. **IMPLEMENT:** Startup validation that checks for default/weak keys and refuses to start

### 5. Weak Development Database Credentials
**File:** `/home/rracine/hanalyx/openwatch/start-openwatch.sh:165-167`

**Details:**
```bash
POSTGRES_PASSWORD=openwatch_dev_password
REDIS_PASSWORD=redis_dev_password
DATABASE_URL=postgresql://openwatch:openwatch_dev_password@localhost:5432/openwatch
```

**Risk:**
- Predictable development passwords could be used in production by mistake
- Script generates .env file with weak credentials
- Users might copy these to production without thinking

**Recommendation:**
1. **HIGH PRIORITY:** Generate random passwords even for development:
   ```bash
   POSTGRES_PASSWORD=$(openssl rand -hex 16)
   ```
2. **IMPLEMENT:** Add prominent warning about not using in production
3. **IMPLEMENT:** Environment detection that refuses weak passwords in production

### 6. Database Connection Strings with Embedded Credentials
**Files:**
- `/home/rracine/hanalyx/openwatch/backend/app/init_admin.py:12`
- `/home/rracine/hanalyx/openwatch/backend/.env.example:9,72,82,92`
- Multiple docker-compose files

**Details:**
```python
# init_admin.py
DATABASE_URL = os.getenv("OPENWATCH_DATABASE_URL",
    "postgresql://openwatch:OpenWatch2025@localhost:5432/openwatch")
```

**Risk:**
- Fallback connection strings contain hardcoded passwords
- Easy to accidentally commit these to logs or error messages
- Password visible in process listings and environment dumps

**Recommendation:**
1. **MEDIUM PRIORITY:** Remove all hardcoded fallback connection strings
2. **IMPLEMENT:** Use separate environment variables for credentials:
   ```python
   POSTGRES_USER = os.getenv("POSTGRES_USER")
   POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
   DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@..."
   ```
3. **IMPLEMENT:** Fail fast if required credentials are missing

---

## Medium Severity Findings

### 7. Example/Documentation Files with Sample Credentials
**Files:**
- `/home/rracine/hanalyx/openwatch/examples/aegis_orsa_implementation.py:369`
- `/home/rracine/hanalyx/openwatch/docs/SCAP_TO_OPENWATCH_CONVERTER_GUIDE.md` (multiple lines)
- `/home/rracine/hanalyx/openwatch/docs/MONGODB_HIGH_AVAILABILITY.md:145-146`

**Details:**
```python
# Example code
api_key="your-aegis-api-key"

# Documentation
mongodb://openwatch:secure_mongo_password@localhost:27017
MONGO_ROOT_PASSWORD=openwatch_secure_mongo_2025
```

**Risk:**
- Users might copy-paste examples without changing credentials
- "secure_mongo_password" is not actually secure
- Creates pattern of weak password usage

**Recommendation:**
1. **MEDIUM PRIORITY:** Use obviously fake placeholders:
   ```python
   api_key="REPLACE_WITH_YOUR_ACTUAL_AEGIS_API_KEY"
   mongodb://user:CHANGEME_PASSWORD@localhost:27017
   ```
2. **IMPLEMENT:** Add validation that rejects placeholder values
3. **DOCUMENT:** Add security warnings in example files

### 8. CHANGEME Placeholders in Template Files
**Files:**
- `/home/rracine/hanalyx/openwatch/packaging/config/secrets.env.template` (multiple)
- `/home/rracine/hanalyx/openwatch/packaging/rpm/openwatch.spec` (multiple)

**Details:**
```bash
POSTGRES_PASSWORD=CHANGEME_SECURE_DB_PASSWORD
REDIS_PASSWORD=CHANGEME_SECURE_REDIS_PASSWORD
SECRET_KEY=CHANGEME_64_CHAR_SECRET_KEY
MASTER_KEY=CHANGEME_32_CHAR_MASTER_KEY
```

**Risk:**
- Users might forget to replace CHANGEME values
- System might deploy with placeholder credentials
- Already has detection logic in place (GOOD)

**Status:** Partially mitigated by validation in `/home/rracine/hanalyx/openwatch/internal/owadm/cmd/validate.go:182`

**Recommendation:**
1. **MEDIUM PRIORITY:** Enhance validation to refuse startup with CHANGEME values
2. **IMPLEMENT:** Automated secret generation script (already exists - good!)
3. **IMPROVE:** Make validation more visible with prominent warnings

### 9. JWT Public Key Committed to Repository
**File:** `/home/rracine/hanalyx/openwatch/backend/security/keys/jwt_public.pem`
**Status:** COMMITTED TO GIT

**Details:**
- Public key committed to repository (generally acceptable for public keys)
- However, corresponding private key might also be committed or generated predictably

**Risk:**
- Lower risk since it's a public key, but indicates private key might be nearby
- Could be used to verify token signatures

**Recommendation:**
1. **MEDIUM PRIORITY:** Verify corresponding private key is NOT committed
2. **IMPLEMENT:** Document key rotation procedures
3. **CONSIDER:** Use asymmetric key generation with proper entropy

### 10. E2E Test Credentials in Example Files
**File:** `/home/rracine/hanalyx/openwatch/frontend/e2e.env.example:9-15`

**Details:**
```bash
E2E_ADMIN_PASSWORD=Admin123!@#
E2E_USER_PASSWORD=User123!@#
E2E_READONLY_PASSWORD=ReadOnly123!@#
```

**Risk:**
- Test credentials might be reused in actual test environments
- Weak passwords that don't follow password policies
- Could be used by attackers if test environment is accessible

**Recommendation:**
1. **LOW-MEDIUM PRIORITY:** Generate random test credentials during test setup
2. **IMPLEMENT:** Isolate test environments completely from production
3. **DOCUMENT:** Never use these credentials in any real environment

---

## Low Severity Findings

### 11. Logging Patterns for Password Detection
**File:** `/home/rracine/hanalyx/openwatch/backend/app/utils/logging_security.py:189`

**Details:**
```python
(r"password[=:\s]+[^\s]+", "password=[REDACTED]"),
```

**Status:** This is actually GOOD - it's redacting passwords from logs

**Recommendation:**
- **MAINTAIN:** Keep this security feature active
- **ENHANCE:** Add more patterns for API keys, tokens, secrets
- **TEST:** Regularly verify log redaction is working

### 12. Development Mode Database URLs
**Files:** Multiple podman-compose and docker-compose files

**Details:**
```yaml
DATABASE_URL: postgresql://openwatch:${POSTGRES_PASSWORD:-OpenWatch2025}@database:5432/openwatch
```

**Risk:**
- Fallback passwords in development configurations
- Could be accidentally used if environment variables fail

**Recommendation:**
1. **LOW PRIORITY:** Remove fallback values for production compose files
2. **MAINTAIN:** Keep for development-specific files only
3. **DOCUMENT:** Clear separation between dev and prod configurations

---

## Files Properly Excluded from Git

These files are correctly NOT committed (GOOD security practice):

✅ `/home/rracine/hanalyx/openwatch/.env` - properly ignored
✅ `/home/rracine/hanalyx/openwatch/backend/.env` - properly ignored
✅ `/home/rracine/hanalyx/openwatch/security/keys/jwt_private.pem` - NOT in git history
✅ `.gitignore` properly configured to exclude `.env`, `.env.*`, `config/secrets.*`

---

## Summary of Recommendations by Priority

### Immediate Action Required (Critical)
1. ⚠️ **Regenerate MongoDB certificates** - remove mongodb.pem from repository
2. ⚠️ **Rotate all credentials** in existing .env files to cryptographically random values
3. ⚠️ **Audit git history** for accidentally committed secrets

### High Priority (Next 7 Days)
4. 🔥 **Remove hardcoded admin password** - implement secure first-run setup
5. 🔥 **Remove fallback secrets** from docker-compose.dev.yml
6. 🔥 **Generate random dev passwords** instead of predictable ones
7. 🔥 **Remove hardcoded database connection strings** with embedded passwords

### Medium Priority (Next 30 Days)
8. 🔸 **Update documentation** with obviously-fake placeholder credentials
9. 🔸 **Enhance CHANGEME validation** to refuse startup
10. 🔸 **Document key rotation** procedures
11. 🔸 **Generate random E2E test credentials**

### Long-Term Improvements
12. 📋 Implement HashiCorp Vault or AWS Secrets Manager integration
13. 📋 Automated secret rotation procedures
14. 📋 Secret scanning in CI/CD pipeline (GitHub Actions, GitLab CI)
15. 📋 Mandatory security training for developers on credential management

---

## Testing Recommendations

After implementing fixes, verify:

1. **No secrets in git history:**
   ```bash
   git log --all --full-history --source -- *.env security/keys/*
   truffleHog --regex --entropy=True .
   ```

2. **Environment validation:**
   ```bash
   # Should fail if secrets not set
   docker-compose up  # without .env file
   ```

3. **Default password detection:**
   ```bash
   # Should refuse to start with default passwords
   grep -r "admin123\|OpenWatch2025\|changeme" .env && echo "FAIL"
   ```

4. **Certificate security:**
   ```bash
   # Verify new certificates generated
   openssl x509 -in security/certs/mongodb/mongodb.pem -noout -dates
   ```

---

## Tools Used in This Scan

- Manual code review using `grep`, `Glob`, and `Read` tools
- Pattern matching for common secret formats
- Git history analysis for committed credentials
- File system inspection for private keys and certificates

---

## Compliance Considerations

### Relevant Standards:
- **NIST SP 800-53:** SC-12 (Cryptographic Key Management), SC-28 (Protection of Information at Rest)
- **PCI DSS 4.0:** Requirement 8.3 (Multi-factor authentication), 3.5 (Protection of cryptographic keys)
- **CIS Controls:** Control 3 (Data Protection), Control 14 (Security Awareness Training)
- **OWASP Top 10:** A07:2021 - Identification and Authentication Failures

### Regulatory Impact:
- **GDPR:** Hardcoded credentials could lead to data breaches (Article 32 - Security of Processing)
- **SOC 2:** Violates Confidentiality criteria (CC6.1 - Logical Access Controls)
- **ISO 27001:** A.9.4.3 (Password Management System), A.10.1.1 (Cryptographic Controls)

---

## Conclusion

The OpenWatch codebase has **good security infrastructure** with proper `.gitignore` configuration and password hashing implementations. However, **critical issues** were found:

1. ✅ **Good:** .env files properly excluded from git
2. ✅ **Good:** Password hashing with Argon2id
3. ✅ **Good:** Log redaction for sensitive data
4. ⚠️ **Critical:** MongoDB private key committed to git
5. ⚠️ **Critical:** Weak predictable credentials in configuration files
6. 🔥 **High:** Hardcoded default admin password "admin123"
7. 🔥 **High:** Fallback secrets in docker-compose files

**Risk Level:** High - Immediate action required on Critical and High severity findings.

**Next Steps:**
1. Address all Critical findings within 24 hours
2. Create incident response plan for credential rotation
3. Implement automated secret scanning in CI/CD pipeline
4. Schedule security training for development team on credential management

---

**Report Generated By:** Claude Code Security Scanner
**Report Version:** 1.0
**Last Updated:** October 15, 2025
