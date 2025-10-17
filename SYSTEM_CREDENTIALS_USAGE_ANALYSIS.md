# System_Credentials Table Usage Analysis

**Date:** October 16, 2025
**Purpose:** Determine if the legacy `system_credentials` table is still being used by any active functionality

---

## Executive Summary

The `system_credentials` table has **LIMITED ACTIVE USAGE** in the current codebase:

- ✅ **PRIMARY CREDENTIAL SYSTEM**: Uses `unified_credentials` table (since Sept 11, 2025)
- ⚠️  **LEGACY TABLE USAGE**: `system_credentials` has 2 active usages
- ❌ **ORPHANED CODE**: Contains unused legacy fallback code

---

## Active Usage Points

### 1. AEGIS Integration Endpoint (ACTIVE but UNUSED)

**File:** `backend/app/routes/credentials.py`
**Endpoint:** `GET /api/v1/credentials/system/default`
**Status:** ⚠️ Code is active, but AEGIS is not configured

```python
# Line 290-296
result = db.execute(text("""
    SELECT username, auth_method, encrypted_password,
           encrypted_private_key, private_key_passphrase, updated_at
    FROM system_credentials
    WHERE is_default = true AND is_active = true
    LIMIT 1
"""))
```

**Analysis:**
- This endpoint is registered and active in the application
- AEGIS_URL is NOT configured (verified via environment check)
- No requests to this endpoint found in logs
- **IMPACT:** Zero - AEGIS integration is not being used

### 2. System Initialization (ACTIVE at startup)

**File:** `backend/app/init_roles.py`
**Function:** `init_default_system_credentials()`
**Status:** ✅ Runs at application startup

```python
# Line 127-198
def init_default_system_credentials(db: Session):
    """Initialize default system SSH credentials for frictionless onboarding"""
    # Check if any system credentials already exist
    result = db.execute(text("""
        SELECT COUNT(*) as count FROM system_credentials WHERE is_active = true
    """))

    # If none exist, create placeholder
    if existing_count == 0:
        db.execute(text("""
            INSERT INTO system_credentials
            (name, description, username, auth_method, encrypted_password, ...)
            VALUES (...)
        """))
```

**Analysis:**
- Runs during RBAC initialization at app startup
- Creates placeholder credential ONLY if table is empty
- Currently table has 1 credential, so this code path is NOT executing
- **IMPACT:** Low - only runs on fresh install, creates unused placeholder

---

## Inactive/Obsolete Code

### 3. Legacy Fallback Method (NEVER CALLED)

**File:** `backend/app/services/auth_service.py`
**Function:** `_get_legacy_system_default()`
**Status:** ❌ Defined but never invoked

```python
# Line 273-363
def _get_legacy_system_default(self) -> Optional[CredentialData]:
    """Get system default credential from legacy system_credentials table"""
    result = self.db.execute(text("""
        SELECT id, username, auth_method, encrypted_password, encrypted_private_key,
               private_key_passphrase
        FROM system_credentials
        WHERE is_default = true AND is_active = true
        LIMIT 1
    """))
```

**Analysis:**
- Method is fully implemented with decryption logic
- **NEVER CALLED** anywhere in the codebase
- The active method `_get_system_default()` (line 364) uses `unified_credentials` instead
- **IMPACT:** Zero - dead code

### 4. Old System Settings Route (NOT IMPORTED)

**File:** `backend/app/routes/system_settings.py`
**Status:** ❌ File exists but not imported in main.py

**Analysis:**
- Contains extensive CRUD operations on `system_credentials` table
- Replaced by `system_settings_unified.py` on Sept 11, 2025
- **NOT imported** in `app/main.py` (line 21 imports `system_settings_unified` instead)
- **IMPACT:** Zero - completely inactive

---

## Current Active Credential System

### Primary System: unified_credentials Table

**File:** `backend/app/services/auth_service.py`
**Active Since:** September 11, 2025

**How it Works:**
1. **System Default Credentials:** Stored in `unified_credentials` with `scope='system'` and `is_default=true`
2. **Host-Specific Credentials:** Stored in `unified_credentials` with `scope='host'` and `target_id=<host_uuid>`
3. **Fallback Logic:** If no host-specific credential exists, uses system default

**Current State:**
- 1 credential in `unified_credentials`: owadmin SSH key (ID: 017f9788-6a47-40a8-bb1e-3dc78a9086c8)
- All 7 hosts successfully authenticating with this credential
- Host monitoring: 7/7 hosts ONLINE

---

## Database Table Status

### system_credentials Table

**Record Count:** 1 credential (password-based)
**Created:** October 9, 2025 at 19:18:49
**Content:**
- Username: owadmin
- Auth Method: password
- Password: ✅ Successfully decrypts with old MASTER_KEY
- Status: is_active=true, is_default=true

**Problem:** This credential is NOT being used because:
1. `auth_service.py` only checks `unified_credentials` table
2. No fallback to legacy table implemented
3. `init_roles.py` won't create new credentials (table not empty)

### unified_credentials Table

**Record Count:** 1 credential (SSH key-based)
**Created:** October 16, 2025 at 16:35:56
**Content:**
- UUID: 017f9788-6a47-40a8-bb1e-3dc78a9086c8
- External ID (for frontend): 1847233813
- Username: owadmin
- Auth Method: ssh_key
- Status: is_default=true, is_active=true

**Status:** ✅ Actively used by all hosts

---

## Verification Evidence

### 1. No AEGIS Calls in Logs
```bash
$ docker logs openwatch-backend 2>&1 | grep -i "aegis\|/api/v1/credentials"
# No results
```

### 2. No AEGIS Configuration
```bash
$ docker exec openwatch-backend printenv | grep -i aegis
# No results
```

### 3. Active Route Registration
```python
# app/main.py:21
from .routes.system_settings_unified import router as system_settings_router

# app/main.py:535
app.include_router(system_settings_router, prefix="/api", tags=["System Settings"])
```

### 4. Auth Service Using Unified Table
```bash
$ docker logs openwatch-backend 2>&1 | grep "Using unified_credentials"
2025-10-16 16:40:20,037 - backend.app.services.auth_service - INFO - Using unified_credentials table for credential resolution
2025-10-16 16:40:20,838 - backend.app.services.auth_service - INFO - Using unified_credentials table for credential resolution
# (repeated for all 7 hosts)
```

---

## Conclusion

### Is system_credentials Still Being Used?

**Answer:** **MINIMALLY** - Only 2 minor usage points, neither affecting production functionality:

1. **AEGIS endpoint** (lines 290-296 in credentials.py): Active code but AEGIS not configured - **ZERO IMPACT**
2. **Initialization check** (lines 132, 154 in init_roles.py): Only runs on fresh installs - **LOW IMPACT**

### What IS Being Used?

- **unified_credentials table** - 100% of credential resolution
- **system_settings_unified.py** - Active API for credential management
- **auth_service.py:_get_system_default()** - Uses unified_credentials exclusively

### Orphaned Password Credential

The password credential in `system_credentials` table:
- ✅ Can be decrypted successfully
- ❌ Is NOT used by any active code path
- ❌ Was never migrated to unified_credentials
- ❌ Has been orphaned since Sept 11, 2025 (when unified system activated)

### Recommendation

**Safe to Deprecate:** The `system_credentials` table can be deprecated after:
1. Updating AEGIS endpoint to use `unified_credentials` (if AEGIS is ever enabled)
2. Removing the initialization code in `init_roles.py` (or updating it to use unified_credentials)
3. Deleting the unused `system_settings.py` route file
4. Removing the `_get_legacy_system_default()` method from auth_service.py

**Migration Note:** The existing password credential in `system_credentials` was never needed and can be safely ignored.

---

## Files Analyzed

- ✅ `app/main.py` - Route registration
- ✅ `app/services/auth_service.py` - Credential resolution
- ✅ `app/routes/system_settings_unified.py` - Active credential management
- ✅ `app/routes/system_settings.py` - Obsolete credential management
- ✅ `app/routes/credentials.py` - AEGIS integration
- ✅ `app/init_roles.py` - System initialization
- ✅ `app/database.py` - Table definitions
- ✅ Backend container logs - Runtime behavior
- ✅ Environment variables - AEGIS configuration
