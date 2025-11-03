# System Credentials Deprecation Status Report

**Date**: 2025-11-03
**Issues**: #108 (3-week deprecation timeline), #112 (Week 3 monitoring)
**Status**: **DEPRECATION IN PROGRESS** - Timeline not yet complete

---

## Executive Summary

**Recommendation**: **DO NOT CLOSE** Issues #108 and #112 yet.

The `system_credentials` table deprecation is **in progress but not complete**:
- ✅ New system fully functional (`unified_credentials` with 4 rows)
- ⚠️ Legacy code still active (19 SQL references to `system_credentials`)
- ⚠️ Legacy table still populated (1 row: default root credential)
- ⏰ **Timeline not reached**: Week 3 removal scheduled for Nov 20, 2025 (17 days away)

---

## Deprecation Timeline

### Issue #108 Timeline
- **Created**: 2025-10-16
- **Week 1 (Nov 6, 2025)**: Add deprecation warnings ← **3 days away**
- **Week 2 (Nov 13, 2025)**: Migrate API routes
- **Week 3 (Nov 20, 2025)**: Monitor and remove table
- **Today (Nov 3, 2025)**: Pre-Week 1 (timeline not started)

### Current Status
**We are 3 days BEFORE Week 1 checkpoint** - removal scheduled for 17 days from now.

---

## Database State Analysis

### system_credentials Table (Legacy)
```sql
name                                     | username | auth_method | is_default | is_active | created_at
-----------------------------------------+----------+-------------+------------+-----------+--------------------
Setup Required - Default SSH Credentials | root     | password    | true       | true      | 2025-10-29 23:50:41
```

**Status**:
- ✅ Table exists
- ⚠️ 1 active row (default credential from init script)
- ⚠️ Created on Oct 29, 2025 (recent!)

### unified_credentials Table (Current)
```sql
name    | username | auth_method | scope  | is_default | is_active | created_at
--------+----------+-------------+--------+------------+-----------+--------------------
owadmin | owadmin  | both        | system | true       | true      | 2025-11-02 03:36:27  ← ACTIVE
owadmin | owadmin  | both        | system | false      | false     | 2025-11-01 03:05:05
owadmin | owadmin  | both        | system | false      | false     | 2025-11-01 02:21:51
owadmin | owadmin  | both        | system | false      | false     | 2025-10-30 00:35:09
```

**Status**:
- ✅ Table exists
- ✅ 4 rows (1 active, 3 inactive/historical)
- ✅ Active credential: owadmin (both SSH key + password)
- ✅ Newest credential from Nov 2, 2025

**Observation**: The `unified_credentials` system is actively being used (most recent credential is 1 day ago).

---

## Code References Analysis

### Active SQL References to system_credentials

**Total**: 19 references across 5 files

#### 1. backend/app/routes/system_settings.py (13 references)
**Purpose**: Legacy credential management API endpoints

**Endpoints affected**:
- `GET /api/v1/system-settings/credentials` (list)
- `POST /api/v1/system-settings/credentials` (create)
- `GET /api/v1/system-settings/credentials/{id}` (get by ID)
- `PATCH /api/v1/system-settings/credentials/{id}` (update)
- `DELETE /api/v1/system-settings/credentials/{id}` (soft delete)
- `GET /api/v1/system-settings/credentials/test/{id}` (test connection)

**Status**:
- ⚠️ **DEPRECATED endpoints still active**
- ⚠️ All endpoints have deprecation warnings in docstrings
- ⚠️ Frontend may still be calling these endpoints

**Example deprecation warning**:
```python
"""
⚠️ DEPRECATED: This endpoint uses the legacy system_credentials table.
Use /api/v2/credentials/* endpoints instead.
"""
```

#### 2. backend/app/services/auth_service.py (1 reference)
**Purpose**: Legacy fallback for system default credentials

**Method**: `_get_legacy_system_default()`
```python
def _get_legacy_system_default(self) -> Optional[CredentialData]:
    """Get system default credential from legacy system_credentials table"""
    logger.info("Getting legacy system default credential from system_credentials table")
    result = self.db.execute(
        text("""
            SELECT id, username, auth_method, encrypted_password, encrypted_private_key,
                   private_key_passphrase
            FROM system_credentials
            WHERE is_default = true AND is_active = true
            LIMIT 1
        """)
    )
```

**Status**:
- ✅ **Method defined but NEVER CALLED** (grep confirms no calls to this method)
- ✅ Dead code - safe to remove
- ⚠️ Logs would show "Getting legacy system default credential" if ever called (not seen in recent logs)

#### 3. backend/app/init_roles.py (2 references)
**Purpose**: Initialize default system credential on first run

**Function**: `init_default_system_credentials()`
```python
def init_default_system_credentials(db: Session):
    # Check if default system credentials exist
    result = db.execute(text("SELECT COUNT(*) as count FROM system_credentials WHERE is_active = true"))

    if count == 0:
        # Create placeholder credential
        db.execute(text("""
            INSERT INTO system_credentials
            (name, username, auth_method, is_default, is_active, ...)
            VALUES ('Setup Required - Default SSH Credentials', 'root', 'password', true, true, ...)
        """))
```

**Status**:
- ⚠️ **ACTIVE CODE** - runs on every application startup
- ⚠️ Creates the default root credential we saw in database
- ⚠️ Called from `backend/app/main.py` startup sequence
- ❌ **Prevents clean deprecation** - keeps recreating legacy credential

**Impact**: This is why `system_credentials` table has 1 row with created_at = 2025-10-29 (recent container restart)

#### 4. backend/app/services/credential_migration.py (2 references)
**Purpose**: Migration script to move data from system_credentials → unified_credentials

**Status**:
- ✅ Migration helper (intended for one-time use)
- ✅ Not part of normal application flow
- ✅ Safe to keep for reference during migration

#### 5. backend/app/migrations/remove_legacy_credentials.py (1 reference)
**Purpose**: Final cleanup script to drop system_credentials table

**Status**:
- ✅ Migration script for Week 3 removal
- ✅ Not executed yet (table still exists)
- ✅ Intended for use after deprecation complete

---

## Critical Blockers to Deprecation Complete

### Blocker #1: init_roles.py Still Creates Legacy Credentials
**File**: `backend/app/init_roles.py`
**Function**: `init_default_system_credentials()`

**Problem**:
- Runs on **every application startup**
- Creates a new `system_credentials` row if table is empty
- Prevents clean removal of legacy table

**Evidence**:
```
name: "Setup Required - Default SSH Credentials"
created_at: 2025-10-29 23:50:41  ← 5 days ago (recent container restart)
```

**Fix Required**:
```python
# BEFORE (current - problematic):
def init_default_system_credentials(db: Session):
    result = db.execute(text("SELECT COUNT(*) FROM system_credentials WHERE is_active = true"))
    if count == 0:
        # Create legacy credential
        db.execute(text("INSERT INTO system_credentials ..."))

# AFTER (Week 1-2 migration):
def init_default_system_credentials(db: Session):
    # DEPRECATED: Check if unified_credentials has system default
    result = db.execute(text("SELECT COUNT(*) FROM unified_credentials WHERE scope = 'system' AND is_default = true"))
    if count == 0:
        # Create unified credential instead
        db.execute(text("INSERT INTO unified_credentials ..."))
```

### Blocker #2: Legacy API Endpoints Still Active
**File**: `backend/app/routes/system_settings.py` (13 references)

**Problem**:
- Frontend Settings UI may still call `/api/v1/system-settings/credentials/*`
- Endpoints marked deprecated but still functional
- No enforcement to use new `/api/v2/credentials/*` endpoints

**Risk**:
- If frontend still uses old endpoints, removing them breaks UI
- Need to verify frontend migration complete

**Fix Required**:
1. **Week 1**: Add response headers to old endpoints: `Deprecation: true`, `Sunset: 2025-11-20`
2. **Week 2**: Migrate frontend to use `system_settings_unified.py` endpoints
3. **Week 3**: Remove old endpoints entirely

### Blocker #3: No Frontend Migration Verification

**Unknown Status**:
- Does frontend Settings UI use `/api/v1/system-settings/credentials/*` (legacy)?
- Or does it use `/api/v2/credentials/*` or `system_settings_unified.py` (new)?

**Verification Needed**:
```bash
# Check frontend API calls
grep -r "system-settings/credentials" frontend/src --include="*.ts" --include="*.tsx"
grep -r "api/v2/credentials" frontend/src --include="*.ts" --include="*.tsx"
```

---

## Deprecation Progress by Week

### Week 1 Checklist (Nov 6, 2025) - NOT STARTED
- [ ] Add deprecation warnings to legacy endpoints ← Already done in docstrings!
- [ ] Create API usage metrics ← Not implemented
- [ ] Add Sunset headers to responses ← Not implemented
- [ ] Verify frontend not calling legacy endpoints ← Not verified

**Status**: 50% complete (warnings exist, but no metrics/enforcement)

### Week 2 Checklist (Nov 13, 2025) - NOT STARTED
- [ ] Migrate `init_roles.py` to create `unified_credentials` instead
- [ ] Migrate frontend Settings UI to use v2 API
- [ ] Add tests for backward compatibility
- [ ] Monitor legacy endpoint usage (should be zero)

**Status**: 0% complete

### Week 3 Checklist (Nov 20, 2025) - NOT STARTED
- [ ] Verify zero usage of legacy endpoints
- [ ] Run `migrations/remove_legacy_credentials.py`
- [ ] Drop `system_credentials` table
- [ ] Remove deprecated code from `system_settings.py`
- [ ] Remove `init_default_system_credentials()` function

**Status**: 0% complete

---

## Current Migration Status

### ✅ Completed
1. **unified_credentials table created** (backend/app/init_database_schema.py)
2. **CentralizedAuthService implemented** (backend/app/services/auth_service.py)
3. **New credentials stored in unified_credentials** (4 rows, active system: owadmin)
4. **New API endpoints created** (backend/app/routes/system_settings_unified.py)
5. **Deprecation warnings added** (all legacy endpoints have docstring warnings)
6. **Migration script prepared** (backend/app/migrations/remove_legacy_credentials.py)

### ⚠️ In Progress
1. **Legacy endpoints still active** (system_settings.py - 13 references)
2. **Legacy table still populated** (1 row from init script)
3. **Legacy fallback method exists** (auth_service._get_legacy_system_default - unused)

### ❌ Not Started
1. **init_roles.py migration** (still creates system_credentials rows)
2. **Frontend migration verification** (unknown if Settings UI updated)
3. **API usage metrics** (no monitoring of legacy endpoint calls)
4. **Table removal** (system_credentials still exists)

---

## Recommendations

### Do NOT Close Issues Yet

**Issue #108** and **#112** should remain **OPEN** until:
1. ✅ Week 3 removal date reached (Nov 20, 2025)
2. ✅ `init_roles.py` migrated to use unified_credentials
3. ✅ Frontend verified to use v2 API endpoints
4. ✅ `system_credentials` table dropped from database
5. ✅ Legacy code removed from system_settings.py

### Immediate Next Steps (Pre-Week 1)

**Option 1: Follow Original Timeline** (Recommended)
- **Do nothing now**, wait for Nov 6, 2025 (Week 1 start)
- Execute Week 1-3 tasks on schedule
- Close issues on Nov 20, 2025 after completion

**Option 2: Accelerate Deprecation** (Risky)
- Verify frontend not using legacy endpoints NOW
- Migrate init_roles.py NOW
- Drop table early (before Nov 20)
- **Risk**: May break functionality if frontend still depends on old API

**Option 3: Add Monitoring First** (Safe)
- Add API usage logging to legacy endpoints
- Run for 1-2 weeks to verify zero usage
- Then proceed with removal

### Verification Commands

**Check if frontend uses legacy API**:
```bash
grep -r "system-settings/credentials" frontend/src --include="*.ts" --include="*.tsx"
grep -r "api/v1/system-settings" frontend/src --include="*.ts" --include="*.tsx"
```

**Check if unified_credentials working**:
```bash
# Test creating a new system credential via new API
curl -X POST http://localhost:8000/api/v2/credentials \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "test", "username": "admin", "scope": "system", ...}'
```

**Check init script behavior**:
```bash
# Restart backend and check if system_credentials gets new row
docker restart openwatch-backend
sleep 5
docker exec openwatch-db psql -U openwatch -d openwatch \
  -c "SELECT created_at FROM system_credentials ORDER BY created_at DESC LIMIT 1;"
```

---

## Comment for Issues #108 and #112

**Recommended comment** (DO NOT CLOSE yet):

```markdown
## Deprecation Status Update - 2025-11-03

**Timeline Status**: Pre-Week 1 (Week 1 starts Nov 6, 3 days away)

### Current Progress
✅ **Completed**:
- unified_credentials table fully functional (4 credentials, 1 active: owadmin)
- CentralizedAuthService implemented and in active use
- New API endpoints created (system_settings_unified.py)
- Deprecation warnings added to all legacy endpoints

⚠️ **In Progress**:
- Legacy system_credentials table still exists (1 row: default root credential)
- Legacy API endpoints still active (13 references in system_settings.py)
- init_roles.py still creates system_credentials on startup (blocker)

❌ **Not Started**:
- Frontend migration verification (unknown if Settings UI updated)
- API usage metrics (no monitoring of old endpoint calls)
- Table removal (scheduled for Week 3: Nov 20, 2025)

### Blockers
1. **init_roles.py** still runs `init_default_system_credentials()` on every startup
   - Creates legacy credential: "Setup Required - Default SSH Credentials"
   - Needs migration to create unified_credential instead

2. **Frontend Status Unknown**
   - Need to verify Settings UI not calling `/api/v1/system-settings/credentials/*`
   - Should be using `/api/v2/credentials/*` or system_settings_unified.py

### Next Steps
- **Nov 6, 2025 (Week 1)**: Add API usage metrics, verify frontend migration
- **Nov 13, 2025 (Week 2)**: Migrate init_roles.py, monitor for zero legacy usage
- **Nov 20, 2025 (Week 3)**: Drop system_credentials table, remove deprecated code

**Status**: Keeping open until Nov 20, 2025 removal complete.
```

---

## Summary Table

| Component | Legacy (system_credentials) | New (unified_credentials) | Status |
|-----------|----------------------------|---------------------------|--------|
| **Database Table** | ✅ Exists (1 row) | ✅ Exists (4 rows) | Both active |
| **API Endpoints** | ⚠️ Active (13 refs) | ✅ Active | Both active |
| **Init Script** | ⚠️ Creates rows | ❌ No creation | Legacy only |
| **Auth Service** | ⚠️ Fallback method (unused) | ✅ Primary method | New primary |
| **Frontend** | ❓ Unknown usage | ❓ Unknown usage | Needs verification |
| **Removal Date** | Nov 20, 2025 (17 days) | N/A | Timeline not reached |

---

## Conclusion

**DO NOT CLOSE** Issues #108 and #112.

The deprecation timeline is **in progress but not complete**. We are currently in the **Pre-Week 1 phase** (3 days before Week 1 checkpoint).

**Estimated completion**: Nov 20, 2025 (17 days from today)

**Critical blockers**:
1. init_roles.py still creates legacy credentials
2. Frontend migration status unknown
3. No API usage monitoring

**Recommendation**: Wait for timeline completion, then verify all success criteria before closing issues.
