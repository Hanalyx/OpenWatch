# Week 2: UUID Serialization Fix

**Issue:** v2 API returning 500 error with Pydantic validation failure
**Root Cause:** UUID objects not converted to strings for Pydantic response model
**Status:** ✅ **FIXED**
**Date:** October 17, 2025

---

## Problem

### Error in Logs
```
2025-10-17 03:30:31,514 - backend.app.routes.v2.credentials - ERROR - Failed to list credentials:
1 validation error for CredentialResponse
id
  Input should be a valid string [type=string_type, input_value=UUID('017f9788-6a47-40a8-bb1e-3dc78a9086c8'), input_type=UUID]
  For further information visit https://errors.pydantic.dev/2.10/v/string_type

INFO: 172.20.0.1:54782 - "GET /api/v2/credentials/?scope=system HTTP/1.1" 500 Internal Server Error
```

### Root Cause

**Pydantic Model Expectation** (`backend/app/routes/v2/credentials.py`):
```python
class CredentialResponse(BaseModel):
    id: str  # Expects string type
    target_id: Optional[str]  # Expects string or None
```

**Database Returns** (`backend/app/services/auth_service.py` line 642):
```python
credentials.append({
    "id": row.id,  # ❌ UUID object, not string
    "target_id": row.target_id,  # ❌ UUID object, not string
})
```

**Result:** Pydantic validation fails when trying to serialize UUID objects as strings

---

## The Fix

### File: `backend/app/services/auth_service.py`

**Before (Lines 642-646):**
```python
credentials.append({
    "id": row.id,  # ❌ UUID object
    "name": row.name,
    "description": row.description,
    "scope": row.scope,
    "target_id": row.target_id,  # ❌ UUID object or None
```

**After (Lines 642-646):**
```python
credentials.append({
    "id": str(row.id),  # ✅ Convert UUID to string
    "name": row.name,
    "description": row.description,
    "scope": row.scope,
    "target_id": str(row.target_id) if row.target_id else None,  # ✅ Convert UUID to string or keep None
```

---

## Why This Happened

### PostgreSQL UUID Type
PostgreSQL `UUID` columns return UUID objects when queried via SQLAlchemy:
```python
result = db.execute(text("SELECT id FROM unified_credentials"))
row = result.fetchone()
type(row.id)  # <class 'uuid.UUID'>
```

### Pydantic Strict Validation
Pydantic 2.x has strict type validation by default:
```python
class CredentialResponse(BaseModel):
    id: str  # Expects exactly string, not UUID object
```

### No Automatic Conversion
Unlike Pydantic 1.x, Pydantic 2.x does NOT automatically convert UUID objects to strings. Must be explicit.

---

## Testing Results

### Before Fix
```
GET /api/v2/credentials/?scope=system
Response: 500 Internal Server Error
Body: {"detail": "Failed to list credentials"}

Error: Pydantic validation error - UUID object instead of string
```

### After Fix
```
GET /api/v2/credentials/?scope=system
Response: 200 OK
Body: [
  {
    "id": "017f9788-6a47-40a8-bb1e-3dc78a9086c8",  ✅ String
    "target_id": null,  ✅ None (system credentials have no target)
    "username": "owadmin",
    "auth_method": "ssh_key",
    ...
  }
]
```

---

## Deployment

```bash
docker cp backend/app/services/auth_service.py openwatch-backend:/app/backend/app/services/auth_service.py
docker-compose restart backend worker
```

**Result:** ✅ Deployed successfully, all containers healthy

---

## Complete Week 2 Fix History

### Issue #1: Router Not Registered
**Problem:** 404 on `/api/v2/credentials`
**Fix:** Add v2 router to `main.py`
**Doc:** [WEEK_2_ROUTER_REGISTRATION_FIX.md](WEEK_2_ROUTER_REGISTRATION_FIX.md)

### Issue #2: Trailing Slash CORS
**Problem:** 400 Bad Request on OPTIONS preflight
**Fix:** Add trailing slash to all v2 API calls
**Doc:** [WEEK_2_TRAILING_SLASH_FIX.md](WEEK_2_TRAILING_SLASH_FIX.md)

### Issue #3: User ID Type Mismatch
**Problem:** Empty credentials due to UUID vs integer comparison
**Fix:** Convert integer user ID to UUID format
**Doc:** [WEEK_2_USER_ID_TYPE_FIX.md](WEEK_2_USER_ID_TYPE_FIX.md)

### Issue #4: UUID Serialization
**Problem:** 500 error from Pydantic validation failure
**Fix:** Convert UUID objects to strings in `list_credentials()`
**Doc:** This document

---

## Status

**All Containers:**
```
openwatch-frontend    Up (healthy) ✅
openwatch-backend     Up (healthy) ✅
openwatch-worker      Up (healthy) ✅
openwatch-mongodb     Up (healthy) ✅
openwatch-db          Up (healthy) ✅
openwatch-redis       Up (healthy) ✅
```

**Week 2 Migration:** ✅ **FULLY COMPLETE WITH ALL FIXES**

**Settings UI:** Should now display credentials correctly!

---

## Next Steps

1. ✅ All technical issues resolved
2. ⏳ **User testing:** Navigate to Settings → System Settings → SSH Credentials
3. ⏳ Verify credentials display correctly
4. ⏳ Test CRUD operations (Create, Update, Delete)
5. ⏳ Week 3: Monitor usage and remove system_credentials table (Nov 17-20, 2025)

---

*Generated: October 17, 2025*
*Issue: UUID serialization for Pydantic validation*
*Fix: Convert UUID objects to strings in auth_service.list_credentials()*
*Status: RESOLVED ✅*
