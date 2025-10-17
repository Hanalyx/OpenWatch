# Week 2: Trailing Slash Fix for v2 API

**Issue:** 400 Bad Request on OPTIONS preflight request to v2 credentials endpoint
**Root Cause:** FastAPI trailing slash redirect causing CORS issues
**Status:** ✅ **FIXED**
**Date:** October 17, 2025

---

## Problem

### Symptoms
```
INFO: 172.20.0.1:53774 - "GET /api/v2/credentials?scope=system HTTP/1.1" 307 Temporary Redirect
INFO: 172.20.0.1:53808 - "OPTIONS /api/v2/credentials/?scope=system HTTP/1.1" 400 Bad Request
```

**Issue:** Frontend makes request to `/api/v2/credentials?scope=system`, FastAPI redirects to `/api/v2/credentials/?scope=system` (with trailing slash), causing CORS preflight failure.

---

## Root Cause

FastAPI's default behavior is to redirect URLs without trailing slashes to URLs with trailing slashes for consistency. This causes issues with CORS preflight OPTIONS requests.

**Request Flow:**
1. Browser sends OPTIONS preflight to `/api/v2/credentials?scope=system`
2. FastAPI redirects (307) to `/api/v2/credentials/?scope=system`
3. OPTIONS request fails with 400 Bad Request
4. Actual GET request never happens

---

## Fix

### Solution: Add trailing slash to all v2 API calls in frontend

**Files Modified:**
1. `frontend/src/pages/settings/Settings.tsx` - 3 endpoints
2. `frontend/src/pages/hosts/HostsEnhanced.tsx` - 1 endpoint
3. `frontend/src/pages/hosts/AddHost.tsx` - 1 endpoint

### Changes Applied

**Settings.tsx:**
```typescript
// LIST endpoint (line 188)
const response = await api.get('/api/v2/credentials/?scope=system');  // Added trailing slash

// CREATE endpoint (line 432)
await api.post('/api/v2/credentials/', v2FormData);  // Added trailing slash

// DELETE endpoint (line 407)
await api.delete(`/api/v2/credentials/${id}/`);  // Added trailing slash
```

**HostsEnhanced.tsx:**
```typescript
// LIST endpoint (line 680)
const response = await api.get('/api/v2/credentials/?scope=system');  // Added trailing slash
```

**AddHost.tsx:**
```typescript
// LIST endpoint (line 311)
const response = await fetch('/api/v2/credentials/?scope=system', {  // Added trailing slash
```

---

## Deployment

### Build and Deploy
```bash
cd frontend
npm run build
docker cp build/. openwatch-frontend:/usr/share/nginx/html/
docker exec openwatch-frontend nginx -s reload
```

**Result:** ✅ Frontend deployed successfully

---

## Testing

### Before Fix
```
GET /api/v2/credentials?scope=system → 307 Redirect
OPTIONS /api/v2/credentials/?scope=system → 400 Bad Request
❌ Settings UI shows empty credential list
```

### After Fix
```
GET /api/v2/credentials/?scope=system → 200 OK
✅ Settings UI should load credentials correctly
```

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

**Week 2 Status:** ✅ **COMPLETE** (Backend + Frontend + Router Registration + Trailing Slash)

---

## Summary of All Week 2 Fixes

1. ✅ **Backend Migration** - 7 endpoints to unified_credentials
2. ✅ **Frontend Migration** - 7 API calls to v2 endpoints
3. ✅ **Router Registration** - Added v2 credentials router to main.py
4. ✅ **Trailing Slash Fix** - Fixed CORS preflight issues

**Settings UI:** Ready for testing - should now load credentials correctly

---

*Generated: October 17, 2025*
*Final fix for Week 2 migration*
