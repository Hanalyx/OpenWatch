# Week 2: Frontend Migration Plan

**Issue:** #111 - Migrate Frontend Settings UI to v2/credentials API
**Status:** Assessment Complete, Ready for Implementation
**Timeline:** 4-6 hours
**Date:** October 17, 2025

---

## Assessment Results

### API Usage Analysis

**Found:** 7 API calls to v1 credential endpoints across 3 files

| File | API Calls | Lines | Operations |
|------|-----------|-------|------------|
| Settings.tsx | 5 calls | 185, 403, 419, 423, 460 | LIST, CREATE, UPDATE, DELETE, DELETE_KEY |
| HostsEnhanced.tsx | 1 call | 679 | LIST (for dropdown) |
| AddHost.tsx | 1 call | 310 | LIST (for credential selection) |

**Total:** 7 v1 API calls need migration ⚠️

---

## Current v1 Endpoint Usage

### 1. Settings.tsx (Primary credential management UI)

**Line 185 - LIST credentials:**
```typescript
const response = await api.get('/api/system/credentials');
setCredentials(response); // API directly returns array
```

**Line 403 - DELETE credential:**
```typescript
await api.delete(`/api/system/credentials/${id}`);
```

**Line 419 - UPDATE credential:**
```typescript
await api.put(`/api/system/credentials/${editingCredential.id}`, formData);
```

**Line 423 - CREATE credential:**
```typescript
await api.post('/api/system/credentials', formData);
```

**Line 460 - DELETE SSH key:**
```typescript
await api.delete(`/api/system/credentials/${editingCredential.id}/ssh-key`);
```

### 2. HostsEnhanced.tsx (Credential dropdown)

**Line 679 - LIST credentials for dropdown:**
```typescript
const response = await api.get('/api/system/credentials');
```

### 3. AddHost.tsx (Credential selection during host creation)

**Line 310 - LIST credentials:**
```typescript
const response = await fetch('/api/system/credentials', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});
```

---

## Migration Strategy

### Principle: Direct v1→v2 Endpoint Replacement

**Strategy:**
- Replace `/api/system/credentials` with `/api/v2/credentials?scope=system`
- Update response handling for v2 models (if different)
- Test each operation thoroughly
- Deploy and verify

**Why this approach:**
- Backend already migrated (Week 2 Backend complete)
- v2 API fully functional and tested
- Frontend-only changes (no backend changes needed)
- Clear migration path

---

## v1 vs v2 Response Model Comparison

### v1 Response Model (SystemCredentialsResponse)
```typescript
interface SystemCredentials {
  id: number;                    // Integer ID (converted from UUID)
  name: string;
  description?: string;
  username: string;
  auth_method: string;           // "ssh_key", "password", "both"
  is_default: boolean;
  is_active: boolean;
  created_at: string;            // ISO datetime
  updated_at: string;            // ISO datetime
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
}
```

### v2 Response Model (CredentialResponse)
```typescript
interface CredentialResponse {
  id: string;                    // UUID string (different!)
  name: string;
  description?: string;
  scope: string;                 // "system", "host", "group" (new field!)
  target_id?: string;            // null for system scope (new field!)
  username: string;
  auth_method: string;           // "ssh_key", "password", "both"
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
  is_default: boolean;
  created_at: string;            // ISO datetime
  updated_at: string;            // ISO datetime
}
```

### Key Differences

| Field | v1 | v2 | Impact |
|-------|----|----|--------|
| id | number | string (UUID) | ⚠️ HIGH - Type change, affects all operations |
| scope | N/A | string | ℹ️ NEW - Always "system" for system credentials |
| target_id | N/A | string? | ℹ️ NEW - Always null for system credentials |
| is_active | boolean | N/A | ℹ️ REMOVED - v2 only returns active credentials |

**Migration Impact:** MEDIUM
- ID type change requires updating state types
- Need to filter by scope=system
- is_active field not present (all returned credentials are active)

---

## Detailed Migration Tasks

### Task 1: Update Settings.tsx (5 endpoints)

**File:** `frontend/src/pages/settings/Settings.tsx`

#### 1.1: Update Type Definitions (Lines 50-65)

**Before:**
```typescript
interface SystemCredentials {
  id: number;
  name: string;
  description?: string;
  username: string;
  auth_method: string;
  is_default: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
}
```

**After:**
```typescript
interface SystemCredentials {
  id: string;  // Changed from number to UUID string
  name: string;
  description?: string;
  scope: string;  // New field (always "system")
  target_id?: string;  // New field (always null for system)
  username: string;
  auth_method: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
  // Note: is_active removed (v2 only returns active credentials)
}
```

#### 1.2: Update LIST Endpoint (Line 185)

**Before:**
```typescript
const response = await api.get('/api/system/credentials');
setCredentials(response); // API directly returns array
```

**After:**
```typescript
const response = await api.get('/api/v2/credentials?scope=system');
setCredentials(response); // API still returns array
```

#### 1.3: Update CREATE Endpoint (Line 423)

**Before:**
```typescript
await api.post('/api/system/credentials', formData);
```

**After:**
```typescript
// Add scope and target_id to formData
const v2FormData = {
  ...formData,
  scope: 'system',
  target_id: null
};
await api.post('/api/v2/credentials', v2FormData);
```

#### 1.4: Update UPDATE Endpoint (Line 419)

**Before:**
```typescript
await api.put(`/api/system/credentials/${editingCredential.id}`, formData);
```

**After:**
```typescript
// v2 API uses DELETE + CREATE for updates (see backend implementation)
// Or we keep using v1 PUT endpoint if v2 doesn't have PUT
// Let me check v2 API...

// v2 doesn't have PUT, backend does DELETE+CREATE internally for v1
// So we can either:
// Option A: Keep using v1 PUT (backward compatible)
// Option B: Implement DELETE+CREATE in frontend
// Recommendation: Use v1 PUT endpoint for now (still works, queries unified_credentials)
```

Actually, let me check if v2 has UPDATE endpoint:

**v2 Endpoints Available:**
- POST / - Create
- GET / - List
- GET /resolve/{target_id} - Resolve
- GET /resolve/{target_id}/data - Get data
- GET /system/default - Get default
- POST /validate - Validate
- DELETE /{credential_id} - Delete

**No PUT endpoint in v2!**

**Solution:** Keep using v1 PUT for update (it's already using unified_credentials after backend migration)

#### 1.5: Update DELETE Endpoint (Line 403)

**Before:**
```typescript
await api.delete(`/api/system/credentials/${id}`);
```

**After:**
```typescript
await api.delete(`/api/v2/credentials/${id}`);
```

#### 1.6: Update DELETE SSH Key Endpoint (Line 460)

**Before:**
```typescript
await api.delete(`/api/system/credentials/${editingCredential.id}/ssh-key`);
```

**After:**
```typescript
// v2 API doesn't have /ssh-key deletion endpoint
// This is a special v1 endpoint for partial updates
// Keep using v1 endpoint (it's using unified_credentials after backend migration)
await api.delete(`/api/system/credentials/${editingCredential.id}/ssh-key`);
```

---

### Task 2: Update HostsEnhanced.tsx (1 endpoint)

**File:** `frontend/src/pages/hosts/HostsEnhanced.tsx`
**Line:** 679

**Before:**
```typescript
const response = await api.get('/api/system/credentials');
```

**After:**
```typescript
const response = await api.get('/api/v2/credentials?scope=system');
```

**Type Update:** If component uses credential.id, change type from number to string

---

### Task 3: Update AddHost.tsx (1 endpoint)

**File:** `frontend/src/pages/hosts/AddHost.tsx`
**Line:** 310

**Before:**
```typescript
const response = await fetch('/api/system/credentials', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});
```

**After:**
```typescript
const response = await fetch('/api/v2/credentials?scope=system', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});
```

**Type Update:** Update credential type from `id: number` to `id: string`

---

## Hybrid Approach (Recommended)

Given that v2 API lacks PUT and DELETE /ssh-key endpoints, I recommend a **hybrid approach:**

### Migrate to v2 (Full v2 support)
- ✅ GET (list) → `/api/v2/credentials?scope=system`
- ✅ POST (create) → `/api/v2/credentials`
- ✅ DELETE → `/api/v2/credentials/{id}`

### Keep v1 (Endpoints not in v2)
- ⚠️ PUT (update) → `/api/system/credentials/{id}` (v1 already uses unified_credentials)
- ⚠️ DELETE /ssh-key → `/api/system/credentials/{id}/ssh-key` (v1 specialized endpoint)

**Justification:**
- v1 endpoints already migrated to use unified_credentials (Week 2 Backend)
- No need to implement UPDATE in v2 API (complex, out of scope)
- Keeps migration simple and focused
- Zero breaking changes

---

## Implementation Order

**Order by risk (lowest risk first):**

1. ✅ **GET (list) endpoints** (3 files: Settings, HostsEnhanced, AddHost)
   - Read-only, safe to test
   - Easy to verify

2. ✅ **POST (create) endpoint** (Settings.tsx)
   - Write operation, but creates new data
   - Easy to test and rollback

3. ✅ **DELETE endpoint** (Settings.tsx)
   - Destructive, but simple operation
   - Test with non-critical credential first

4. ⏸️ **PUT (update) endpoint** - KEEP v1
   - Already using unified_credentials
   - No migration needed

5. ⏸️ **DELETE /ssh-key endpoint** - KEEP v1
   - Specialized v1 endpoint
   - No migration needed

---

## Testing Plan

### Pre-Migration Testing

1. **Open Settings UI:**
   ```
   Navigate to: Settings → System Settings → Credentials
   ```

2. **Test Current Operations:**
   - List credentials ✓
   - Create new credential ✓
   - Update credential ✓
   - Delete credential ✓
   - Delete SSH key ✓

3. **Document Response Format:**
   - Open Browser DevTools → Network tab
   - Perform each operation
   - Save response JSON

### Post-Migration Testing

**For each migrated endpoint:**

1. **Verify Response Format:**
   - Open Browser DevTools → Network tab
   - Perform operation
   - Verify response matches v2 format
   - Check ID is UUID string (not number)

2. **Test CRUD Operations:**
   - Create credential with password
   - Create credential with SSH key
   - Create credential with "both"
   - Update credential (uses v1 PUT)
   - Delete credential
   - Set default credential

3. **Test Host Integration:**
   - Navigate to Add Host page
   - Verify credentials load in dropdown
   - Verify credential selection works

4. **Test Hosts List:**
   - Navigate to Hosts page
   - Verify credentials load
   - Verify credential display

---

## Type Updates Required

### Settings.tsx
```typescript
// Before
const [credentials, setCredentials] = useState<SystemCredentials[]>([]);
const [editingCredential, setEditingCredential] = useState<SystemCredentials | null>(null);

// After (update SystemCredentials interface)
// id: number → id: string
// Add scope and target_id fields
```

### HostsEnhanced.tsx
```typescript
// Find credential type usage and update id type
```

### AddHost.tsx
```typescript
// Find credential type usage and update id type
```

---

## Rollback Plan

If issues occur:

1. **Revert Code Changes:**
   ```bash
   git checkout HEAD -- frontend/src/pages/settings/Settings.tsx
   git checkout HEAD -- frontend/src/pages/hosts/HostsEnhanced.tsx
   git checkout HEAD -- frontend/src/pages/hosts/AddHost.tsx
   ```

2. **Rebuild Frontend:**
   ```bash
   cd frontend
   npm run build
   ```

3. **Restart Container:**
   ```bash
   docker-compose restart frontend
   ```

**Risk:** 🟡 MEDIUM (frontend-only changes, easy rollback)

---

## Success Criteria

- ✅ All LIST operations use `/api/v2/credentials?scope=system`
- ✅ CREATE operations use `/api/v2/credentials`
- ✅ DELETE operations use `/api/v2/credentials/{id}`
- ✅ UPDATE operations continue using v1 (already on unified_credentials)
- ✅ DELETE /ssh-key continues using v1 (specialized endpoint)
- ✅ Credential ID type changed from number to string
- ✅ Settings UI CRUD operations work identically
- ✅ Host creation credential dropdown works
- ✅ Hosts list credential display works
- ✅ Zero breaking changes for users

---

## Timeline Estimate

| Task | Estimated Time | Notes |
|------|---------------|-------|
| Update Settings.tsx types | 15 min | Change id type, add scope/target_id |
| Migrate LIST endpoints (3 files) | 30 min | Simple URL change |
| Migrate CREATE endpoint | 30 min | Add scope/target_id to request |
| Migrate DELETE endpoint | 15 min | Simple URL change |
| Update HostsEnhanced.tsx | 15 min | Type update + URL change |
| Update AddHost.tsx | 15 min | Type update + URL change |
| Testing all operations | 2 hours | Thorough CRUD testing |
| Documentation | 30 min | Update completion report |
| **Total** | **4-5 hours** | Within estimate |

---

## Related Documentation

- [WEEK_2_BACKEND_MIGRATION_COMPLETE.md](WEEK_2_BACKEND_MIGRATION_COMPLETE.md) - Backend migration
- [WEEK_2_COMPLETE_SUMMARY.md](WEEK_2_COMPLETE_SUMMARY.md) - Overall Week 2 status
- [backend/app/routes/v2/credentials.py](../backend/app/routes/v2/credentials.py) - v2 API implementation

---

*Generated: October 17, 2025*
*Issue: #111 - Migrate Frontend Settings UI to v2/credentials API*
*Timeline: 3-week gradual deprecation (Week 2 of 3)*
