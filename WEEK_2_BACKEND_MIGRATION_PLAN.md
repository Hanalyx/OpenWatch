# Week 2: Backend API Migration Plan

**Issue:** #110 - Migrate Backend API Routes to unified_credentials
**Status:** Assessment Complete
**Timeline:** 6-8 hours
**Goal:** Update v1 credential endpoints to query unified_credentials table instead of system_credentials while maintaining 100% backward compatibility

---

## Current State Analysis

### V1 Endpoints (Legacy - Using system_credentials)

**credentials.py** (AEGIS integration):
1. `GET /api/v1/credentials/hosts/{host_id}` - Get host credentials (already uses hosts.encrypted_credentials)
2. `POST /api/v1/credentials/hosts/batch` - Get multiple host credentials (already uses hosts.encrypted_credentials)
3. `GET /api/v1/credentials/system/default` ⚠️ **NEEDS MIGRATION** - Uses system_credentials table

**system_settings_unified.py** (Admin UI):
1. `GET /api/v1/system/credentials` ⚠️ **NEEDS MIGRATION** - Lists system_credentials
2. `POST /api/v1/system/credentials` ⚠️ **NEEDS MIGRATION** - Creates in system_credentials
3. `GET /api/v1/system/credentials/default` ⚠️ **NEEDS MIGRATION** - Gets from system_credentials
4. `GET /api/v1/system/credentials/{credential_id}` ⚠️ **NEEDS MIGRATION** - Gets from system_credentials
5. `PUT /api/v1/system/credentials/{credential_id}` ⚠️ **NEEDS MIGRATION** - Updates system_credentials
6. `DELETE /api/v1/system/credentials/{credential_id}` ⚠️ **NEEDS MIGRATION** - Deletes from system_credentials

### V2 Endpoints (New - Using unified_credentials via CentralizedAuthService)

All v2 endpoints use CentralizedAuthService which queries unified_credentials:
1. `POST /api/v2/credentials/` - Create credential (any scope)
2. `GET /api/v2/credentials/` - List credentials (with scope filter)
3. `GET /api/v2/credentials/resolve/{target_id}` - Resolve credentials
4. `GET /api/v2/credentials/resolve/{target_id}/data` - Get decrypted data
5. `GET /api/v2/credentials/system/default` - Get system default credential
6. `POST /api/v2/credentials/validate` - Validate credential
7. `DELETE /api/v2/credentials/{credential_id}` - Delete credential

---

## Migration Strategy

### Principle: "Bridge Pattern" - Maintain v1 Interface, Use v2 Logic

**Strategy:**
- Keep v1 endpoint routes unchanged (no breaking changes)
- Replace internal database queries with CentralizedAuthService calls
- Transform v2 response models to match v1 response models
- Maintain exact same response format for backward compatibility

**Benefits:**
- Zero breaking changes for existing clients
- Gradual migration path
- Single source of truth (unified_credentials)
- Consistent encryption across all credentials

---

## Detailed Migration Tasks

### Task 1: Migrate credentials.py (1 endpoint)

**File:** `backend/app/routes/credentials.py`

**Endpoint:** `GET /api/v1/credentials/system/default` (lines 277-372)

**Current Implementation:**
```python
# Queries system_credentials table
result = db.execute(text("""
    SELECT username, auth_method, encrypted_password,
           encrypted_private_key, private_key_passphrase, updated_at
    FROM system_credentials
    WHERE is_default = true AND is_active = true
    LIMIT 1
"""))

# Uses encryption.decrypt_data()
from ..services.encryption import decrypt_data
ssh_key = decrypt_data(row.encrypted_private_key).decode()
password = decrypt_data(row.encrypted_password).decode()
```

**New Implementation:**
```python
from ..services.auth_service import get_auth_service

# Use CentralizedAuthService
auth_service = get_auth_service(db)
credential = auth_service.resolve_credential(use_default=True)

if not credential:
    raise HTTPException(status_code=404, detail="No default system credentials configured")

# Transform to SSHCredential response model (same format as before)
credential_response = SSHCredential(
    host_id="system-default",
    hostname="system-default",
    username=credential.username,
    auth_method=credential.auth_method.value,
    ssh_key=credential.private_key,
    key_type=None,  # Could extract from metadata
    password=credential.password,
    source="openwatch-system",
    last_updated=datetime.utcnow().isoformat()
)
```

**Changes:**
- Lines 7-8: Add imports
- Lines 307-372: Replace logic with CentralizedAuthService call
- Maintain SSHCredential response model (no change)

**Testing:**
- Call `GET /api/v1/credentials/system/default`
- Verify response format matches exactly
- Verify credential data is correct

---

### Task 2: Migrate system_settings_unified.py (6 endpoints)

**File:** `backend/app/routes/system_settings_unified.py`

#### Endpoint 2.1: List System Credentials

**Endpoint:** `GET /api/v1/system/credentials` (lines 89-136)

**Current:** Queries `SELECT * FROM system_credentials`

**New:**
```python
auth_service = get_auth_service(db)
credentials = auth_service.list_credentials(scope=CredentialScope.SYSTEM)

# Transform to SystemCredentialsResponse
return [
    SystemCredentialsResponse(
        id=cred['id'],
        username=cred['username'],
        auth_method=cred['auth_method'],
        is_default=cred['is_default'],
        ssh_key_fingerprint=cred.get('ssh_key_fingerprint'),
        ssh_key_type=cred.get('ssh_key_type'),
        ssh_key_bits=cred.get('ssh_key_bits'),
        ssh_key_comment=cred.get('ssh_key_comment'),
        created_at=cred['created_at'],
        updated_at=cred['updated_at']
    )
    for cred in credentials
]
```

#### Endpoint 2.2: Create System Credential

**Endpoint:** `POST /api/v1/system/credentials` (lines 138-233)

**Current:** Encrypts and inserts into system_credentials

**New:**
```python
from ..services.auth_service import (
    get_auth_service, CredentialData, CredentialMetadata,
    CredentialScope, AuthMethod
)

auth_service = get_auth_service(db)

# Create credential data
credential_data = CredentialData(
    username=request.username,
    auth_method=AuthMethod(request.auth_method),
    password=request.password,
    private_key=request.ssh_key,
    private_key_passphrase=request.ssh_key_passphrase
)

metadata = CredentialMetadata(
    name=request.name or "System Credential",
    description=request.description,
    scope=CredentialScope.SYSTEM,
    target_id=None,
    is_default=request.is_default
)

credential_id = auth_service.store_credential(
    credential_data=credential_data,
    metadata=metadata,
    created_by=current_user.get('id')
)
```

#### Endpoint 2.3: Get System Credential

**Endpoint:** `GET /api/v1/system/credentials/{credential_id}` (lines 251-303)

**Current:** Queries system_credentials by ID

**New:**
```python
auth_service = get_auth_service(db)
credential_list = auth_service.list_credentials(scope=CredentialScope.SYSTEM)

credential = next((c for c in credential_list if c['id'] == credential_id), None)

if not credential:
    raise HTTPException(status_code=404, detail="Credential not found")

# Transform to SystemCredentialsResponse
```

#### Endpoint 2.4: Get Default System Credential

**Endpoint:** `GET /api/v1/system/credentials/default` (lines 305-345)

**Current:** Queries `WHERE is_default = true AND is_active = true`

**New:**
```python
auth_service = get_auth_service(db)
credential = auth_service.resolve_credential(use_default=True)

if not credential:
    raise HTTPException(status_code=404, detail="No default credential")

# Transform to SystemCredentialsResponse
```

#### Endpoint 2.5: Update System Credential

**Endpoint:** `PUT /api/v1/system/credentials/{credential_id}` (lines 347-492)

**Current:** Updates system_credentials table

**New:**
```python
auth_service = get_auth_service(db)

# Delete old credential
auth_service.delete_credential(credential_id)

# Create new credential with same ID
credential_data = CredentialData(...)
metadata = CredentialMetadata(id=credential_id, ...)
auth_service.store_credential(credential_data, metadata, current_user.get('id'))
```

#### Endpoint 2.6: Delete System Credential

**Endpoint:** `DELETE /api/v1/system/credentials/{credential_id}` (lines 494-549)

**Current:** Sets `is_active = false` in system_credentials

**New:**
```python
auth_service = get_auth_service(db)
success = auth_service.delete_credential(credential_id)

if not success:
    raise HTTPException(status_code=404, detail="Credential not found")
```

---

## Response Model Mapping

### V1 Response Models → V2 Data Structures

**SSHCredential (credentials.py):**
```python
# V1 Model (keep unchanged)
class SSHCredential(BaseModel):
    host_id: str
    hostname: str
    username: str
    auth_method: str
    ssh_key: Optional[str] = None
    key_type: Optional[str] = None
    password: Optional[str] = None
    source: str = "openwatch"
    last_updated: str

# Maps to v2 CredentialDataResponse
```

**SystemCredentialsResponse (system_settings_unified.py):**
```python
# V1 Model (keep unchanged)
class SystemCredentialsResponse(BaseModel):
    id: str
    username: str
    auth_method: str
    is_default: bool
    ssh_key_fingerprint: Optional[str]
    ssh_key_type: Optional[str]
    ssh_key_bits: Optional[int]
    ssh_key_comment: Optional[str]
    created_at: datetime
    updated_at: datetime

# Maps to v2 CredentialResponse
```

---

## Testing Plan

### Pre-Migration Verification

1. Export current system_credentials data:
   ```sql
   SELECT * FROM system_credentials WHERE is_active = true;
   ```

2. Verify unified_credentials has matching data:
   ```sql
   SELECT * FROM unified_credentials WHERE scope = 'system' AND is_active = true;
   ```

### Migration Testing

**For each migrated endpoint:**

1. **Before Migration:**
   - Call endpoint, save response JSON
   - Note response time

2. **After Migration:**
   - Call endpoint, save response JSON
   - Compare JSON responses (must be identical)
   - Verify response time is similar
   - Check database queries use unified_credentials

3. **Integration Test:**
   - Test Settings UI credential CRUD operations
   - Test host monitoring credential resolution
   - Test scan operations credential resolution

### Rollback Plan

If issues occur:
1. Revert code changes (git revert)
2. Restart backend container
3. Verify system_credentials still queryable
4. System continues using legacy endpoints

---

## Implementation Order

**Order by risk (lowest risk first):**

1. ✅ **DELETE endpoint** (simplest, soft delete only)
2. ✅ **GET default endpoint** (read-only, direct mapping)
3. ✅ **GET by ID endpoint** (read-only, simple lookup)
4. ✅ **LIST endpoint** (read-only, simple filter)
5. ⚠️ **CREATE endpoint** (write operation, validation required)
6. ⚠️ **UPDATE endpoint** (write operation, complex logic)

---

## Success Criteria

- ✅ All 7 v1 endpoints migrated to use unified_credentials
- ✅ Zero breaking changes for existing API clients
- ✅ Response format identical to current implementation
- ✅ All 7 hosts remain online during migration
- ✅ Settings UI credential management works identically
- ✅ Database queries confirmed using unified_credentials
- ✅ Week 1 deprecation warnings remain active

---

## Risk Assessment

**Risk Level:** 🟡 MEDIUM

**Risks:**
1. Response format mismatch → Mitigated by strict model mapping
2. Encryption/decryption issues → Mitigated by using CentralizedAuthService
3. Missing credentials → Mitigated by pre-migration verification
4. Performance degradation → Mitigated by testing response times

**Mitigation:**
- Test each endpoint individually
- Deploy one endpoint at a time
- Monitor logs for errors
- Keep rollback plan ready

---

## Next Steps

1. ✅ Assessment complete
2. ⏳ Implement Task 1 (credentials.py)
3. ⏳ Implement Task 2 (system_settings_unified.py)
4. ⏳ Test all endpoints
5. ⏳ Deploy to production
6. ⏳ Monitor for 24 hours
7. ⏳ Update Issue #110 status

---

## Notes

- **No data migration required** - unified_credentials already has the data
- **Deprecation warnings** remain in place (Week 1 work)
- **v2 API** already exists and works correctly
- **Frontend migration** (Issue #111) happens after this
- **system_credentials table** deletion happens in Week 3 (Issue #112)
