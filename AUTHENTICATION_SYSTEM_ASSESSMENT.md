# Authentication System Assessment & Implementation Plan

**Date:** October 16, 2025
**Purpose:** Assess current authentication system and create plan to enforce user intent for compliance scanning

---

## Executive Summary

**Current State:** ❌ **USER INTENT IS NOT RESPECTED**

The authentication system has **critical gaps** where user-configured authentication methods are ignored:

1. ❌ **Host-specific credentials NOT implemented** - all hosts fallback to system default
2. ❌ **auth_method field ignored** - user's choice of password vs SSH key not enforced
3. ❌ **Password authentication unavailable** - only SSH key works currently
4. ⚠️ **"Both" option not functional** - fallback logic missing

**Impact for Compliance Scanning:**
- User configures host for password authentication → System uses SSH key anyway
- User configures host-specific SSH key → System uses system default anyway
- Compliance requirements cannot be met when specific auth methods are mandated

---

## Current System Architecture

### Three Authentication Levels (Intended Design)

```
1. SYSTEM DEFAULT (Settings >> System Settings >> SSH Credentials)
   ├─ Password only
   ├─ SSH Key only
   └─ Both (Password + SSH Key with fallback)

2. HOST-SPECIFIC (Hosts >> Edit/Add Host >> Authentication Method)
   ├─ Use System Default
   ├─ Password (different from system)
   ├─ SSH Key (different from system)
   └─ Both (Password + SSH Key)

3. EMBEDDED (Legacy - in hosts table)
   └─ encrypted_credentials field (deprecated)
```

### Current Database State

**System Default Credentials:**
```
Table: unified_credentials
Scope: system
Count: 1 credential

Current credential:
  Name: owadmin
  Username: owadmin
  Auth Method: ssh_key
  Has Password: No
  Has SSH Key: Yes ✅
  Is Default: Yes
```

**Host-Specific Credentials:**
```
Table: unified_credentials
Scope: host
Count: 0 credentials ❌

STATUS: NOT IMPLEMENTED
```

**Host Configurations:**
```
Table: hosts
Total Active: 7 hosts

Breakdown:
  - 5 hosts: auth_method = 'system_default'
  - 1 host: auth_method = 'ssh_key' (192.168.1.212)
  - 1 host: auth_method = 'password' (192.168.1.214)
  - 0 hosts: auth_method = 'both'
```

---

## What's Working ✅

### 1. System Default SSH Key Authentication
**Status:** ✅ WORKING

- System default SSH key configured and encrypted properly
- All 7 hosts successfully authenticate
- Credential resolution from `unified_credentials` works
- Host monitoring shows all hosts ONLINE

**Evidence:**
```
2025-10-16 16:40:18 - INFO - Using unified_credentials table for credential resolution
2025-10-16 16:40:18 - INFO - ✅ Resolved system_default credentials for host monitoring
2025-10-16 16:40:18 - INFO - SSH connection successful (auth: private_key, duration: 0.24s)
2025-10-16 16:40:18 - INFO - Host is ONLINE (SSH accessible)
```

### 2. System Settings UI
**Status:** ✅ WORKING (UI level)

- Frontend allows creating credentials with auth_method: password, ssh_key, or both
- API endpoint `/api/system/credentials` accepts all three options
- Credentials stored in `unified_credentials` table correctly
- Encryption/decryption working with current MASTER_KEY

**Limitation:** While UI works, password option is unusable (no password credential exists)

### 3. Host Edit/Add UI
**Status:** ✅ WORKING (UI level)

- Frontend allows selecting authentication method
- API endpoint `/api/hosts` accepts auth_method field
- Value saved to `hosts.auth_method` field correctly

**Limitation:** While UI works, the value is ignored by credential resolution logic

---

## What's NOT Working ❌

### 1. Host-Specific Credentials
**Status:** ❌ NOT IMPLEMENTED

**Code Evidence:**
```python
# backend/app/services/auth_service.py:264-267
def resolve_credential(self, target_id: str = None, use_default: bool = False):
    # For now, host-specific credentials are not supported via unified system
    # Fall back to system default
    logger.info(f"No host-specific unified credentials supported yet, using system default")
    return self._get_system_default()
```

**Impact:**
- User selects "Host-Specific SSH Key" in UI
- UI saves auth_method='ssh_key' and creates credential with target_id=<host_uuid>
- System **IGNORES** host-specific credential and uses system default anyway

**Example Violation:**
```
Host: 192.168.1.212
User configured: auth_method='ssh_key' (expecting host-specific key)
System behavior: Uses system default SSH key
User intent: VIOLATED ❌
```

### 2. Password Authentication
**Status:** ❌ NOT AVAILABLE

**Root Cause:**
- No password credential exists in `unified_credentials` table
- System default is SSH key only
- Even if user selects "password" in UI, system uses SSH key

**Impact:**
- User configures host for password authentication
- System uses SSH key instead (violates compliance requirements)

**Example Violation:**
```
Host: 192.168.1.214
User configured: auth_method='password'
System behavior: Uses system default SSH key
User intent: VIOLATED ❌
```

### 3. "Both" Authentication Method
**Status:** ❌ NOT FUNCTIONAL

**Root Cause:**
- No fallback logic implemented
- If auth_method='both' and SSH key fails, doesn't try password
- If auth_method='both' and password fails, doesn't try SSH key

**Missing Implementation:**
```python
# SHOULD BE:
if auth_method == 'both':
    # Try SSH key first
    if ssh_key_available:
        try_ssh_key()
        if success:
            return

    # Fallback to password
    if password_available:
        try_password()
        if success:
            return

    # Both failed
    raise AuthenticationError
```

### 4. Auth Method Enforcement
**Status:** ❌ NOT ENFORCED

**Root Cause:**
- `hosts.auth_method` field exists but is **never checked** during credential resolution
- `resolve_credential()` doesn't receive or use auth_method parameter
- System always returns same credential regardless of user's choice

**Code Gap:**
```python
# CURRENT - auth_method NOT used:
def resolve_credential(self, target_id: str = None, use_default: bool = False):
    return self._get_system_default()  # Always same result!

# SHOULD BE - auth_method drives behavior:
def resolve_credential(self, target_id: str = None, required_auth_method: str = None):
    if target_id:
        host_cred = self._get_host_credential(target_id)
        if host_cred and host_cred.auth_method == required_auth_method:
            return host_cred

    system_default = self._get_system_default()
    if required_auth_method and system_default.auth_method != required_auth_method:
        raise AuthMethodMismatchError()

    return system_default
```

---

## User Intent Violations

### Violation 1: Password Host Using SSH Key

**Scenario:**
```
User Action: Hosts >> Edit Host (192.168.1.214)
User Selects: Authentication Method = "Password"
User Expects: Host will authenticate with password
```

**What Actually Happens:**
```
1. Host.auth_method saved as 'password' ✅
2. Scan initiated for host
3. auth_service.resolve_credential() called
4. resolve_credential() ignores auth_method ❌
5. Returns system default (SSH key) ❌
6. Host authenticates with SSH key ❌
7. User's compliance requirement violated ❌
```

**Evidence:**
```
Host: 192.168.1.214
Configured: auth_method='password'
Actual behavior: "Using system_default credentials (method: ssh_key)"
Result: USER INTENT VIOLATED
```

### Violation 2: Host-Specific SSH Key Using System Default

**Scenario:**
```
User Action: Hosts >> Edit Host (192.168.1.212)
User Selects: Authentication Method = "Host-Specific SSH Key"
User Provides: Different SSH key than system default
User Expects: Host will use its own SSH key
```

**What Actually Happens:**
```
1. Host-specific credential created in unified_credentials ✅
2. Credential.scope = 'host', target_id = <host_uuid> ✅
3. Scan initiated for host
4. auth_service.resolve_credential(target_id=<host_uuid>) called
5. resolve_credential() has hardcoded fallback to system default ❌
6. Host-specific credential ignored ❌
7. System default SSH key used instead ❌
```

**Code Proof:**
```python
# Line 264-267:
# For now, host-specific credentials are not supported via unified system
# Fall back to system default
return self._get_system_default()
```

### Violation 3: "Both" Method Not Attempting Fallback

**Scenario:**
```
User Action: System Settings >> SSH Credentials
User Selects: Authentication Method = "Both (Password + SSH Key)"
User Provides: Both password and SSH key
User Expects: System tries SSH key first, falls back to password if needed
```

**What Would Actually Happen:**
```
1. Credential created with auth_method='both' ✅
2. Both password and SSH key encrypted and stored ✅
3. Scan initiated
4. SSH key attempted
5. If SSH key fails... system gives up ❌
6. Password never attempted ❌
7. Fallback logic missing ❌
```

---

## Compliance Impact

### Why This Matters for Compliance Scanning

**Scenario: Government Compliance Audit**

```
Compliance Requirement:
"Production systems must use password authentication only.
Development systems may use SSH key authentication."

User Configuration:
- Production hosts: auth_method='password'
- Development hosts: auth_method='ssh_key'

Current System Behavior:
- ALL hosts use SSH key (system default)
- Compliance requirement: VIOLATED
- Audit result: FAIL
```

**Scenario: Multi-Tenant Environment**

```
Business Requirement:
"Each customer's hosts must use customer-specific SSH keys.
Never use shared credentials across customers."

User Configuration:
- Customer A hosts: host-specific SSH key A
- Customer B hosts: host-specific SSH key B

Current System Behavior:
- ALL hosts use same system default SSH key
- Customer isolation: VIOLATED
- Security requirement: FAIL
```

**Scenario: Privileged Access Management**

```
Security Requirement:
"Scanner must authenticate with least-privileged accounts.
Use 'scanuser' account (password), not 'root' account (SSH key)."

User Configuration:
- Hosts configured for password authentication with 'scanuser'
- System default is SSH key with 'root'

Current System Behavior:
- All hosts authenticate as 'root' with SSH key
- Least privilege: VIOLATED
- Security policy: FAIL
```

---

## Root Cause Analysis

### Primary Root Cause
**Location:** `backend/app/services/auth_service.py:241-271`
**Function:** `resolve_credential()`

**Problem:** The credential resolution logic is **incomplete**:

1. **Host-specific lookup not implemented** (lines 264-267)
   ```python
   # For now, host-specific credentials are not supported
   return self._get_system_default()
   ```

2. **auth_method not passed or checked**
   - Caller doesn't pass host's desired auth_method
   - Function doesn't validate auth_method matches
   - No error if mismatch occurs

3. **No validation logic**
   - Doesn't check if credential type matches requirement
   - Doesn't raise error if wrong auth method
   - Silent failure violates user intent

### Secondary Root Causes

**1. unified_credentials Scope Not Fully Utilized**

The `scope` field exists but host-specific resolution missing:
```sql
-- Table has scope field:
scope VARCHAR(50) CHECK (scope IN ('system', 'host', 'group'))
target_id UUID

-- But query only checks system scope:
SELECT * FROM unified_credentials
WHERE scope = 'system' AND is_default = true
-- Never queries: WHERE scope = 'host' AND target_id = ?
```

**2. Host Monitoring Hardcoded to System Default**

File: `backend/app/services/host_monitor.py`

Likely calls:
```python
# Probably does:
cred = auth_service.resolve_credential(use_default=True)  # Forces system default!

# Should do:
cred = auth_service.resolve_credential(
    target_id=host.id,
    required_auth_method=host.auth_method
)
```

**3. Missing "Both" Auth Logic**

No code attempts fallback when auth_method='both':
```python
# Missing implementation:
if credential.auth_method == 'both':
    if ssh_key_available:
        if try_ssh_authentication():
            return success
    if password_available:
        if try_password_authentication():
            return success
    return failure
```

---

## Implementation Plan

### Phase 1: Implement Host-Specific Credential Resolution ⭐ CRITICAL

**Objective:** Make host-specific credentials work

**Changes Required:**

#### 1.1 Update `auth_service.resolve_credential()`

**File:** `backend/app/services/auth_service.py`

**Current Code (lines 241-271):**
```python
def resolve_credential(self, target_id: str = None, use_default: bool = False):
    if use_default or not target_id:
        return self._get_system_default()

    # For now, host-specific credentials are not supported
    return self._get_system_default()
```

**New Code:**
```python
def resolve_credential(
    self,
    target_id: str = None,
    required_auth_method: str = None,
    use_default: bool = False
) -> Optional[CredentialData]:
    """
    Resolve credentials with strict user intent enforcement.

    Resolution order:
    1. If use_default=True -> system default only
    2. If target_id provided -> try host-specific, fallback to system default
    3. Validate auth_method matches requirement

    Args:
        target_id: Host/group UUID to resolve credentials for
        required_auth_method: Required authentication method ('password', 'ssh_key', 'both', 'system_default')
        use_default: Force system default (ignores target_id)

    Returns:
        CredentialData matching requirements, or None

    Raises:
        AuthMethodMismatchError: If available credential doesn't match required method
    """
    try:
        credential = None

        # 1. Try host-specific credential first (if target_id provided and not forcing default)
        if target_id and not use_default:
            logger.info(f"Attempting to resolve host-specific credential for target: {target_id}")
            credential = self._get_host_credential(target_id)

            if credential:
                logger.info(f"✅ Found host-specific credential (auth_method: {credential.auth_method})")

                # Validate auth method if required
                if required_auth_method and required_auth_method != 'system_default':
                    if not self._auth_method_compatible(credential.auth_method, required_auth_method):
                        logger.error(
                            f"Host-specific credential auth_method '{credential.auth_method}' "
                            f"does not match required '{required_auth_method}'"
                        )
                        raise AuthMethodMismatchError(
                            f"Host requires {required_auth_method} but credential is {credential.auth_method}"
                        )

                return credential
            else:
                logger.info(f"No host-specific credential found for target: {target_id}")

        # 2. Fall back to system default
        logger.info("Attempting to resolve system default credential")
        credential = self._get_system_default()

        if not credential:
            logger.error("No system default credential available")
            return None

        logger.info(f"✅ Found system default credential (auth_method: {credential.auth_method})")

        # 3. Validate system default matches requirement
        if required_auth_method and required_auth_method != 'system_default':
            if not self._auth_method_compatible(credential.auth_method, required_auth_method):
                logger.error(
                    f"System default auth_method '{credential.auth_method}' "
                    f"does not match required '{required_auth_method}'"
                )
                raise AuthMethodMismatchError(
                    f"Host requires {required_auth_method} but system default is {credential.auth_method}"
                )

        return credential

    except AuthMethodMismatchError:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve credential: {e}")
        return None
```

#### 1.2 Add `_get_host_credential()` Method

**File:** `backend/app/services/auth_service.py`

**New Method:**
```python
def _get_host_credential(self, target_id: str) -> Optional[CredentialData]:
    """
    Get host-specific credential from unified_credentials table.

    Args:
        target_id: Host UUID

    Returns:
        CredentialData for the host, or None if not found
    """
    try:
        result = self.db.execute(text("""
            SELECT id FROM unified_credentials
            WHERE scope = 'host'
              AND target_id = :target_id
              AND is_active = true
            ORDER BY created_at DESC
            LIMIT 1
        """), {"target_id": target_id})

        row = result.fetchone()
        if row:
            credential = self.get_credential(row.id)
            if credential:
                credential.source = f"host:{target_id}"
                return credential

        return None

    except Exception as e:
        logger.error(f"Failed to get host credential for {target_id}: {e}")
        return None
```

#### 1.3 Add `_auth_method_compatible()` Method

**File:** `backend/app/services/auth_service.py`

**New Method:**
```python
def _auth_method_compatible(self, available: str, required: str) -> bool:
    """
    Check if available auth method satisfies required auth method.

    Compatibility matrix:
    - 'both' satisfies: 'password', 'ssh_key', 'both'
    - 'password' satisfies: 'password' only
    - 'ssh_key' satisfies: 'ssh_key' only

    Args:
        available: Auth method available in credential
        required: Auth method required by host

    Returns:
        True if compatible, False otherwise
    """
    if available == required:
        return True

    if available == 'both':
        # 'both' can satisfy any requirement
        return required in ['password', 'ssh_key', 'both']

    return False
```

#### 1.4 Add Exception Class

**File:** `backend/app/services/auth_service.py`

**New Exception:**
```python
class AuthMethodMismatchError(Exception):
    """Raised when credential auth method doesn't match requirement"""
    pass
```

**Testing:**
```python
# Test case 1: Host with host-specific SSH key
host_id = "126259ff-256b-4453-8102-37674996bde2"
cred = auth_service.resolve_credential(
    target_id=host_id,
    required_auth_method='ssh_key'
)
assert cred.source == f"host:{host_id}"
assert cred.auth_method == 'ssh_key'

# Test case 2: Host requiring password but system default is SSH key
try:
    cred = auth_service.resolve_credential(
        target_id=None,  # No host-specific
        required_auth_method='password'
    )
    assert False, "Should raise AuthMethodMismatchError"
except AuthMethodMismatchError:
    pass  # Expected
```

---

### Phase 2: Update Host Monitoring to Pass Auth Method

**Objective:** Make host monitoring respect host's configured auth_method

**Changes Required:**

#### 2.1 Update Host Monitor

**File:** `backend/app/services/host_monitor.py`

**Find calls to `resolve_credential()` and update:**

**Current (estimated):**
```python
# Probably does:
cred = auth_service.resolve_credential(use_default=True)
```

**New:**
```python
# Get host configuration
host = db.query(Host).filter(Host.id == host_id).first()

# Resolve credential matching host's auth_method
cred = auth_service.resolve_credential(
    target_id=str(host.id),
    required_auth_method=host.auth_method
)

if not cred:
    logger.error(f"No credential available for host {host.hostname} with auth_method={host.auth_method}")
    return
```

**Testing:**
```bash
# Should see in logs:
"Attempting to resolve host-specific credential for target: <uuid>"
"✅ Found host-specific credential (auth_method: password)"
```

---

### Phase 3: Implement "Both" Authentication Method

**Objective:** Make auth_method='both' attempt fallback

**Changes Required:**

#### 3.1 Update SSH Connection Logic

**File:** `backend/app/services/unified_ssh_service.py` (or similar)

**Add fallback logic:**

```python
def connect_with_credential(self, host, credential):
    """
    Connect to host using credential with fallback support.

    If credential.auth_method == 'both':
    1. Try SSH key first
    2. If fails, try password
    3. Return result
    """
    if credential.auth_method == 'both':
        logger.info(f"Credential has 'both' auth method, attempting SSH key first")

        # Try SSH key
        if credential.private_key:
            try:
                return self._connect_ssh_key(host, credential)
            except Exception as e:
                logger.warning(f"SSH key authentication failed: {e}")

        # Fallback to password
        if credential.password:
            logger.info("Falling back to password authentication")
            try:
                return self._connect_password(host, credential)
            except Exception as e:
                logger.error(f"Password authentication also failed: {e}")
                raise

        raise AuthenticationError("Both SSH key and password authentication failed")

    elif credential.auth_method == 'ssh_key':
        return self._connect_ssh_key(host, credential)

    elif credential.auth_method == 'password':
        return self._connect_password(host, credential)

    else:
        raise ValueError(f"Unknown auth_method: {credential.auth_method}")
```

---

### Phase 4: Create Password System Default Credential

**Objective:** Enable password authentication option for users

**Changes Required:**

#### 4.1 Document Password Credential Creation

**Via UI:**
1. Navigate to: Settings >> System Settings >> SSH Credentials
2. Click: Add New Credential
3. Fill in:
   - Name: "System Default Password"
   - Username: owadmin (or appropriate)
   - Authentication Method: "Password"
   - Password: (secure password)
   - Set as Default: (optional - or keep SSH key as default)
4. Save

**Via API:**
```bash
curl -X POST http://localhost:8000/api/system/credentials \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "System Default Password",
    "username": "owadmin",
    "auth_method": "password",
    "password": "SecurePassword123!",
    "is_default": false
  }'
```

**Testing:**
```python
# Verify password credential exists
result = db.execute(text("""
    SELECT * FROM unified_credentials
    WHERE scope = 'system' AND auth_method = 'password'
"""))
assert result.fetchone() is not None
```

---

### Phase 5: Add Host-Specific Credential UI

**Objective:** Allow users to create host-specific credentials via UI

**Changes Required:**

#### 5.1 Frontend: Host Edit Form

**File:** `frontend/src/components/Hosts/HostEditDialog.tsx` (estimated)

**Add credential section:**
```typescript
// When auth_method is not 'system_default':
<FormControl>
  <FormLabel>Host-Specific Credential</FormLabel>

  {authMethod === 'password' && (
    <TextField
      label="Password"
      type="password"
      value={hostPassword}
      onChange={(e) => setHostPassword(e.target.value)}
    />
  )}

  {authMethod === 'ssh_key' && (
    <TextField
      label="SSH Private Key"
      multiline
      rows={10}
      value={hostSSHKey}
      onChange={(e) => setHostSSHKey(e.target.value)}
    />
  )}

  {authMethod === 'both' && (
    <>
      <TextField label="Password" type="password" />
      <TextField label="SSH Private Key" multiline rows={10} />
    </>
  )}
</FormControl>
```

#### 5.2 Backend: Host API Update

**File:** `backend/app/routes/hosts.py`

**Update create/update endpoints:**
```python
@router.put("/hosts/{host_id}")
async def update_host(host_id: str, host_update: HostUpdate, db: Session = Depends(get_db)):
    # ... existing host update logic ...

    # NEW: If user provided host-specific credentials, store them
    if host_update.auth_method != 'system_default':
        if host_update.password or host_update.ssh_private_key:
            # Create host-specific credential
            auth_service = get_auth_service(db)

            credential_data = CredentialData(
                username=host_update.username or host.username,
                auth_method=AuthMethod(host_update.auth_method),
                password=host_update.password,
                private_key=host_update.ssh_private_key,
                private_key_passphrase=host_update.ssh_passphrase,
                source="host_edit_form"
            )

            metadata = CredentialMetadata(
                name=f"{host.hostname} credential",
                description=f"Host-specific credential for {host.hostname}",
                scope=CredentialScope.HOST,
                target_id=host_id,
                is_default=False,
                is_active=True
            )

            # Store or update host-specific credential
            auth_service.store_credential(
                credential_data=credential_data,
                metadata=metadata,
                created_by=current_user['id']
            )

    return host
```

---

## Implementation Priority

### Critical (Must Have) - Week 1

1. ✅ **Phase 1.1-1.4:** Implement host-specific credential resolution
   - **Why:** Core functionality blocking all user intent
   - **Impact:** Enables host-specific credentials to work
   - **Effort:** 4-6 hours
   - **Risk:** Medium (touching core auth logic)

2. ✅ **Phase 2.1:** Update host monitoring to pass auth_method
   - **Why:** Makes monitoring respect user configuration
   - **Impact:** Fixes compliance violations in monitoring
   - **Effort:** 2-3 hours
   - **Risk:** Low (isolated change)

3. ✅ **Testing:** Comprehensive auth resolution testing
   - **Why:** Verify user intent is respected
   - **Impact:** Prevents regression
   - **Effort:** 3-4 hours

### Important (Should Have) - Week 2

4. ✅ **Phase 3.1:** Implement "both" fallback logic
   - **Why:** Enables resilient authentication
   - **Impact:** "Both" option becomes functional
   - **Effort:** 3-4 hours
   - **Risk:** Medium (new connection logic)

5. ✅ **Phase 4.1:** Document password credential creation
   - **Why:** Enables password authentication
   - **Impact:** Makes password option available
   - **Effort:** 1 hour
   - **Risk:** None (documentation only)

### Nice to Have - Week 3

6. ⚠️ **Phase 5.1-5.2:** Add host-specific credential UI
   - **Why:** Better user experience
   - **Impact:** Easier credential management
   - **Effort:** 6-8 hours
   - **Risk:** Low (UI only, API already exists)

---

## Testing Strategy

### Test Case 1: Host with Password Auth

**Setup:**
```sql
-- Host configured for password
UPDATE hosts SET auth_method = 'password' WHERE id = '<uuid>';

-- Create host-specific password credential
INSERT INTO unified_credentials (scope, target_id, username, auth_method, encrypted_password, ...)
VALUES ('host', '<uuid>', 'testuser', 'password', <encrypted>, ...);
```

**Test:**
```python
cred = auth_service.resolve_credential(
    target_id='<uuid>',
    required_auth_method='password'
)

assert cred.auth_method == 'password'
assert cred.password is not None
assert cred.private_key is None
```

**Expected Behavior:**
- ✅ Returns host-specific password credential
- ✅ Does NOT return system default SSH key
- ✅ User intent respected

### Test Case 2: Host Requires Password but Only System Default (SSH Key) Available

**Setup:**
```sql
-- Host configured for password
UPDATE hosts SET auth_method = 'password' WHERE id = '<uuid>';

-- No host-specific credential
-- System default is SSH key
```

**Test:**
```python
try:
    cred = auth_service.resolve_credential(
        target_id='<uuid>',
        required_auth_method='password'
    )
    assert False, "Should raise AuthMethodMismatchError"
except AuthMethodMismatchError as e:
    assert 'password' in str(e).lower()
    assert 'ssh_key' in str(e).lower()
```

**Expected Behavior:**
- ✅ Raises clear error
- ✅ Does NOT silently use wrong auth method
- ✅ User knows configuration is invalid

### Test Case 3: "Both" Auth Method with Fallback

**Setup:**
```sql
-- Credential with both password and SSH key
INSERT INTO unified_credentials (auth_method, encrypted_password, encrypted_private_key, ...)
VALUES ('both', <encrypted_pwd>, <encrypted_key>, ...);
```

**Test:**
```python
# Mock SSH key failure
with mock.patch('ssh_connect', side_effect=AuthenticationError):
    # Should fallback to password
    connection = connect_with_credential(host, credential)
    assert connection.auth_method_used == 'password'
```

**Expected Behavior:**
- ✅ Tries SSH key first
- ✅ Falls back to password on failure
- ✅ Connection succeeds

---

## Success Criteria

### Definition of Done

1. ✅ **Host-specific credentials work**
   - User can create host-specific password credential
   - User can create host-specific SSH key credential
   - System uses host-specific credential when available
   - System does NOT fallback to system default if host-specific exists

2. ✅ **Auth method enforcement works**
   - Host configured for password → uses password (or errors if unavailable)
   - Host configured for SSH key → uses SSH key (or errors if unavailable)
   - Host configured for "both" → tries both with fallback
   - Host configured for system default → uses system default

3. ✅ **Compliance requirements met**
   - User can mandate password-only authentication for specific hosts
   - User can mandate SSH-key-only authentication for specific hosts
   - User can isolate credentials per customer/environment
   - Audit logs show correct auth method used

4. ✅ **No regressions**
   - Existing hosts with system_default continue working
   - Current SSH key authentication unaffected
   - Host monitoring remains operational
   - API backwards compatible

---

## Rollback Plan

If implementation causes issues:

1. **Immediate Rollback:**
   ```bash
   git revert <commit-hash>
   docker-compose restart backend worker
   ```

2. **Feature Flag:**
   ```python
   # Add to settings
   ENABLE_HOST_SPECIFIC_CREDENTIALS = os.getenv('ENABLE_HOST_SPECIFIC_CREDS', 'false').lower() == 'true'

   # In code
   if settings.ENABLE_HOST_SPECIFIC_CREDENTIALS:
       cred = self._get_host_credential(target_id)
   else:
       cred = self._get_system_default()
   ```

3. **Gradual Rollout:**
   - Week 1: Deploy to dev environment
   - Week 2: Deploy to staging, test with real hosts
   - Week 3: Deploy to production with monitoring

---

## Conclusion

**Current State:** Authentication system does NOT respect user intent - critical gap for compliance scanning.

**Required Action:** Implement Phase 1 (host-specific resolution) and Phase 2 (auth method passing) as **CRITICAL PRIORITY**.

**Timeline:** Can be completed in 1-2 weeks with proper testing.

**Impact:** Enables OpenWatch to meet compliance requirements where specific authentication methods are mandated.
