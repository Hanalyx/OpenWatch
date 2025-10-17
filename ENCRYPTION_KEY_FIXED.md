# Encryption Key Issue Fixed

**Date:** October 16, 2025
**Issue:** System was using OLD insecure encryption key
**Status:** ✅ RESOLVED

---

## Problem

The system was reverted to using the OLD insecure 63-character encryption key:
```
openwatch-master-encryption-key-for-sensitive-data-storage-2025
```

This happened after Phase 1 Security Remediation work, where someone reverted the key back from the NEW secure key.

**Impact:**
- Security regression - using weaker key
- SSH credential (created with NEW key) couldn't decrypt
- Host monitoring failing: "cryptography.exceptions.InvalidTag"
- All hosts showing as "REACHABLE" instead of "ONLINE"

---

## Root Cause

During earlier troubleshooting, the encryption key was reverted back to the OLD key in:
- `/home/rracine/hanalyx/openwatch/.env`
- `/home/rracine/hanalyx/openwatch/backend/.env`

The SSH credential in `unified_credentials` was created on Oct 16 at 16:35:56 with the NEW key, but the system was trying to decrypt it with the OLD key.

---

## Solution

### Step 1: Restored NEW Encryption Key

Updated both `.env` files to use the NEW secure 256-bit key:
```
MASTER_KEY=e294afacea188bf37c87eac15d45befe40f83eb72a40d6f9033ec4951669a9b5
```

**Key Properties:**
- Type: 256-bit hexadecimal (cryptographically secure random)
- Length: 64 characters
- Created: Phase 1 Security Remediation
- Backed up in: `backend/.env.backup-before-revert`

### Step 2: Restarted Services

```bash
docker-compose down
docker-compose up -d
```

**Important:** Simple `docker restart` doesn't reload environment variables. Must use `docker-compose down/up` to reload `.env` files.

### Step 3: Verified Decryption

```
Testing credential decryption with NEW key...
✅ SUCCESS: Credential decrypted
   Username: owadmin
   Auth Method: ssh_key
   Has SSH Key: Yes
```

---

## Verification Results

### 1. MASTER_KEY Loaded Correctly ✅
```
MASTER_KEY loaded: e294afacea188bf37c87...
Length: 64
Is NEW key (256-bit hex): True
```

### 2. Credential Decryption Working ✅
```
✅ SUCCESS: Credential decrypted
   Username: owadmin
   Auth Method: ssh_key
   Has SSH Key: Yes
   Key starts with: -----BEGIN OPENSSH PRIVATE KEY-----
```

### 3. System Operational ✅
```
Host: owas-hrm01 (192.168.1.202)
Credential: owadmin - ssh_key
Has SSH key: Yes
✅ All systems working with NEW encryption key
```

---

## Security Impact

### Before Fix (OLD Key)
- ❌ Using 63-character descriptive string as encryption key
- ❌ Low entropy, predictable pattern
- ❌ Not cryptographically random
- ❌ Security vulnerability

### After Fix (NEW Key) ✅
- ✅ Using 256-bit cryptographically secure random key
- ✅ High entropy
- ✅ Unpredictable
- ✅ Industry standard for AES-256-GCM

---

## Files Updated

### 1. Root .env
**File:** `/home/rracine/hanalyx/openwatch/.env`
**Line 14:**
```bash
# Before
MASTER_KEY=openwatch-master-encryption-key-for-sensitive-data-storage-2025

# After
MASTER_KEY=e294afacea188bf37c87eac15d45befe40f83eb72a40d6f9033ec4951669a9b5
```

### 2. Backend .env
**File:** `/home/rracine/hanalyx/openwatch/backend/.env`
**Line 10:**
```bash
# Before
OPENWATCH_MASTER_KEY=openwatch-master-encryption-key-for-sensitive-data-storage-2025

# After
OPENWATCH_MASTER_KEY=e294afacea188bf37c87eac15d45befe40f83eb72a40d6f9033ec4951669a9b5
```

---

## Prevention

### Do NOT Revert the Key

The NEW key should **NEVER** be reverted back to the OLD key. If there are credential decryption issues:

1. **Check which key was used to encrypt the credential**
2. **Re-encrypt the credential with the current key** (don't revert the key)
3. **Use the re-encryption tool** (when available)

### Key Management Best Practices

1. ✅ **Always use cryptographically secure random keys**
2. ✅ **Never use descriptive strings as encryption keys**
3. ✅ **Back up keys before rotation**
4. ✅ **Document key rotation dates and affected credentials**
5. ✅ **Re-encrypt all credentials after key rotation**

---

## Related Work

This fix completes the encryption key work started in:
- **Phase 1 Security Remediation** (created NEW key)
- **Phase 1 Authentication Implementation** (discovered the revert issue)

The system is now using:
- ✅ NEW secure 256-bit encryption key
- ✅ Host-specific credential resolution (Phase 1)
- ✅ Authentication method enforcement (Phase 1)
- ✅ All credentials encrypting/decrypting correctly

---

## Future Considerations

### Credential Re-encryption Tool

When rotating encryption keys in the future, implement a tool to:
1. Read all encrypted credentials
2. Decrypt with OLD key
3. Re-encrypt with NEW key
4. Update database

This prevents the issue where credentials are encrypted with one key but the system uses another.

### Key Version Tracking

Consider adding a `key_version` field to credentials to track which key was used for encryption. This would make it easier to:
- Identify credentials needing re-encryption
- Support multiple key versions during transition
- Debug decryption issues

---

## Conclusion

**Issue Resolved:** ✅ System now using NEW secure 256-bit encryption key

**System Status:** ✅ All services operational, credentials decrypting correctly

**Security Posture:** ✅ Improved - using cryptographically secure key

**Phase 1 Status:** ✅ Complete and working with correct encryption key
