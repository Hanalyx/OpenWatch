# Encryption Key Migration - SSH Credentials Issue

**Date**: October 16, 2025
**Issue**: SSH credentials cannot be decrypted after Phase 1 encryption key rotation
**Status**: ⚠️ REQUIRES MANUAL INTERVENTION

---

## Problem Summary

During Phase 1 security remediation, we generated a new secure `OPENWATCH_ENCRYPTION_KEY` to replace the insecure default key. However, this created an issue:

**Before Phase 1:**
- SSH credentials were encrypted with the old default key: `"dev-key-change-in-production"`

**After Phase 1:**
- New secure encryption key generated: `e294afacea188bf37c87eac15d45befe40f83eb72a40d6f9033ec4951669a9b5`
- Existing SSH credentials in database still encrypted with old key
- Application cannot decrypt old credentials with new key
- **Result**: All SSH host monitoring and scanning broken

---

## Error Symptoms

Backend logs show:
```
backend.app.services.encryption - ERROR - Decryption error:
backend.app.services.auth_service - ERROR - Failed to get credential 833d1d67-2dd0-47fc-98fe-73a96a68d7ff
backend.app.services.host_monitor - WARNING - No credentials available for host owas-tst02
backend.app.services.host_monitor - INFO - No SSH credentials available for owas-tst02 (neither host-specific nor system default)
```

All hosts report: `No SSH credentials configured`

---

## Root Cause

In Phase 2 (commit bf1a811), we added fail-safe validation to `backend/app/services/crypto.py`:

**Before**:
```python
ENCRYPTION_KEY = os.getenv("OPENWATCH_ENCRYPTION_KEY", "dev-key-change-in-production")
```

**After**:
```python
ENCRYPTION_KEY = os.getenv("OPENWATCH_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("OPENWATCH_ENCRYPTION_KEY must be set")
```

This was a **security improvement** to prevent using weak default keys. However, we didn't migrate the existing encrypted data.

---

## Solution Options

### Option 1: Re-encrypt Credentials (Recommended - Automated)

Use the provided migration script to decrypt with old key and re-encrypt with new key.

**Steps**:

1. **Dry run first** (safe - makes no changes):
```bash
docker exec -it openwatch-backend python3 /app/backend/scripts/reencrypt_credentials.py \
  --old-key "dev-key-change-in-production" \
  --new-key "$OPENWATCH_ENCRYPTION_KEY" \
  --database-url "$OPENWATCH_DATABASE_URL" \
  --dry-run
```

2. **Review output** - Verify it finds your credentials

3. **Apply changes** (removes --dry-run):
```bash
docker exec -it openwatch-backend python3 /app/backend/scripts/reencrypt_credentials.py \
  --old-key "dev-key-change-in-production" \
  --new-key "$OPENWATCH_ENCRYPTION_KEY" \
  --database-url "$OPENWATCH_DATABASE_URL"
```

4. **Restart services**:
```bash
docker-compose restart backend worker
```

5. **Verify** - Check logs for successful SSH connections

---

### Option 2: Re-enter Credentials (Manual - Safer but Time-Consuming)

If you prefer to manually re-enter credentials through the UI:

1. Go to **Settings → System Settings → SSH Credentials**
2. Delete existing system default credential
3. Create new system default credential with:
   - SSH username
   - SSH password or private key
4. For host-specific credentials:
   - Go to **Hosts → [hostname] → Edit**
   - Re-enter SSH credentials
5. Test connection on each host

**Pros**: No risk of decryption errors, fresh credentials
**Cons**: Time-consuming if you have many hosts, original credentials must be known

---

### Option 3: Temporarily Revert Key (Quick Fix - Not Recommended)

**WARNING**: This reverts to the insecure default key and should only be used temporarily.

1. **Backup current .env files**:
```bash
cp /home/rracine/hanalyx/openwatch/.env /home/rracine/hanalyx/openwatch/.env.secure
cp /home/rracine/hanalyx/openwatch/backend/.env /home/rracine/hanalyx/openwatch/backend/.env.secure
```

2. **Temporarily use old key**:
```bash
# Update .env files
sed -i 's/OPENWATCH_ENCRYPTION_KEY=.*/OPENWATCH_ENCRYPTION_KEY=dev-key-change-in-production/' \
  /home/rracine/hanalyx/openwatch/.env
sed -i 's/OPENWATCH_ENCRYPTION_KEY=.*/OPENWATCH_ENCRYPTION_KEY=dev-key-change-in-production/' \
  /home/rracine/hanalyx/openwatch/backend/.env
```

3. **Restart services**:
```bash
docker-compose restart backend worker
```

4. **Verify credentials work**

5. **Use Option 1 to migrate to new key**, then restore secure key:
```bash
mv /home/rracine/hanalyx/openwatch/.env.secure /home/rracine/hanalyx/openwatch/.env
mv /home/rracine/hanalyx/openwatch/backend/.env.secure /home/rracine/hanalyx/openwatch/backend/.env
docker-compose restart backend worker
```

---

## Re-encryption Script Details

**Location**: `backend/scripts/reencrypt_credentials.py`

**What it does**:
1. Connects to PostgreSQL database
2. Finds all credentials in `unified_credentials` table with encrypted data
3. For each credential:
   - Decrypts `encrypted_password` using old key
   - Decrypts `encrypted_private_key` using old key
   - Re-encrypts both fields using new key
   - Updates database record

**Safety features**:
- `--dry-run` mode to preview changes without modifying database
- Confirms before proceeding in live mode
- Rolls back on errors
- Detailed logging of each credential processed
- Summary report at end

**Requirements**:
- Access to database (uses OPENWATCH_DATABASE_URL env var)
- Old encryption key
- New encryption key
- Python environment with SQLAlchemy and cryptography

---

## Verification Steps

After re-encryption, verify SSH credentials work:

1. **Check backend logs**:
```bash
docker logs openwatch-backend 2>&1 | grep -i "credential\|decrypt" | tail -20
```

Should NOT see: `Decryption error` or `Failed to get credential`

2. **Check host monitoring**:
```bash
docker logs openwatch-backend 2>&1 | grep "host_monitor" | tail -20
```

Should see: `SSH credentials found` and successful connection attempts

3. **Test SSH connection** through UI:
   - Go to **Hosts** page
   - Check host status - should show "Connected" or "Online"
   - Try running a scan on a host

4. **Manual SSH test** from container:
```bash
docker exec -it openwatch-backend ssh -o StrictHostKeyChecking=no user@hostname
```

---

## Prevention for Future Key Rotations

When rotating encryption keys in the future:

1. **Always create a migration script** before changing keys
2. **Test with --dry-run** first
3. **Backup database** before migration
4. **Document old key** in SECRET_ROTATION_LOG.md for emergency recovery
5. **Verify all encrypted data** after migration
6. **Update monitoring** to alert on decryption failures

---

## Technical Details

### Encryption Algorithm
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Nonce Size**: 12 bytes (recommended for GCM)
- **Salt Size**: 16 bytes
- **Storage Format**: `[salt(16)][nonce(12)][ciphertext]` then base64 encoded

### Database Schema
```sql
CREATE TABLE unified_credentials (
    id UUID PRIMARY KEY,
    credential_type VARCHAR(50),  -- 'system_default', 'host_specific', 'scan_specific'
    username VARCHAR(255),
    encrypted_password TEXT,      -- Base64 encoded encrypted data
    encrypted_private_key TEXT,   -- Base64 encoded encrypted data
    target_type VARCHAR(50),      -- 'host', 'scan'
    target_id UUID,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Affected Services
- `backend/app/services/auth_service.py` - Credential retrieval
- `backend/app/services/host_monitor.py` - SSH host monitoring
- `backend/app/services/scap_scanner.py` - Remote SCAP scanning
- `backend/app/tasks/monitoring_tasks.py` - Periodic host checks

---

## Impact Assessment

**Severity**: HIGH - All SSH-based operations broken

**Affected Features**:
- ❌ Remote host monitoring (all hosts show "No credentials")
- ❌ SSH-based SCAP scanning
- ❌ Remote remediation tasks
- ❌ Host status checks
- ✅ Local operations still work
- ✅ Web UI accessible
- ✅ Database operations normal

**Number of Affected Hosts**: All hosts with SSH credentials (appears to be 7+ hosts)

**Downtime**: None - services running, just SSH operations failing

---

## Rollback Plan

If re-encryption fails or causes issues:

1. **Restore database backup** (if taken before migration)
2. **Revert to old encryption key** (temporary - see Option 3)
3. **Restore .env files** from backup
4. **Restart services**
5. **Investigate** re-encryption script errors
6. **Contact support** if needed

---

## Recommended Action

**For immediate fix**: Use **Option 1** (Re-encrypt Credentials)

**Advantages**:
- ✅ Automated and fast
- ✅ Preserves existing credentials
- ✅ Maintains security (moves to new strong key)
- ✅ Dry-run mode for safety
- ✅ Can be audited via logs

**Timeline**: 5-10 minutes including verification

**Risk**: Low (dry-run first, rollback available)

---

## Follow-up Actions

After fixing:

1. **Document** the old key in SECRET_ROTATION_LOG.md (for emergency recovery only)
2. **Test** SSH connections to all hosts
3. **Monitor** logs for 24 hours for any decryption errors
4. **Update** security procedures to include data migration for key rotations
5. **Create** backup/restore procedures for encryption keys

---

## Questions & Support

**Q: Can I use the old key temporarily?**
A: Yes (Option 3), but this reverts to the insecure default key. Only use temporarily while migrating.

**Q: Will this affect my user passwords?**
A: No. User passwords use Argon2id hashing (one-way), not encryption. Only SSH credentials are affected.

**Q: Can I just delete and re-create credentials?**
A: Yes (Option 2), but you must know the original passwords/keys to re-enter them.

**Q: What if I don't know the old key?**
A: The old default key was `"dev-key-change-in-production"`. If you had already changed it before our Phase 1, you'll need that previous key or must re-enter credentials (Option 2).

**Q: Will this happen again with future key rotations?**
A: No. We now have a migration script template. Future rotations should include running this script as part of the process.

---

## Status

- **Issue Identified**: October 16, 2025
- **Root Cause**: Encryption key rotation without data migration
- **Migration Script Created**: October 16, 2025
- **Fix Applied**: ⏳ PENDING USER ACTION
- **Verification**: ⏳ PENDING

---

**Next Step**: Choose an option above and follow the steps to restore SSH credential access.
