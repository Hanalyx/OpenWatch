# Encryption Migration Baseline Metrics

**Migration**: crypto.py → encryption.py
**Date**: 2025-11-01
**Branch**: `feat/migrate-encryption-py`
**Backup File**: `backups/backup_pre_encryption_migration_20251101.sql` (370 KB)

---

## Database Baseline (Pre-Migration)

### PostgreSQL Database: `openwatch`

**Table**: `hosts`
- **Total Hosts**: 5
- **Hosts with `encrypted_credentials`**: 0
- **Hosts without `encrypted_credentials`**: 5

**All hosts currently use `system_default` auth_method** (rely on unified_credentials table).

#### Host Inventory:
| ID | Hostname | IP Address | Auth Method | Has Encrypted Creds |
|----|----------|------------|-------------|---------------------|
| a80a6479-97c5-4ed6-b56b-9098e5a55764 | owas-hrm01 | 192.168.1.202 | system_default | No |
| 3ca628b1-5183-4dba-9337-14d10a037274 | owas-rhn01 | 192.168.1.213 | system_default | No |
| 435af0ff-200b-453c-84ea-ddd07f04f216 | owas-tst01 | 192.168.1.203 | system_default | No |
| 3445de70-2b5e-4afd-a88f-095c57271143 | owas-tst02 | 192.168.1.211 | system_default | No |
| 3600b521-6e7a-47c4-ba0b-bcf868ac1d9e | owas-ub5s2 | 192.168.1.217 | system_default | No |

---

**Table**: `unified_credentials`
- **Total Active Credentials**: 1
- **System Credentials**: 1
- **Host-Specific Credentials**: 0
- **Default Credentials**: 1

#### Credential Inventory:
| ID | Name | Scope | Auth Method | Is Default | Created |
|----|------|-------|-------------|------------|---------|
| 0edb4ceb-0090-478a-be75-f30647d9beb3 | owadmin | system | both | Yes | 2025-11-01 03:05:05 |

---

## Migration Impact Analysis

### ✅ **EXCELLENT NEWS: Minimal Migration Complexity**

**Key Findings**:
1. ✅ **NO hosts using legacy `encrypted_credentials` column** in `hosts` table
2. ✅ **ALL hosts use `system_default` authentication** (unified_credentials table)
3. ✅ **Only 1 system credential** needs to be verified
4. ✅ **No host-specific credentials** to migrate

### Simplified Migration Plan

Since there are **ZERO entries in hosts.encrypted_credentials**, the migration is significantly simpler:

#### **Original Plan** (for systems with legacy data):
- Decrypt all hosts.encrypted_credentials with crypto.py
- Re-encrypt with encryption.py
- Update database
- Risk: HIGH (data migration)

#### **Actual Situation** (current state):
- Verify the 1 system credential uses encryption.py format ✅
- Update code to use encryption.py exclusively ✅
- Remove crypto.py fallback logic ✅
- Risk: LOW (no data migration needed)

---

## Verification Steps

### Verify System Credential Format

The single system credential (ID: `0edb4ceb-0090-478a-be75-f30647d9beb3`) needs to be verified:

```sql
-- Check which encryption format is used
SELECT
  id,
  name,
  LENGTH(encrypted_password) as pwd_length,
  LENGTH(encrypted_private_key) as key_length
FROM unified_credentials
WHERE id = '0edb4ceb-0090-478a-be75-f30647d9beb3';
```

**Expected**:
- If encrypted with `encryption.py`: Format is `salt(16) + nonce(12) + ciphertext_with_tag`
- If encrypted with `crypto.py`: Format is `salt(16) + nonce(12) + tag(16) + ciphertext`

**Action Required**:
- Test decryption with both `encryption.py` and `crypto.py`
- If using crypto.py format, re-encrypt once with encryption.py
- If already using encryption.py, no action needed

---

## Files Requiring Updates

Based on earlier analysis, these 5 files use crypto.py:

| File | Usage | Impact | Migration Action |
|------|-------|--------|------------------|
| `backend/app/services/host_monitor.py` | Decrypt `hosts.encrypted_credentials` | ✅ NONE (no data in column) | Remove fallback logic |
| `backend/app/services/terminal_service.py` | SSH terminal credentials | ⚠️ VERIFY | Test with encryption.py only |
| `backend/app/services/command_sandbox.py` | Remediation commands | ⚠️ VERIFY | Update to encryption.py |
| `backend/app/tasks/scan_tasks.py` | Celery scan tasks | ⚠️ VERIFY | Update to encryption.py |
| `backend/app/routes/ssh_debug.py` | Debug endpoint | ✅ LOW | Update to encryption.py |

**Since hosts.encrypted_credentials is empty**, only the unified_credentials path needs validation.

---

## Success Criteria (Simplified)

**Pre-Migration** ✅:
- [x] Database backup created (370 KB)
- [x] Baseline metrics documented
- [x] Git branch created: `feat/migrate-encryption-py`
- [x] Current work committed

**Phase 1 (Code Updates)** ⏳:
- [ ] Create encryption_compatibility.py helper (defensive, but not strictly needed)
- [ ] Update 5 files to prefer encryption.py
- [ ] Test suite validates both formats work
- [ ] Deploy code changes

**Phase 2 (Verification)** ⏳:
- [ ] Verify system credential decrypts with encryption.py
- [ ] Test SSH connections to all 5 hosts
- [ ] Test terminal service
- [ ] Test scan execution

**Phase 3 (Cleanup)** ⏳:
- [ ] Remove crypto.py fallback logic (if verified all using encryption.py)
- [ ] Deprecate crypto.py
- [ ] Update documentation

---

## Risk Assessment

**Original Risk Level**: 🔴 HIGH (data migration required)
**Actual Risk Level**: 🟢 **LOW** (no data migration needed)

**Why Low Risk**:
1. ✅ Zero hosts using legacy `encrypted_credentials` column
2. ✅ Only 1 credential to verify (system default)
3. ✅ All encryption happens in unified_credentials (managed by auth_service)
4. ✅ auth_service already uses encryption.py (from earlier code review)
5. ✅ No production data to migrate

**Remaining Risks**:
- ⚠️ If system credential was encrypted with crypto.py, need one-time re-encryption
- ⚠️ Code using crypto.py directly might break (need fallback during transition)

---

## Next Steps (Phase 1, Day 1 Afternoon)

1. Create `encryption_compatibility.py` helper (defensive programming)
2. Test if system credential uses encryption.py or crypto.py
3. If crypto.py format detected:
   - Write one-time migration script for the 1 credential
   - Test thoroughly before applying
4. Update 5 code files to use encryption_compatibility.py
5. Deploy and verify

**Timeline**: Reduced from 14 days to **3-4 days** due to simplified scope.

---

## Conclusion

**This migration is MUCH simpler than originally planned** because:
- ✅ No legacy data in `hosts.encrypted_credentials`
- ✅ Only 1 system credential to verify
- ✅ Already using modern unified_credentials architecture
- ✅ No user-facing downtime required

The migration is primarily a **code cleanup** exercise rather than a data migration.

---

**Generated**: 2025-11-01
**By**: OpenWatch Migration Planning
**Status**: ✅ Baseline Complete - Ready for Phase 1 Afternoon
