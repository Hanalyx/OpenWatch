# Compliance Rule Validation: Upload vs Update Comparison

**Version:** 1.0.0
**Date:** October 23, 2025
**Status:** Technical Comparison

## Overview

This document explains the differences between validation during **initial upload** (new rules) versus **update** (existing rules being re-imported). Understanding these differences is critical for troubleshooting import issues.

---

## Quick Answer

**The validation checks are IDENTICAL for both uploads and updates.**

The difference is NOT in validation but in what happens AFTER validation passes:

| Aspect | Initial Upload | Update |
|--------|----------------|--------|
| **Validation Phases** | All 8 phases (identical) | All 8 phases (identical) |
| **MongoDB Schema Validation** | Yes (Pydantic models) | Yes (Pydantic models) |
| **Content Hash Calculation** | Yes | Yes |
| **After Validation** | Create new rule (v1) | Create new version (v2, v3, etc.) |
| **Existing Data** | No existing rule in DB | Existing rule found in DB |
| **Deduplication** | Always "imported" | "skipped" or "updated" |

---

## The Complete Flow Comparison

### Initial Upload Flow (New Rule)

```
1. Bundle Upload
   ↓
2. Phase 1-3: Security Validation (SAME)
   ↓
3. Phase 4: Archive Extraction (SAME)
   ↓
4. Phase 5: Manifest Validation (SAME)
   ↓
5. Phase 6: Rule Parsing (SAME)
   ↓
6. Phase 7: Deduplication Check
   ├─ Query MongoDB for rule_id
   ├─ Result: NOT FOUND
   └─ Action: IMPORT (create new)
   ↓
7. Phase 8: MongoDB Validation (SAME)
   ├─ Pydantic model validation
   ├─ rule_id must start with "ow-"
   ├─ metadata.name required
   └─ platform_implementations.versions required
   ↓
8. Create New Rule
   ├─ version: 1
   ├─ is_latest: true
   ├─ effective_from: now
   └─ INSERT into MongoDB
   ↓
9. Intelligence Generation
   └─ Create RuleIntelligence record
```

---

### Update Flow (Existing Rule)

```
1. Bundle Upload
   ↓
2. Phase 1-3: Security Validation (SAME)
   ↓
3. Phase 4: Archive Extraction (SAME)
   ↓
4. Phase 5: Manifest Validation (SAME)
   ↓
5. Phase 6: Rule Parsing (SAME)
   ↓
6. Phase 7: Deduplication Check
   ├─ Query MongoDB for rule_id
   ├─ Result: FOUND (existing_rule)
   ├─ Calculate content hashes:
   │  ├─ existing_hash = SHA256(existing_rule - metadata)
   │  └─ new_hash = SHA256(new_rule - metadata)
   ├─ Compare hashes:
   │  ├─ If existing_hash == new_hash → SKIP (no changes)
   │  └─ If existing_hash != new_hash → UPDATE (content changed)
   └─ Detect field changes
   ↓
7. Phase 8: MongoDB Validation (SAME)
   ├─ Pydantic model validation
   ├─ rule_id must start with "ow-"
   ├─ metadata.name required
   └─ platform_implementations.versions required
   ↓
8a. If Action = SKIP
    └─ No MongoDB operation (rule unchanged)

8b. If Action = UPDATE
    ├─ Step 1: Mark existing version as superseded
    │  ├─ UPDATE existing document:
    │  │  ├─ is_latest: false
    │  │  ├─ effective_until: now
    │  │  └─ superseded_by: version + 1
    │  └─ (Immutable - existing data preserved)
    ├─ Step 2: Create new version
    │  ├─ version: existing.version + 1
    │  ├─ is_latest: true
    │  ├─ supersedes_version: existing.version
    │  ├─ effective_from: now
    │  ├─ change_summary: {...}
    │  └─ INSERT new document (append-only)
    └─ Step 3: Update RuleIntelligence (if needed)
   ↓
9. Intelligence Update
   └─ Recalculate importance if frameworks changed
```

---

## Key Differences Explained

### 1. MongoDB Query

**Initial Upload**:
```python
existing_rule = await ComplianceRule.find_one(
    ComplianceRule.rule_id == rule_id,
    ComplianceRule.is_latest == True
)
# Result: None (no existing rule)
```

**Update**:
```python
existing_rule = await ComplianceRule.find_one(
    ComplianceRule.rule_id == rule_id,
    ComplianceRule.is_latest == True
)
# Result: ComplianceRule document (found existing)
```

---

### 2. Content Hash Comparison

**Initial Upload**:
- No hash comparison (nothing to compare against)
- Action: Always "imported"

**Update**:
```python
# Calculate hashes
existing_hash = calculate_content_hash(existing_rule)
new_hash = calculate_content_hash(new_rule_data)

# Compare
if existing_hash == new_hash:
    action = "skipped"  # No changes
else:
    action = "updated"  # Content changed
```

**Hash Calculation** (excludes metadata):
```python
EXCLUDED_FROM_HASH = {
    # Metadata (changes every import)
    'imported_at', 'updated_at', 'source_file', '_id',

    # Versioning (immutable fields)
    'version', 'version_hash', 'is_latest',
    'supersedes_version', 'superseded_by',
    'effective_from', 'effective_until',

    # Provenance
    'source_bundle', 'source_bundle_hash', 'import_id',

    # Computed fields
    'derived_rules'
}

# Only compare actual rule content
normalized = {k: v for k, v in rule.items() if k not in EXCLUDED_FROM_HASH}
content_hash = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
```

---

### 3. Change Detection

**Initial Upload**:
- No change detection (no baseline to compare)
- Changes: N/A

**Update**:
```python
changes = detect_field_changes(existing_rule, new_rule_data)

# Example change detection
{
    'severity': {
        'old': 'medium',
        'new': 'high'
    },
    'frameworks.nist.controls': {
        'old': ['AC-2', 'AC-3'],
        'new': ['AC-2', 'AC-3', 'AC-6']  # Added AC-6
    },
    'metadata.description': {
        'old': 'Old description...',
        'new': 'Updated description...'
    }
}
```

**Change Categorization**:
```python
TRACKED_FIELD_CATEGORIES = {
    'metadata': ['metadata'],
    'frameworks': ['frameworks'],
    'platforms': ['platform_implementations'],
    'check_content': ['check_type', 'check_content'],
    'fix_content': ['fix_available', 'fix_content'],
    'severity': ['severity', 'remediation_risk'],
    'inheritance': ['inherits_from', 'base_parameters'],
    'dependencies': ['dependencies']
}
```

**Statistics**:
```
Rule ow-account_disable updated:
  - 3 fields changed
  - Categories: metadata, severity, frameworks
```

---

### 4. Database Operation

**Initial Upload**:
```python
# Create new rule (version 1)
new_rule = ComplianceRule(**rule_data)
new_rule.version = 1
new_rule.is_latest = True
new_rule.effective_from = datetime.utcnow()
new_rule.supersedes_version = None

await new_rule.insert()  # INSERT new document
```

**Update (Immutable Versioning)**:
```python
# Step 1: Mark old version as superseded
await ComplianceRule.find_one(
    ComplianceRule._id == existing_rule.id
).update({
    "$set": {
        "is_latest": False,
        "effective_until": datetime.utcnow(),
        "superseded_by": existing_rule.version + 1
    }
})

# Step 2: Create new version (append-only)
new_rule = ComplianceRule(**new_rule_data)
new_rule.version = existing_rule.version + 1
new_rule.is_latest = True
new_rule.supersedes_version = existing_rule.version
new_rule.effective_from = datetime.utcnow()
new_rule.change_summary = {
    'changed_fields': list(changes.keys()),
    'change_count': len(changes),
    'previous_version': existing_rule.version
}

await new_rule.insert()  # INSERT new version (never UPDATE)
```

**Immutable History**:
```
MongoDB after update:
[
  {
    rule_id: "ow-account_disable",
    version: 1,
    is_latest: false,           ← Marked as old
    effective_until: "2025-10-23T15:30:00Z",
    superseded_by: 2
  },
  {
    rule_id: "ow-account_disable",
    version: 2,
    is_latest: true,            ← Current version
    supersedes_version: 1,
    effective_from: "2025-10-23T15:30:00Z"
  }
]
```

---

## Validation That IS The Same

All 8 validation phases run identically for both uploads and updates:

### ✅ Phase 1: File Extension Validation
- **Same**: `.tar.gz` or `.tgz` required
- **Same**: Reject all other extensions

### ✅ Phase 2: File Size Validation
- **Same**: 0 bytes < size < 100MB
- **Same**: Empty file rejection
- **Same**: DoS protection

### ✅ Phase 3: Security Validation
- **Same**: SHA-512 hash calculation
- **Same**: Path traversal prevention
- **Same**: Forbidden filename detection
- **Same**: Archive bomb protection
- **Same**: Symlink blocking
- **Same**: Null byte detection

### ✅ Phase 4: Archive Extraction
- **Same**: Temporary directory extraction
- **Same**: Safe extraction (filter='data')
- **Same**: Permission restrictions (0o700)

### ✅ Phase 5: Manifest Validation
- **Same**: manifest.json/manifest.bson required
- **Same**: JSON format validation
- **Same**: Required fields: name, version, rules_count, created_at
- **Same**: Rule count verification
- **Same**: Signature verification (if enabled)

### ✅ Phase 6: Rule Parsing
- **Same**: BSON/JSON format validation
- **Same**: File corruption detection
- **Same**: Basic schema checks

### ✅ Phase 7: Deduplication
- **Different Decision**: Import vs Skip vs Update
- **Same Validation**: Hash calculation algorithm
- **Same Validation**: Field comparison logic

### ✅ Phase 8: MongoDB Validation
- **Same**: Pydantic model validation
- **Same**: rule_id prefix check (ow-)
- **Same**: metadata.name requirement
- **Same**: platform_implementations.versions requirement
- **Same**: Severity enum validation
- **Same**: Framework structure validation

---

## Example Scenarios

### Scenario 1: Upload Same Bundle Twice

**First Upload** (Initial):
```
✓ All validation phases pass
✓ Deduplication: rule_id not found
→ Action: IMPORT
→ Result: 2013 rules imported
```

**Second Upload** (Update):
```
✓ All validation phases pass (SAME)
✓ Deduplication: rule_id found
✓ Content hash: existing == new
→ Action: SKIP
→ Result: 0 imported, 0 updated, 2013 skipped
```

---

### Scenario 2: Upload Modified Bundle

**First Upload** (Initial):
```
✓ All validation phases pass
→ Result: 2013 rules imported (all v1)
```

**Second Upload** (1 rule changed):
```
✓ All validation phases pass (SAME)
✓ Deduplication:
  - 2012 rules: hash match → SKIP
  - 1 rule: hash mismatch → UPDATE
→ Result: 0 imported, 1 updated, 2012 skipped

MongoDB:
  - ow-changed-rule v1 (is_latest=false, superseded)
  - ow-changed-rule v2 (is_latest=true, current)
```

---

### Scenario 3: Validation Failure During Update

**Setup**: Rule exists in DB (v1)

**Upload New Bundle** (updated rule has validation error):
```
✓ Phase 1-6: All pass (SAME)
✓ Phase 7: Deduplication detects changes
→ Action: UPDATE

✗ Phase 8: MongoDB Validation FAILS
  Error: "platform_implementations.rhel8.versions: Field required"

→ Result: Update REJECTED
→ MongoDB: Original v1 remains unchanged (is_latest=true)
→ Statistics: 1 error, updated counter decremented
```

**Critical**: If validation fails during update, the existing rule is NOT modified. The update is completely rejected.

---

## Deduplication Strategies

The deduplication strategy affects what happens AFTER validation:

### Strategy 1: skip_all (Default)
```python
if existing_rule:
    return "SKIP"  # Never update, only import new
```

**Upload**: Import new rules
**Update**: Skip all existing rules (even if changed)

---

### Strategy 2: skip_unchanged_update_changed (Recommended)
```python
if existing_hash == new_hash:
    return "SKIP"
else:
    return "UPDATE"
```

**Upload**: Import new rules
**Update**: Skip unchanged, update changed rules

---

### Strategy 3: replace_all
```python
if existing_rule:
    return "UPDATE"  # Update everything
```

**Upload**: Import new rules
**Update**: Update ALL rules (create new versions)

---

### Strategy 4: version_increment
```python
# Always create new version (keep all versions)
if existing_rule:
    new_rule.version = max_version + 1
    return "IMPORT_NEW_VERSION"
```

**Upload**: Import as v1
**Update**: Import as v2, v3, v4... (never skip)

---

## Error Handling Differences

### Initial Upload Error
```python
try:
    new_rule = ComplianceRule(**rule_data)
    await new_rule.insert()
except ValidationError as e:
    # Decrement imported counter
    statistics['imported'] -= 1
    statistics['errors'] += 1
    return {'action': 'error', 'error': str(e)}
```

**Result**: Rule not created, import fails

---

### Update Error
```python
try:
    # Mark old version as superseded
    await existing_rule.update({"$set": {"is_latest": False}})

    # Create new version
    new_rule = ComplianceRule(**new_data)
    await new_rule.insert()
except ValidationError as e:
    # ROLLBACK: Re-mark old version as latest
    await existing_rule.update({"$set": {"is_latest": True}})

    # Decrement updated counter
    statistics['updated'] -= 1
    statistics['errors'] += 1
    return {'action': 'error', 'error': str(e)}
```

**Result**: Old version remains active (is_latest=true), update fails

---

## Statistics Reporting

### Initial Upload
```json
{
  "imported": 2013,
  "updated": 0,
  "skipped": 0,
  "errors": 0
}
```

### Update (Mixed Results)
```json
{
  "imported": 0,
  "updated": 150,
  "skipped": 1860,
  "errors": 3,
  "field_changes": {
    "metadata": 45,
    "severity": 30,
    "frameworks": 75
  }
}
```

**Interpretation**:
- 0 new rules
- 150 rules had content changes (new versions created)
- 1860 rules unchanged (skipped)
- 3 rules failed validation (updates rejected)

---

## Common Misconceptions

### ❌ Myth: "Updates skip some validation phases"
**Reality**: All 8 phases run identically for uploads and updates

### ❌ Myth: "Updates modify existing MongoDB documents"
**Reality**: Updates create NEW versions (append-only, immutable)

### ❌ Myth: "Hash comparison replaces validation"
**Reality**: Hash comparison is for deduplication only. Full validation still runs.

### ❌ Myth: "If validation fails on update, partial data is saved"
**Reality**: Updates are atomic - validation failure means NO changes to MongoDB

---

## Performance Implications

### Initial Upload
- **No DB Queries**: No existing rule lookup needed
- **No Hash Comparison**: Skip content hash calculation
- **Faster**: Deduplication phase is simpler

### Update
- **DB Query Per Rule**: Must check for existing rule
- **Hash Calculation**: Two hashes calculated (existing + new)
- **Change Detection**: Field-by-field comparison
- **Slower**: Deduplication phase is more complex

**Optimization**: Use `skip_all` strategy if you know bundles are always new

---

## Troubleshooting

### Issue: "Rules show as 'skipped' but should be updated"

**Diagnosis**:
```python
# Check if content actually changed
existing_hash = calculate_content_hash(existing_rule)
new_hash = calculate_content_hash(new_rule_data)

if existing_hash == new_hash:
    print("Content is IDENTICAL - skip is correct")
else:
    print("Content CHANGED but hash matched - check excluded fields")
```

**Possible Causes**:
1. Only metadata changed (excluded from hash)
2. Timestamp-only changes
3. Whitespace differences in JSON

---

### Issue: "Update creates new version but validation fails"

**Diagnosis**:
```
Upload Result: "1 updated, 0 errors"
MongoDB: Still shows old version as is_latest=true

Error Log: "platform_implementations.rhel8.versions: Field required"
```

**Explanation**:
- Deduplication marked as "updated" (content changed)
- MongoDB validation failed (missing required field)
- Update was rolled back
- Counter was decremented (should show "0 updated, 1 error")

**Fix**: Ensure all required fields are present in updated bundle

---

## References

- [COMPLIANCE_BUNDLE_VALIDATION.md](./COMPLIANCE_BUNDLE_VALIDATION.md) - Full validation details
- [backend/app/services/compliance_rules_deduplication_service.py](../backend/app/services/compliance_rules_deduplication_service.py) - Deduplication logic
- [backend/app/services/compliance_rules_upload_service.py](../backend/app/services/compliance_rules_upload_service.py) - Upload orchestration
- [backend/app/services/compliance_rules_versioning_service.py](../backend/app/services/compliance_rules_versioning_service.py) - Immutable versioning
