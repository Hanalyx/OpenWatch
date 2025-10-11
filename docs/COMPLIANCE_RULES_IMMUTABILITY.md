# Compliance Rules Immutability Architecture

## Overview

OpenWatch implements **full immutability** for compliance rules to meet audit and regulatory requirements for:
- High-security government/defense systems (FISMA, FedRAMP)
- Financial services (SOX, PCI DSS)
- Healthcare (HIPAA)
- Multi-framework version support

## Design Principles

### 1. Append-Only Rule Storage
- **Never update or delete** existing rule documents
- **Always insert** new versions
- Each version is uniquely identifiable and independently queryable

### 2. Content-Addressed Versioning
- Version numbers are monotonically increasing integers
- Each version has a content hash (SHA-256) for integrity verification
- Versions are linked by `rule_id` (semantic identifier)

### 3. Temporal Queries
- Query "latest" version (most common use case)
- Query version "as-of" specific timestamp (audit/compliance)
- Query specific version number (reproducibility)
- Query all versions for a rule (change history)

## Schema Design

### Primary Collection: `compliance_rules`

```javascript
{
  // MongoDB ObjectId - unique per version
  _id: ObjectId("..."),

  // Semantic Rule Identifier (stays constant across versions)
  rule_id: "ow-accounts_password_pam_ucredit",

  // Version Information
  version: 1,                                    // Monotonically increasing
  version_hash: "sha256:a3f5d2e8...",           // Content hash for integrity
  is_latest: true,                               // Denormalized for query performance
  supersedes_version: null,                      // Previous version number (null for v1)

  // Temporal Information
  effective_from: "2025-10-11T01:00:00Z",        // When this version became active
  effective_until: null,                         // null = currently active, otherwise superseded
  created_at: "2025-10-11T01:00:00Z",
  created_by: "admin",

  // Source Tracking
  source_bundle: "openwatch-rules-bundle_v0.0.1.tar.gz",
  source_bundle_hash: "sha512:97243803...",
  import_id: "uuid-of-import-operation",

  // Rule Content (same structure as current)
  scap_rule_id: "xccdf_org.ssgproject.content_rule_...",
  metadata: {
    name: "Ensure PAM Enforces Password Requirements...",
    description: "The pam_pwquality module's <tt>ucredit</tt>...",
    rationale: "Use of a complex password helps...",
    source: { /* ... */ }
  },
  severity: "medium",
  category: "authentication",
  tags: ["scap", "converted", "nist"],
  frameworks: {
    nist: { "800-53r5": ["AC-2", "IA-5"] },
    cis: { "rhel8-v2.0.0": ["5.3.1"] },
    stig: {},
    iso27001: {},
    pci_dss: {},
    hipaa: {}
  },
  platform_implementations: {
    rhel8: {
      versions: ["8.0", "8.1", "8.2", "8.3"],
      check_command: "grep ucredit /etc/security/pwquality.conf",
      enable_command: "echo 'ucredit = -1' >> /etc/security/pwquality.conf",
      config_files: ["/etc/security/pwquality.conf"]
    }
  },
  dependencies: {
    requires: [],
    conflicts: [],
    related: []
  },

  // Change Metadata (what changed from previous version)
  change_summary: {
    change_type: "created" | "updated" | "deprecated",
    changed_fields: ["severity", "frameworks.nist"],
    change_reason: "Updated per NIST 800-53r6 guidance",
    breaking_changes: false
  }
}
```

### Indexes for Performance

```javascript
// Primary query patterns
db.compliance_rules.createIndex({ rule_id: 1, version: -1 })           // Get latest version
db.compliance_rules.createIndex({ rule_id: 1, is_latest: 1 })          // Get current rules
db.compliance_rules.createIndex({ is_latest: 1, severity: 1 })         // Filter current by severity
db.compliance_rules.createIndex({ rule_id: 1, effective_from: 1 })     // Temporal queries
db.compliance_rules.createIndex({ version_hash: 1 }, { unique: true }) // Content integrity
db.compliance_rules.createIndex({ source_bundle: 1 })                  // Track bundle imports
```

## Query Patterns

### 1. Get Latest Version of All Rules

```javascript
// Fast query using denormalized is_latest flag
db.compliance_rules.find({ is_latest: true })

// Alternative: Aggregation (slower but always accurate)
db.compliance_rules.aggregate([
  { $sort: { rule_id: 1, version: -1 } },
  { $group: {
      _id: "$rule_id",
      latest: { $first: "$$ROOT" }
    }
  },
  { $replaceRoot: { newRoot: "$latest" } }
])
```

### 2. Get Specific Rule (Latest Version)

```javascript
db.compliance_rules.findOne({
  rule_id: "ow-accounts_password_pam_ucredit",
  is_latest: true
})
```

### 3. Time-Travel Query ("As-Of" Date)

```javascript
// "What were the compliance rules on January 1, 2025?"
db.compliance_rules.aggregate([
  {
    $match: {
      effective_from: { $lte: new Date("2025-01-01T00:00:00Z") },
      $or: [
        { effective_until: null },
        { effective_until: { $gt: new Date("2025-01-01T00:00:00Z") } }
      ]
    }
  },
  { $sort: { rule_id: 1, version: -1 } },
  { $group: {
      _id: "$rule_id",
      rule_at_date: { $first: "$$ROOT" }
    }
  }
])
```

### 4. Get Complete Change History

```javascript
// All versions of a specific rule
db.compliance_rules.find({
  rule_id: "ow-accounts_password_pam_ucredit"
}).sort({ version: 1 })
```

### 5. Track Bundle Imports

```javascript
// All rules from a specific bundle
db.compliance_rules.find({
  source_bundle: "openwatch-rules-bundle_v0.0.1.tar.gz",
  is_latest: true
})
```

## Upload Process (Immutable)

### Current Behavior (Mutable)
```javascript
if (ruleExists) {
  await updateRule(newData)  // ❌ Overwrites old data
}
```

### New Behavior (Immutable)
```javascript
if (ruleExists) {
  const latestVersion = await getLatestVersion(rule_id)

  // Detect changes
  const changes = detectChanges(latestVersion, newData)

  if (hasChanges(changes)) {
    // Mark old version as superseded
    await db.compliance_rules.updateOne(
      { _id: latestVersion._id },
      {
        $set: {
          is_latest: false,
          effective_until: new Date(),
          superseded_by: latestVersion.version + 1
        }
      }
    )

    // Insert new version (append-only)
    await db.compliance_rules.insertOne({
      ...newData,
      rule_id: rule_id,
      version: latestVersion.version + 1,
      version_hash: calculateHash(newData),
      is_latest: true,
      supersedes_version: latestVersion.version,
      effective_from: new Date(),
      effective_until: null,
      change_summary: {
        change_type: "updated",
        changed_fields: Object.keys(changes),
        change_reason: "Imported from bundle",
        breaking_changes: detectBreakingChanges(changes)
      }
    })
  } else {
    // No changes - skip (idempotent)
  }
} else {
  // New rule - version 1
  await db.compliance_rules.insertOne({
    ...newData,
    version: 1,
    version_hash: calculateHash(newData),
    is_latest: true,
    supersedes_version: null,
    effective_from: new Date(),
    effective_until: null,
    change_summary: {
      change_type: "created",
      changed_fields: [],
      change_reason: "Initial import"
    }
  })
}
```

## Scan Results Integration

### Link Scans to Rule Versions

```javascript
// When performing a scan
{
  scan_id: "scan-uuid",
  host_id: "host123",
  started_at: "2025-10-11T02:00:00Z",
  rules_snapshot: [
    {
      rule_id: "ow-accounts_password_pam_ucredit",
      version: 3,                          // Pin to specific version
      version_hash: "sha256:a3f5d2e8..."  // Integrity check
    }
    // ... all rules used in this scan
  ],
  results: [
    {
      rule_id: "ow-accounts_password_pam_ucredit",
      rule_version: 3,
      status: "fail",
      finding: "Password complexity not enforced"
    }
  ]
}
```

### Benefits

1. **Reproducible Scans** - Re-run scan with exact same rules
2. **Audit Trail** - Prove which rule version was used
3. **Change Impact Analysis** - "This rule changed at version 4, let's re-scan"

## Framework Version Support

### Multiple Active Versions

```javascript
// Support NIST 800-53r5 and r6 simultaneously
db.compliance_rules.find({
  is_latest: true,
  "frameworks.nist.800-53r5": { $exists: true }
})

db.compliance_rules.find({
  is_latest: true,
  "frameworks.nist.800-53r6": { $exists: true }
})

// Gradual migration
{
  rule_id: "ow-access-control-policy",
  version: 5,
  frameworks: {
    nist: {
      "800-53r5": ["AC-1"],      // Legacy support
      "800-53r6": ["AC-01"]      // New version
    }
  }
}
```

## Retention & Archival

### Retention Policy

```javascript
// Keep all versions for compliance
// Archive old versions to cold storage after N years
{
  rule_id: "ow-deprecated-rule",
  version: 1,
  archived: true,
  archived_at: "2030-01-01T00:00:00Z",
  archive_location: "s3://openwatch-archives/rules/2025/..."
}
```

### Delete Policy

**NEVER DELETE** - Only mark as archived or deprecated

```javascript
// Deprecate (don't delete)
{
  rule_id: "ow-legacy-ssl-check",
  version: 10,
  is_latest: true,
  deprecated: true,
  deprecation_reason: "Superseded by TLS 1.3 requirement",
  replacement_rule_id: "ow-tls13-enforcement"
}
```

## Audit & Compliance Queries

### 1. Rule Change Report

```javascript
// "What rules changed in the last 30 days?"
db.compliance_rules.find({
  "change_summary.change_type": "updated",
  effective_from: {
    $gte: new Date(Date.now() - 30*24*60*60*1000)
  }
})
```

### 2. Breaking Changes Report

```javascript
// "Which rule updates broke existing scans?"
db.compliance_rules.find({
  "change_summary.breaking_changes": true,
  effective_from: { $gte: new Date("2025-01-01") }
})
```

### 3. Compliance Baseline Report

```javascript
// "Show me NIST 800-53r5 baseline as-of Dec 31, 2024"
db.compliance_rules.aggregate([
  {
    $match: {
      "frameworks.nist.800-53r5": { $exists: true },
      effective_from: { $lte: new Date("2024-12-31T23:59:59Z") },
      $or: [
        { effective_until: null },
        { effective_until: { $gt: new Date("2024-12-31T23:59:59Z") } }
      ]
    }
  }
])
```

## Migration Plan

### Phase 1: Schema Update
1. Add version fields to ComplianceRule model
2. Create indexes
3. Migrate existing rules to version 1

### Phase 2: Upload Service
1. Update upload service to insert new versions
2. Implement change detection
3. Update is_latest flags

### Phase 3: Query Service
1. Create RulesVersionService
2. Implement temporal queries
3. Update API endpoints

### Phase 4: Frontend
1. Display version information
2. Show change history
3. Add time-travel UI

### Phase 5: Integration
1. Update scan service to pin rule versions
2. Update reporting to show historical baselines
3. Add audit log queries

## Benefits Summary

✅ **Audit Trail** - Complete history of all rule changes
✅ **Reproducibility** - Re-run scans with exact same rules
✅ **Compliance** - Meet FISMA/FedRAMP/HIPAA/SOX requirements
✅ **Multi-Framework** - Support multiple framework versions
✅ **Time-Travel** - Query rules as they existed at any point
✅ **Change Analysis** - Track impact of rule updates
✅ **Data Integrity** - Content hashing prevents tampering
✅ **No Data Loss** - Nothing is ever deleted

## Performance Considerations

- **Storage:** ~2-5x growth (acceptable for compliance use case)
- **Query Speed:** Denormalized `is_latest` flag ensures fast queries
- **Index Overhead:** 6 indexes, optimized for common patterns
- **Archive Strategy:** Move old versions to cold storage after 7 years

---

**Last Updated:** 2025-10-11
**Status:** Design Complete - Ready for Implementation
