# OpenWatch Compliance Rules - Data Structure Specification

**Version:** 1.2.0
**Date:** October 23, 2025
**Status:** Definitive Specification

## Purpose

This document defines the **official data structures** for OpenWatch compliance rules and bundles. All tools (converters, importers, exporters) MUST conform to these structures.

---

## 1. Bundle Manifest Structure

### Location
- **File:** `manifest.json` (at root of tar.gz bundle)
- **Format:** JSON

### Required Fields

```json
{
  "name": "string",           // Bundle name (REQUIRED)
  "version": "string",        // Semantic version (REQUIRED)
  "rules_count": integer,     // Number of rules in bundle (REQUIRED)
  "created_at": "ISO8601"     // ISO 8601 datetime with timezone (REQUIRED)
}
```

### Optional Fields

```json
{
  "description": "string",    // Human-readable description
  "source": "string",         // Source system (e.g., "complianceascode_prerendered")
  "product": "string",        // Target product (e.g., "rhel8", "ubuntu2204")
  "format": "string",         // Rule file format: "bson" or "json"
  "signature": {              // Cryptographic signature for bundle verification
    "algorithm": "string",    // Hash algorithm: "SHA256", "SHA384", or "SHA512"
    "signature": "string",    // RSA-PSS signature in hexadecimal format
    "signer": "string",       // Signer name/identifier
    "public_key_id": "string", // SHA-256 hash of public key (first 16 chars)
    "signed_at": "ISO8601"    // ISO 8601 datetime when bundle was signed
  },
  "rules": [                  // Array of rule metadata
    {
      "rule_id": "string",
      "filename": "string",
      "hash": "string"        // Format: "sha256:hexdigest"
    }
  ]
}
```

### Validation Rules

1. **name**: Must be non-empty string, max 255 characters
2. **version**: Must follow semantic versioning (e.g., "1.0.0", "2.1.3-beta")
3. **rules_count**: Must be positive integer, must match actual file count
4. **created_at**: Must be valid ISO 8601 format with timezone
   - Accepted formats:
     - `"2025-10-22T19:55:05.419113+00:00"` (preferred)
     - `"2025-10-22T19:55:05Z"` (will be converted)

### Example Manifest (Without Signature - Development Mode)

```json
{
  "name": "complianceascode-rhel8",
  "version": "1.0.0",
  "rules_count": 2013,
  "created_at": "2025-10-22T19:55:05.419113+00:00",
  "description": "RHEL 8 compliance rules from ComplianceAsCode",
  "source": "complianceascode_prerendered",
  "product": "rhel8",
  "format": "bson"
}
```

### Example Manifest (With Signature - Production Mode)

```json
{
  "name": "complianceascode-rhel8",
  "version": "1.0.0",
  "rules_count": 2013,
  "created_at": "2025-10-22T19:55:05.419113+00:00",
  "description": "RHEL 8 compliance rules from ComplianceAsCode",
  "source": "complianceascode_prerendered",
  "product": "rhel8",
  "format": "bson",
  "signature": {
    "algorithm": "SHA512",
    "signature": "a1b2c3d4e5f6789...",
    "signer": "ComplianceAsCode Project",
    "public_key_id": "7f8e9d6c5b4a3210",
    "signed_at": "2025-10-22T19:55:05.419113+00:00"
  }
}
```

### Signature Verification (Security)

**Purpose**: Cryptographic signatures ensure bundle authenticity and integrity

**Production Requirements**:
- Bundles MUST include valid signature in manifest
- Signature MUST be from trusted publisher (public key in `/app/security/compliance_bundle_keys/`)
- Unsigned bundles will be REJECTED

**Development Requirements**:
- Signature verification can be disabled via `REQUIRE_BUNDLE_SIGNATURE=false` environment variable
- Unsigned bundles are ALLOWED in development mode
- Warning messages will be logged for unsigned bundles

**Signature Algorithm**:
- RSA-PSS with MGF1 padding
- Minimum key size: 2048 bits (4096 bits recommended)
- Supported hash algorithms: SHA256, SHA384, SHA512 (SHA512 recommended)
- Signature format: Hexadecimal encoding
- Signing data: Raw bundle tar.gz bytes

**Trust Management**:
- Trusted public keys stored in PEM format
- Key ID calculated as SHA-256 hash of public key (first 16 characters)
- Keys loaded at service startup
- Dynamic key management via admin API (add/remove trusted signers)

**Example Signature Generation**:
```python
# Using OpenWatch signature service
from compliance_rules_signature_service import ComplianceRulesSignatureService

service = ComplianceRulesSignatureService()
result = await service.sign_bundle(
    bundle_data=bundle_bytes,
    private_key_path=Path("/path/to/private_key.pem"),
    signer_name="ComplianceAsCode Project",
    algorithm="SHA512"
)

# Add signature to manifest before creating bundle
manifest['signature'] = result['signature']
```

---

## 2. Compliance Rule Structure (MongoDB Document)

### Model Definition
- **Collection:** `compliance_rules`
- **Model Class:** `ComplianceRule` (Document)
- **File:** `backend/app/models/mongo_models.py:285`

### Core Required Fields

```python
{
  "rule_id": str,              // Unique OpenWatch rule identifier (REQUIRED, INDEXED)
  "metadata": dict,            // Rich metadata (REQUIRED)
  "severity": str,             // Severity level (REQUIRED)
  "scanner_type": str,         // Scanner type for Phase 1 (REQUIRED, INDEXED)
  "version": str,              // Rule version (REQUIRED, INDEXED)
  "is_latest": bool,           // Is this the latest version? (REQUIRED, INDEXED)
  "frameworks": dict,          // Framework mappings (REQUIRED)
  "platforms": list[str],      // Supported platforms (REQUIRED)
}
```

### Metadata Field Structure

```python
{
  "metadata": {
    "name": str,               // Human-readable rule name
    "description": str,        // Detailed description
    "rationale": str,          // Why this rule matters
    "source": {
      "type": str,             // "complianceascode", "custom", etc.
      "upstream_id": str,      // Original rule ID from source
      "imported_at": datetime, // When imported
      "version": str           // Source version
    }
  }
}
```

### Framework Mappings Structure

```python
{
  "frameworks": {
    "nist_800_53": {
      "controls": ["AC-2", "IA-4"],
      "applicable": true
    },
    "cis": {
      "controls": ["4.5.1.4"],
      "applicable": true
    },
    "pci_dss": {
      "controls": ["Req-8.1.4"],
      "applicable": true
    },
    "disa_stig": {
      "controls": ["RHEL-08-020260"],
      "applicable": true
    }
  }
}
```

### Platform Implementation Structure

```python
{
  "platform_implementations": {
    "rhel8": {
      "versions": ["8.0", "8.1", "8.2", ...],
      "check_method": "oscap",          // or "manual", "script", etc.
      "check_command": "oscap xccdf eval ...",
      "config_files": ["/etc/default/useradd"],
      "remediation_available": true,
      "remediation_script": "#!/bin/bash\n..."
    }
  }
}
```

### Complete Rule Example

```json
{
  "rule_id": "account_disable_post_pw_expiration",
  "scap_rule_id": "xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration",
  "parent_rule_id": null,

  "metadata": {
    "name": "Set Account Expiration Following Inactivity",
    "description": "Configure the INACTIVE setting in /etc/default/useradd to disable accounts after password expiration.",
    "rationale": "Inactive accounts pose a security risk by potentially providing undetected access to attackers.",
    "source": {
      "type": "complianceascode",
      "upstream_id": "account_disable_post_pw_expiration",
      "imported_at": "2025-10-22T19:55:05+00:00",
      "version": "0.1.73",
      "build_type": "prerendered"
    }
  },

  "abstract": false,
  "inherits_from": null,
  "derived_rules": [],

  "severity": "medium",
  "category": "authentication",
  "tags": ["scap", "ssg", "authentication", "password_policy"],

  "scanner_type": "oscap",
  "version": "1.0.0",
  "is_latest": true,

  "frameworks": {
    "nist_800_53": {
      "controls": ["IA-4(e)", "AC-2(3)", "CM-6(a)"],
      "applicable": true
    },
    "cis": {
      "controls": ["4.5.1.4"],
      "applicable": true
    },
    "pci_dss": {
      "controls": ["Req-8.1.4"],
      "applicable": true
    },
    "disa_stig": {
      "controls": ["RHEL-08-020260"],
      "applicable": true
    }
  },

  "platforms": ["rhel8", "rhel9", "centos8"],

  "platform_implementations": {
    "rhel8": {
      "versions": ["8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8"],
      "check_method": "oscap",
      "check_command": "grep INACTIVE /etc/default/useradd",
      "config_files": ["/etc/default/useradd"],
      "remediation_available": true,
      "remediation_script": "#!/bin/bash\nuseradd -D -f 35\n"
    }
  },

  "variables": [
    {
      "name": "var_account_disable_post_pw_expiration",
      "type": "number",
      "description": "Days of inactivity before account is disabled",
      "default_value": "35",
      "constraints": {
        "min_value": 0,
        "max_value": 365
      }
    }
  ],

  "check_content": {
    "type": "automated",
    "oval_id": "oval:ssg-account_disable_post_pw_expiration:def:1",
    "ocil": "grep INACTIVE /etc/default/useradd should return INACTIVE=35 or lower",
    "ocil_clause": "the value of INACTIVE is greater than 35 or is -1"
  },

  "identifiers": {
    "cce": "CCE-80954-1"
  },

  "created_at": "2025-10-22T19:55:05+00:00",
  "updated_at": "2025-10-22T19:55:05+00:00",
  "effective_from": "2025-10-22T19:55:05+00:00",
  "effective_until": null
}
```

---

## 3. Bundle Directory Structure

### Standard Layout

```
openwatch-{product}-bundle_v{version}.tar.gz
├── manifest.json                    # Bundle metadata (REQUIRED)
└── rules/                           # Rules directory (REQUIRED)
    ├── ow-rule_id_1.bson           # Individual rule files
    ├── ow-rule_id_2.bson
    └── ...
```

### File Naming Convention

- **Pattern:** `ow-{rule_id}.{format}`
- **Examples:**
  - `ow-account_disable_post_pw_expiration.bson`
  - `ow-accounts_password_minlen_login_defs.json`
- **Rule ID Format:**
  - Lowercase alphanumeric and underscores only
  - No spaces, hyphens converted to underscores
  - Max length: 255 characters

---

## 4. MongoDB Pydantic Validators

### Critical Validation Rules

The MongoDB `ComplianceRule` model includes Pydantic validators that **MUST** be satisfied:

**File:** `backend/app/models/mongo_models.py:637-649`

#### Validator 1: rule_id Prefix

```python
@validator('rule_id')
def validate_rule_id(cls, v):
    if not v or len(v) < 3:
        raise ValueError('Rule ID must be at least 3 characters long')
    if not v.startswith('ow-'):
        raise ValueError('Rule ID must start with "ow-"')
    return v
```

**Requirements:**
- **MUST** start with `"ow-"` prefix
- **MUST** be at least 3 characters long
- Examples:
  - ✅ `"ow-account_disable_post_pw_expiration"`
  - ✅ `"ow-sysctl_kernel_randomize_va_space"`
  - ❌ `"account_disable_post_pw_expiration"` (missing prefix)
  - ❌ `"ow"` (too short)

#### Validator 2: metadata.name Required

```python
@validator('metadata')
def validate_metadata(cls, v):
    if not v.get('name'):
        raise ValueError('Metadata must contain a name')
    return v
```

**Requirements:**
- `metadata` dictionary **MUST** contain a `name` field
- `name` **MUST** be a non-empty string
- Example:
  ```json
  {
    "metadata": {
      "name": "Set Account Expiration Following Inactivity",  // REQUIRED
      "components": ["useradd"],
      "warnings": [],
      "conflicts": [],
      "requires": []
    }
  }
  ```

### Validation Failure Impact

**CRITICAL:** If a rule fails Pydantic validation:
1. MongoDB insert will fail with `ValidationError`
2. The rule will **NOT** be saved to the database
3. Error will be logged in backend logs
4. Upload statistics will show the rule in error count (not imported count)

### Converter Requirements

All converters **MUST**:
1. Add `"ow-"` prefix to `rule_id` field
2. Include `name` in `metadata` dictionary
3. Test generated rules against MongoDB model before bundling

---

## 5. Validation Requirements

### Bundle Validation

Upload service validates bundles in this order:

1. **Security Validation**
   - File size limits
   - Path traversal prevention
   - Malicious content scanning

2. **Structure Validation**
   - manifest.json exists at root
   - manifest.json is valid JSON
   - All required manifest fields present
   - `rules/` directory exists
   - Rule count matches manifest

3. **Content Validation**
   - Each rule file is valid BSON/JSON
   - Rule IDs are unique
   - Required rule fields present
   - Field types match schema

### Rule Validation

Each rule must pass:

1. **Schema Validation** (Pydantic model)
2. **Business Logic Validation**
   - Valid scanner_type
   - Valid severity level
   - Valid platform identifiers
3. **Integrity Validation**
   - Hash matches (if provided in manifest)
   - No duplicate rule_ids in bundle

---

## 5. Import Process

### Upload Service Flow

```
1. Security Validation (compliance_rules_security_service.py)
   ↓
2. Archive Extraction (to temp directory)
   ↓
3. Manifest Parsing (compliance_rules_bson_parser.py)
   ↓
4. Rule Parsing (all BSON/JSON files)
   ↓
5. Deduplication (based on strategy)
   ↓
6. MongoDB Insert (bulk operation)
   ↓
7. Cleanup (remove temp files)
```

### Deduplication Strategies

1. **skip_all** - Skip if rule_id exists
2. **skip_unchanged_update_changed** - Compare content hash, update if different
3. **version_increment** - Create new version, preserve old
4. **replace_all** - Delete existing, insert new

---

## 6. Framework Mappings

### Supported Frameworks

| Framework | Key | Example Controls |
|-----------|-----|------------------|
| NIST 800-53 | `nist_800_53` | AC-2, IA-4, CM-6 |
| CIS Benchmarks | `cis` | 4.5.1.4, 5.2.1 |
| PCI-DSS | `pci_dss` | Req-8.1.4 |
| DISA STIG | `disa_stig` | RHEL-08-020260 |
| ISO 27001 | `iso_27001` | A.9.2.1 |
| HIPAA | `hipaa` | 164.308(a)(4) |

### Framework Mapping Format

```json
{
  "framework_key": {
    "controls": ["control_id_1", "control_id_2"],
    "applicable": true
  }
}
```

---

## 7. Versioning Strategy

### Bundle Versioning

- **Format:** Semantic Versioning 2.0.0
- **Pattern:** `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`
- **Examples:**
  - `1.0.0` - Initial release
  - `1.1.0` - New rules added
  - `1.1.1` - Bug fixes
  - `2.0.0` - Breaking changes
  - `1.0.0-beta.1` - Pre-release
  - `1.0.0+rhel8` - Build metadata

### Rule Versioning

- Each rule has its own version
- `is_latest` flag marks current version
- Old versions preserved for audit trail
- Version increments on content changes

---

## 8. Migration Guide

### Updating Existing Converters

If you have an existing converter that doesn't match this spec:

1. **Update Manifest Generation:**
   ```python
   manifest = {
       "name": f"your-source-{product}",      # REQUIRED
       "version": "1.0.0",                     # REQUIRED
       "rules_count": len(rules),              # REQUIRED (not rule_count)
       "created_at": datetime.now(timezone.utc).isoformat(),  # REQUIRED
       # Optional fields...
   }
   ```

2. **Update Rule Structure:**
   - Ensure all required fields present
   - Follow framework mapping format
   - Include proper metadata structure

3. **Test Bundle:**
   ```bash
   # Upload via API
   curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
     -H "Authorization: Bearer $TOKEN" \
     -F "file=@bundle.tar.gz"
   ```

---

## 9. Reference Implementation

### Official Converter

**File:** `backend/app/cli/scap_json_to_openwatch_converter.py`

This converter is the reference implementation for creating compliant bundles from ComplianceAsCode builds.

### Validation Service

**File:** `backend/app/services/compliance_rules_bson_parser.py`

This service defines the validation rules that all bundles must pass.

---

## 10. Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-10-22 | Initial definitive specification |
| 1.1.0 | 2025-10-23 | Added Section 4: MongoDB Pydantic Validators documenting required validators |

---

## Notes

- **DO NOT** modify MongoDB schema to fit converter output
- **DO** modify converters to match this specification
- **ALWAYS** validate against this spec before deployment
- This spec is the single source of truth for data structures
