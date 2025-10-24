# Compliance Bundle Validation - Complete Reference

**Version:** 1.0.0
**Date:** October 23, 2025
**Status:** Comprehensive Documentation

## Overview

OpenWatch implements an 8-phase validation pipeline for compliance rule bundles to ensure security, integrity, and data quality. This document explains what each validation phase does, why it's necessary, and how it works.

---

## Validation Pipeline Overview

```
Upload Bundle (.tar.gz)
    ↓
[1] File Extension Validation
    ↓
[2] File Size Validation
    ↓
[3] Security Validation (Phase 1) ← CRITICAL SECURITY GATE
    ↓
[4] Archive Extraction
    ↓
[5] Manifest Validation (Phase 2)
    ↓
[6] Rule Parsing (Phase 3)
    ↓
[7] Deduplication (Phase 4)
    ↓
[8] MongoDB Validation (Phase 4 continued)
    ↓
Import Complete ✓
```

**Total Validation Checks**: 20+ individual security and data quality checks across 8 phases

---

## Phase 1: File Extension Validation

**Location**: [backend/app/utils/file_security.py](../backend/app/utils/file_security.py)

### What
Validates that the uploaded file has an allowed archive extension.

### Why
- **Early Rejection**: Reject invalid files immediately without processing
- **Resource Efficiency**: Don't waste resources on obviously wrong file types
- **User Feedback**: Give clear error message about expected format

### How
```python
def validate_file_extension(filename: str, allowed_extensions: list[str]) -> bool:
    # Allowed: ['.tar.gz', '.tgz']
    filename_lower = filename.lower()

    # Check for multi-part extensions (.tar.gz) first
    for ext in sorted(allowed_extensions, key=len, reverse=True):
        if filename_lower.endswith(ext):
            return True

    return False
```

**Checks**:
- ✅ `bundle.tar.gz` → PASS
- ✅ `bundle.tgz` → PASS
- ❌ `bundle.zip` → FAIL
- ❌ `bundle.tar` → FAIL
- ❌ `bundle.json` → FAIL

**Error Message**: `"Invalid file type. Only .tar.gz archives are allowed"`

---

## Phase 2: File Size Validation

**Location**: [backend/app/services/compliance_rules_security_service.py:99](../backend/app/services/compliance_rules_security_service.py#L99)

### What
Ensures the uploaded file is not empty and doesn't exceed maximum size limits.

### Why
- **Empty File Protection**: Empty files indicate upload errors or malicious activity
- **Resource Protection**: Prevent DoS attacks via extremely large files
- **Storage Management**: Ensure bundles fit within allocated storage

### How
```python
MAX_ARCHIVE_SIZE = 100 * 1024 * 1024  # 100MB

def _check_archive_size(self, archive_data: bytes) -> SecurityCheckResult:
    size = len(archive_data)

    if size == 0:
        return FAIL("Archive is empty")

    if size > MAX_ARCHIVE_SIZE:
        return FAIL(f"Archive too large: {size/1024/1024:.2f}MB (max: 100MB)")

    return PASS(f"Archive size valid: {size/1024/1024:.2f}MB")
```

**Limits**:
- Minimum: 1 byte (must not be empty)
- Maximum: 100 MB (DoS protection)

**Error Messages**:
- `"Archive is empty (0 bytes)"`
- `"Archive too large: 150.5MB (max: 100MB)"`

---

## Phase 3: Security Validation (CRITICAL SECURITY GATE)

**Location**: [backend/app/services/compliance_rules_security_service.py:82-147](../backend/app/services/compliance_rules_security_service.py#L82-L147)

This is the **most critical phase** with 10+ security checks to prevent malicious uploads.

### 3.1 SHA-512 Hash Calculation

#### What
Calculates cryptographic hash of the entire bundle archive.

#### Why
- **Provenance Tracking**: Create immutable fingerprint for audit logs
- **Integrity Reference**: Can detect if bundle is re-uploaded or modified
- **Forensics**: Useful for security investigations

#### How
```python
archive_hash = hashlib.sha512(archive_data).hexdigest()
# Result: "a1b2c3d4e5f6789..." (128 hex characters)
```

**Note**: This hash is **NOT verified against anything** in Phase 3. It's recorded for provenance. Signature verification (if enabled) happens in Phase 5 (Manifest Validation).

**Always Passes**: This is informational only, never fails.

---

### 3.2 Path Traversal Prevention

#### What
Prevents malicious files from escaping the extraction directory.

#### Why
- **Critical Security**: Attackers could overwrite `/etc/passwd`, `~/.ssh/authorized_keys`, etc.
- **OWASP Top 10**: Path traversal is a critical web vulnerability
- **System Integrity**: Protects OpenWatch host system

#### How
Scans every file in the tar archive BEFORE extraction:

```python
def _is_path_traversal(self, path: str) -> bool:
    return (
        path.startswith('/')      # Absolute path: /etc/passwd
     or path.startswith('\\')     # Windows absolute: C:\Windows
     or '..' in path              # Parent traversal: ../../etc/shadow
     or path.startswith('~')      # Home directory: ~/.ssh/id_rsa
    )
```

**Blocked Paths**:
- ❌ `/etc/passwd`
- ❌ `../../../etc/shadow`
- ❌ `~/.ssh/id_rsa`
- ❌ `..\..\..\Windows\System32`
- ✅ `rules/ow-account_disable.bson` → ALLOWED
- ✅ `manifest.json` → ALLOWED

**Error**: `"Path traversal detected: ../../../etc/passwd"`

---

### 3.3 Forbidden Filename Detection

#### What
Blocks bundles containing security-sensitive files or executables.

#### Why
- **Credential Protection**: Prevent accidental/malicious credential leaks
- **Execution Prevention**: Block executable code from entering system
- **Data Exfiltration**: Prevent sensitive file uploads disguised as bundles

#### How
```python
FORBIDDEN_FILENAMES = [
    # Credentials & Secrets
    '.env', '.env.local', '.env.production',
    'credentials', 'secrets', 'private_key',

    # SSH Keys
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    'authorized_keys', 'known_hosts',

    # System Files
    'passwd', 'shadow', 'sudoers',

    # Shell History
    '.bash_history', '.zsh_history',

    # Cloud Credentials
    '.aws', '.docker', '.kube'
]

FORBIDDEN_EXTENSIONS = [
    # Scripts
    '.sh', '.bash', '.zsh', '.py', '.pyc',

    # Executables
    '.exe', '.dll', '.so', '.dylib',

    # Windows
    '.bat', '.cmd', '.ps1',

    # Java
    '.jar', '.war', '.class'
]
```

**Smart Filtering**:
- ✅ `ow-accounts_password_pam.bson` → ALLOWED (substring "password" is OK in rule names)
- ❌ `passwd` → BLOCKED (exact match)
- ❌ `.env` → BLOCKED
- ❌ `deploy.sh` → BLOCKED (executable script)

**Error**: `"Forbidden filename detected: .env"`

---

### 3.4 Archive Bomb Protection

#### What
Prevents "zip bomb" attacks where small archives expand to huge files.

#### Why
- **Disk Exhaustion**: 42KB zip can expand to 4.5PB (petabytes)
- **DoS Attack**: Crash server by filling disk
- **Resource Starvation**: Consume all available storage

#### How
Check COMPRESSED size in tar metadata BEFORE extraction:

```python
MAX_RULE_FILE_SIZE = 1 * 1024 * 1024  # 1MB per file

for member in tar.getmembers():
    if member.size > MAX_RULE_FILE_SIZE:
        return FAIL(f"File too large: {member.name} ({member.size:,} bytes)")
```

**Example Attack**:
```
Archive: evil.tar.gz (42 KB)
  └─ bomb.bson (4,500,000,000,000 bytes) ← BLOCKED BEFORE EXTRACTION
```

**Limits**:
- Maximum single file size: 1 MB
- Maximum total bundle size: 100 MB

**Error**: `"File too large: rules/huge.bson (5,000,000 bytes)"`

---

### 3.5 Symlink Protection

#### What
Blocks symbolic links and hard links in archives.

#### Why
- **Security Bypass**: Symlinks can point to `/etc/passwd`, `/root/.ssh/id_rsa`
- **Path Traversal**: Symlink to `../../../sensitive/data`
- **Privilege Escalation**: Link to setuid binaries

#### How
```python
for member in tar.getmembers():
    if member.issym() or member.islnk():
        return FAIL(f"Symlink detected: {member.name}")
```

**Blocked Examples**:
- ❌ `rules/passwd -> /etc/passwd` (symlink)
- ❌ `secrets -> ~/.ssh/` (symlink to directory)
- ❌ Hard link to `/root/.bash_history`

**Error**: `"Symlink detected (not allowed): rules/passwd"`

---

### 3.6 Null Byte Detection in JSON

#### What
Scans JSON files for null bytes (binary content).

#### Why
- **Binary Payload**: Attackers hide executables in JSON files
- **Parser Exploits**: Null bytes can crash or confuse parsers
- **Data Integrity**: JSON should be pure text

#### How
```python
if file_path.suffix == '.json':
    content = file_path.read_bytes()
    if b'\x00' in content:
        return FAIL(f"Binary content detected in JSON: {file_path.name}")
```

**Example Attack**:
```json
{
  "rule_id": "ow-test",
  "exploit": "\x00\x7fELF\x01\x01..."  ← Embedded binary (null byte \x00)
}
```

**Error**: `"Binary content detected in JSON file: rule.json"`

---

### 3.7 Safe Extraction

#### What
Uses Python 3.12+ secure extraction with additional protections.

#### Why
- **CVE-2007-4559**: Historic Python tarfile vulnerability
- **Defense in Depth**: Platform-specific security features
- **Future Proofing**: Benefit from Python security updates

#### How
```python
tar.extractall(temp_extract_dir, filter='data')
#                                 ^^^^^^^
#                                 Enables CVE-2007-4559 protections
```

**Python 3.12+ `filter='data'` protections**:
- Rejects absolute paths
- Rejects parent directory references
- Rejects device files
- Rejects symlinks escaping extraction directory

---

## Phase 4: Archive Extraction

**Location**: [backend/app/services/compliance_rules_security_service.py:183-248](../backend/app/services/compliance_rules_security_service.py#L183-L248)

### What
Extracts the validated tar.gz archive to a temporary directory.

### Why
- **Isolation**: Extract in temporary directory, not production
- **Cleanup**: Can delete on failure without affecting system
- **Inspection**: Can validate contents before MongoDB import

### How
```python
temp_extract_dir = tempfile.gettempdir() / f"extract_{timestamp}"
temp_extract_dir.mkdir(mode=0o700)  # Owner-only permissions

tar.extractall(temp_extract_dir, filter='data')
```

**Directory Structure After Extraction**:
```
/tmp/extract_1729728000.123/
├── manifest.json          ← Bundle metadata
└── rules/
    ├── ow-rule1.bson
    ├── ow-rule2.bson
    └── ow-rule3.bson
```

**Permissions**: `0o700` (rwx------) = owner-only access

---

## Phase 5: Manifest Validation

**Location**: [backend/app/services/compliance_rules_upload_service.py:145-154](../backend/app/services/compliance_rules_upload_service.py#L145-L154)

### What
Validates the bundle manifest file contains required metadata.

### Why
- **Bundle Identity**: Ensures bundle has name, version, metadata
- **Rule Count**: Verifies claimed rule count matches actual files
- **Traceability**: Tracks bundle source and creation date

### How

#### 5.1 Manifest Existence
```python
manifest_bson = extracted_path / "manifest.bson"
manifest_json = extracted_path / "manifest.json"

if not manifest_bson.exists() and not manifest_json.exists():
    return FAIL("Archive missing required manifest")
```

**Accepts**:
- ✅ `manifest.json` (preferred for human readability)
- ✅ `manifest.bson` (preferred for size efficiency)

---

#### 5.2 JSON Format Validation
```python
import json

with open(manifest_path, 'r') as f:
    manifest = json.load(f)  # Fails if invalid JSON
```

**Catches**:
- ❌ Syntax errors (missing commas, brackets)
- ❌ Invalid UTF-8 encoding
- ❌ Trailing commas
- ❌ Comments (not valid in JSON)

**Error**: `"Invalid JSON in manifest: Expecting ',' delimiter"`

---

#### 5.3 Required Fields Validation
```python
REQUIRED_FIELDS = ['name', 'version', 'rules_count', 'created_at']

for field in REQUIRED_FIELDS:
    if field not in manifest:
        return FAIL(f"Manifest missing required field: {field}")
```

**Required Manifest Fields**:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `name` | string | Bundle name | `"complianceascode-rhel8"` |
| `version` | string | Semantic version | `"1.0.3"` |
| `rules_count` | integer | Number of rules | `2013` |
| `created_at` | ISO8601 | Creation timestamp | `"2025-10-23T19:55:05Z"` |

**Error**: `"Manifest missing required field: version"`

---

#### 5.4 Rule Count Verification
```python
claimed_count = manifest['rules_count']
actual_files = len(list(extracted_path.glob("rules/*.bson")))

if claimed_count != actual_files:
    return FAIL(f"Rule count mismatch: manifest claims {claimed_count}, found {actual_files}")
```

**Why**: Detects incomplete bundles, corruption, or manifest errors

**Error**: `"Rule count mismatch: manifest claims 2013, found 2000"`

---

#### 5.5 Signature Verification (Optional)

**Location**: [backend/app/services/compliance_rules_upload_service.py:156-232](../backend/app/services/compliance_rules_upload_service.py#L156-L232)

If `REQUIRE_BUNDLE_SIGNATURE=true`:

```python
signature_data = manifest.get('signature')

if not signature_data:
    return FAIL("No signature provided (required in production)")

# Verify RSA-PSS signature
signature_check = await signature_service.verify_bundle_signature(
    bundle_data=archive_data,
    signature_data=signature_data,
    require_trusted_signature=True
)

if not signature_check.passed:
    return FAIL(signature_check.message)
```

**See**: [COMPLIANCE_BUNDLE_SIGNATURES.md](./COMPLIANCE_BUNDLE_SIGNATURES.md) for full details

---

## Phase 6: Rule Parsing

**Location**: [backend/app/services/compliance_rules_bson_parser.py](../backend/app/services/compliance_rules_bson_parser.py)

### What
Parses each rule file (BSON or JSON) and validates format.

### Why
- **Format Validation**: Ensure files are valid BSON/JSON
- **Schema Preview**: Detect schema issues before MongoDB import
- **Error Reporting**: Provide specific file/line error messages

### How

#### 6.1 BSON Parsing
```python
import bson

with open(rule_file, 'rb') as f:
    rule_data = bson.decode(f.read())
```

**Catches**:
- ❌ Corrupted BSON files
- ❌ Invalid BSON encoding
- ❌ Truncated files

**Error**: `"Invalid BSON file: rules/ow-test.bson"`

---

#### 6.2 JSON Parsing
```python
import json

with open(rule_file, 'r', encoding='utf-8') as f:
    rule_data = json.load(f)
```

**Catches**:
- ❌ Syntax errors
- ❌ Invalid UTF-8
- ❌ Binary content

**Error**: `"Invalid JSON in rules/ow-test.json: Expecting value at line 42"`

---

#### 6.3 Basic Schema Validation
```python
# Check for critical fields
if 'rule_id' not in rule_data:
    return FAIL(f"Rule missing 'rule_id': {filename}")

if 'metadata' not in rule_data:
    return FAIL(f"Rule missing 'metadata': {filename}")
```

**Early Detection**: Catches schema issues before expensive MongoDB validation

---

## Phase 7: Deduplication

**Location**: [backend/app/services/compliance_rules_deduplication_service.py](../backend/app/services/compliance_rules_deduplication_service.py)

### What
Detects duplicate rules and applies configured deduplication strategy.

### Why
- **Idempotency**: Same bundle can be uploaded multiple times safely
- **Version Control**: Track rule changes across uploads
- **Storage Efficiency**: Don't store identical rules multiple times

### How

#### 7.1 Duplicate Detection
```python
# Check if rule_id already exists in MongoDB
existing_rule = await ComplianceRule.find_one({"rule_id": rule_id})

if existing_rule:
    # Calculate content hashes
    existing_hash = calculate_content_hash(existing_rule)
    new_hash = calculate_content_hash(new_rule_data)

    if existing_hash == new_hash:
        action = "SKIP"  # Identical content
    else:
        action = "UPDATE"  # Content changed
else:
    action = "IMPORT"  # New rule
```

**Content Hash Calculation**:
```python
# SHA-256 hash of rule content (excludes metadata like timestamps)
EXCLUDED_FIELDS = [
    'imported_at', 'updated_at', 'source_file', '_id',
    'version', 'version_hash', 'revision_id'
]

normalized = {k: v for k, v in rule.items() if k not in EXCLUDED_FIELDS}
content_hash = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
```

---

#### 7.2 Deduplication Strategies

**Strategy 1: skip_all** (Default)
```python
# Skip all duplicates, only import new rules
if existing_rule:
    return "SKIP"
```

**Strategy 2: skip_unchanged_update_changed**
```python
# Skip if identical, update if content changed
if existing_hash == new_hash:
    return "SKIP"
else:
    return "UPDATE"
```

**Strategy 3: replace_all**
```python
# Replace all existing rules (re-import everything)
if existing_rule:
    return "UPDATE"
```

**Strategy 4: version_increment**
```python
# Create new version, keep old version
if existing_rule:
    new_rule.version = increment_version(existing_rule.version)
    return "IMPORT_NEW_VERSION"
```

---

#### 7.3 Statistics Tracking
```python
self.statistics = {
    'imported': 0,    # New rules added
    'updated': 0,     # Existing rules updated
    'skipped': 0,     # Duplicates skipped
    'errors': 0       # Validation failures
}
```

**User Feedback**: `"Successfully uploaded: 1500 imported, 300 updated, 213 skipped"`

---

## Phase 8: MongoDB Validation

**Location**: [backend/app/models/mongo_models.py:630-670](../backend/app/models/mongo_models.py#L630-L670)

This is the **final validation gate** before data enters MongoDB.

### What
Pydantic model validation enforcing strict schema requirements.

### Why
- **Data Quality**: Ensure all rules meet quality standards
- **Database Integrity**: Prevent malformed data in MongoDB
- **Application Stability**: Avoid runtime errors from bad data

### How

#### 8.1 Rule ID Validation
```python
@validator('rule_id')
def validate_rule_id(cls, v):
    if not v or len(v) < 3:
        raise ValueError('Rule ID must be at least 3 characters long')

    if not v.startswith('ow-'):
        raise ValueError('Rule ID must start with "ow-"')

    return v
```

**Requirements**:
- Minimum length: 3 characters
- Must start with `ow-` prefix
- Example: `ow-account_disable_post_pw_expiration`

**Why `ow-` prefix**: Namespace rules to prevent conflicts with other rule sources

**Error**: `"Rule ID must start with 'ow-'"`

---

#### 8.2 Metadata Validation
```python
@validator('metadata')
def validate_metadata(cls, v):
    if not v.get('name'):
        raise ValueError('Metadata must contain a name')

    return v
```

**Requirements**:
- `metadata` must be a dict
- `metadata.name` must exist and be non-empty

**Why**: UI displays `metadata.name` as rule title

**Error**: `"Metadata must contain a name"`

---

#### 8.3 Platform Implementation Validation
```python
class PlatformImplementation(BaseModel):
    versions: List[str] = Field(
        description="OS versions this implementation applies to"
    )  # REQUIRED - no default value
```

**Requirements**:
- `platform_implementations` is a dict of platform configs
- Each platform MUST have `versions` array
- Example: `{"rhel8": {"versions": ["8.0", "8.1", "8.2"]}}`

**Why**: UI needs to know which OS versions a rule applies to

**Error**: `"platform_implementations.rhel8.versions: Field required"`

---

#### 8.4 Severity Validation
```python
severity: str = Field(
    ...,  # Required
    pattern="^(critical|high|medium|low|info|unknown)$"
)
```

**Allowed Values**:
- `critical`, `high`, `medium`, `low`, `info`, `unknown`

**Error**: `"severity: String should match pattern '^(critical|high|medium|low|info|unknown)$'"`

---

#### 8.5 Framework Validation
```python
frameworks: Dict[str, Any] = Field(
    default_factory=dict,
    description="Framework mappings (NIST, CIS, STIG, etc.)"
)
```

**Structure**:
```json
{
  "nist": {
    "controls": ["AC-2", "AC-3"],
    "version": "800-53r5"
  },
  "cis": {
    "controls": ["1.1.1", "1.1.2"],
    "version": "v8.0"
  }
}
```

**Why**: Maps rules to compliance frameworks for reporting

---

## Validation Statistics

### By Phase

| Phase | Checks | Critical | High | Medium | Low | Info |
|-------|--------|----------|------|--------|-----|------|
| 1. File Extension | 1 | 1 | 0 | 0 | 0 | 0 |
| 2. File Size | 2 | 1 | 1 | 0 | 0 | 0 |
| 3. Security Validation | 10+ | 6 | 3 | 1 | 0 | 1 |
| 4. Archive Extraction | 1 | 1 | 0 | 0 | 0 | 0 |
| 5. Manifest Validation | 5+ | 2 | 1 | 0 | 0 | 2 |
| 6. Rule Parsing | 3 | 2 | 1 | 0 | 0 | 0 |
| 7. Deduplication | 1 | 0 | 0 | 0 | 0 | 1 |
| 8. MongoDB Validation | 10+ | 3 | 2 | 1 | 0 | 0 |
| **TOTAL** | **33+** | **16** | **8** | **2** | **0** | **4** |

---

## Error Handling

### Error Severity Levels

**Critical** (immediate rejection):
- Path traversal attempts
- Forbidden filenames
- Invalid tar.gz format
- Missing manifest
- Invalid signature (production mode)

**High** (rejection with details):
- Archive too large
- File too large (archive bomb)
- Missing required fields

**Medium** (warning, may continue):
- Individual file read errors
- Non-critical format issues

**Info** (informational only):
- SHA-512 hash calculated
- Archive structure valid
- Deduplication statistics

---

## Performance Considerations

### Validation Speed

**Fast Checks** (< 1ms):
- File extension validation
- Manifest existence
- JSON parsing

**Medium Checks** (< 100ms):
- SHA-512 hash calculation
- Archive extraction
- Manifest validation

**Slow Checks** (> 100ms):
- Individual file content scanning
- MongoDB validation (database queries)
- Deduplication hash comparison

### Optimization Strategies

1. **Early Rejection**: Fail fast on simple checks (extension, size)
2. **Streaming**: Don't load entire bundle into memory
3. **Parallel Validation**: Check multiple files concurrently
4. **Hash Caching**: Cache content hashes for deduplication

---

## Security Best Practices

### Defense in Depth

Multiple layers of protection:
1. File type whitelist
2. Size limits (bundle + individual files)
3. Path traversal prevention
4. Malicious content scanning
5. Symlink blocking
6. Signature verification (optional)
7. Schema validation

### Least Privilege

- Temporary extraction directories: owner-only (`0o700`)
- No execution permissions on extracted files
- Sandboxed MongoDB operations

### Audit Trail

Every validation phase logs:
- Timestamp
- Check name
- Pass/fail status
- Error details
- Bundle SHA-512 hash (provenance)

---

## Troubleshooting

### Common Validation Failures

**"Invalid file type. Only .tar.gz archives are allowed"**
- **Cause**: File extension is not `.tar.gz` or `.tgz`
- **Fix**: Ensure bundle is created with `tar czf bundle.tar.gz ...`

**"Rule ID must start with 'ow-'"**
- **Cause**: Converter didn't add `ow-` prefix to rule IDs
- **Fix**: Update converter to prepend `ow-` to all rule IDs

**"platform_implementations.rhel8.versions: Field required"**
- **Cause**: Platform config missing required `versions` array
- **Fix**: Add `"versions": ["8.0", "8.1", ...]` to platform config

**"Path traversal detected: ../../../etc/passwd"**
- **Cause**: Malicious or corrupted archive
- **Fix**: Investigate bundle source, reject upload

**"Bundle signature verification failed"**
- **Cause**: Unsigned bundle in production mode OR invalid signature
- **Fix**: Sign bundle with trusted key OR disable `REQUIRE_BUNDLE_SIGNATURE`

---

## References

- [DATA_STRUCTURE_SPECIFICATION.md](./DATA_STRUCTURE_SPECIFICATION.md) - Bundle format specification
- [COMPLIANCE_BUNDLE_SIGNATURES.md](./COMPLIANCE_BUNDLE_SIGNATURES.md) - Signature verification guide
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) - Security background
- [CVE-2007-4559](https://nvd.nist.gov/vuln/detail/CVE-2007-4559) - Python tarfile vulnerability
