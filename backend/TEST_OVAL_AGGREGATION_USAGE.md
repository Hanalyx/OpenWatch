# OVAL Aggregation Test Script - Usage Guide

## Overview

The `test_oval_aggregation.py` script is a comprehensive testing tool for validating OVAL (Open Vulnerability and Assessment Language) aggregation functionality in OpenWatch. It allows you to test XCCDF and OVAL generation for specific platforms and compliance frameworks.

**Location**: `/home/rracine/hanalyx/openwatch/backend/test_oval_aggregation.py`

---

## Quick Start

### 1. List Available Platforms and Frameworks

Before running tests, discover what platforms and frameworks are available in your database:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list
```

**Example Output**:
```
================================================================================
Available Platforms and Frameworks
================================================================================

Available Platforms:
--------------------------------------------------------------------------------
  rhel8                - 2013 rules with OVAL
  rhel9                - 2145 rules with OVAL
  ubuntu2004           -  567 rules with OVAL
  ubuntu2204           -  892 rules with OVAL

Available Frameworks by Platform:
--------------------------------------------------------------------------------

  rhel8:
    - cis            (1234 rules)
    - nist           (1890 rules)
    - pci_dss        (456 rules)
    - stig           (1678 rules)

  rhel9:
    - cis            (1345 rules)
    - nist           (2010 rules)
    - stig           (1789 rules)

  ubuntu2204:
    - cis            (567 rules)
    - nist           (789 rules)

================================================================================
Total: 4 platforms, 7618 rules with OVAL
================================================================================
```

---

## Usage Examples

### Example 1: Test All Platforms (Default Behavior)

Test OVAL aggregation for **all platforms** in your database:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py
```

**What it does**:
- Discovers all platforms automatically
- Generates aggregated OVAL files for each platform
- Creates test XCCDF benchmarks
- Validates XML structure

**Output Files** (in `/tmp/oval_test/`):
```
oval-definitions-rhel8.xml
oval-definitions-rhel9.xml
oval-definitions-ubuntu2004.xml
oval-definitions-ubuntu2204.xml
test-benchmark-rhel9.xml
```

---

### Example 2: Test Specific Platform Only

Test OVAL aggregation for **RHEL 9** only:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9
```

**What it does**:
- Fetches only RHEL 9 rules with OVAL definitions
- Generates `oval-definitions-rhel9.xml`
- Creates test XCCDF benchmark for RHEL 9

**Use Case**: You uploaded new RHEL 9 SCAP content and want to verify OVAL aggregation works.

---

### Example 3: Test CIS Controls for RHEL 9

Test OVAL aggregation for **CIS framework on RHEL 9**:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework cis
```

**What it does**:
- Fetches RHEL 9 rules that have CIS framework mappings
- Filters rules by `frameworks.cis` field in MongoDB
- Generates `oval-definitions-rhel9-cis.xml`
- Creates `test-benchmark-rhel9-cis.xml` with only CIS-mapped rules

**Use Case**: You need to validate that CIS-specific OVAL definitions are correctly aggregated for RHEL 9 scanning.

---

### Example 4: Test STIG Profile for RHEL 8

Test OVAL aggregation for **DISA STIG on RHEL 8**:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel8 --framework stig
```

**What it does**:
- Fetches RHEL 8 rules with STIG framework mappings
- Generates `oval-definitions-rhel8-stig.xml`
- Creates `test-benchmark-rhel8-stig.xml` with STIG controls

**Use Case**: You're preparing for a DISA STIG compliance scan and want to ensure OVAL definitions are complete.

---

### Example 5: Test NIST 800-53 for Ubuntu 22.04

Test OVAL aggregation for **NIST 800-53 on Ubuntu 22.04**:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform ubuntu2204 --framework nist
```

**What it does**:
- Fetches Ubuntu 22.04 rules with NIST framework mappings
- Generates `oval-definitions-ubuntu2204-nist.xml`
- Creates `test-benchmark-ubuntu2204-nist.xml` with NIST controls

**Use Case**: FedRAMP compliance requires NIST 800-53 controls on Ubuntu infrastructure.

---

### Example 6: Custom Output Directory

Save output files to a custom directory:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel9 \
  --framework cis \
  --output-dir /app/data/oval_test_results
```

**Output Files** (in `/app/data/oval_test_results/`):
```
oval-definitions-rhel9-cis.xml
test-benchmark-rhel9-cis.xml
```

---

### Example 7: Verbose Logging

Enable detailed debug logging:

```bash
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel8 \
  --framework stig \
  --verbose
```

**Use Case**: Troubleshooting OVAL aggregation failures or understanding MongoDB query details.

---

## Command-Line Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--platform` | string | Platform to test (rhel8, rhel9, ubuntu2204, etc.) | None (all platforms) |
| `--framework` | string | Framework/profile to test (cis, stig, nist, pci_dss, etc.) | None (all frameworks) |
| `--list` | flag | List available platforms and frameworks, then exit | False |
| `--output-dir` | string | Directory for output files | `/tmp/oval_test` |
| `--verbose` | flag | Enable verbose logging (DEBUG level) | False |

---

## Understanding the Output

### Test Phases

The script runs 6 test phases:

#### **Test 1: Fetching rules with OVAL definitions**
```
Test 1: Fetching rules with OVAL definitions
--------------------------------------------------------------------------------
Found 2145 rules with OVAL definitions
```

Queries MongoDB for rules matching your filters (platform + framework).

---

#### **Test 2: Rules grouped by platform**
```
Test 2: Rules grouped by platform
--------------------------------------------------------------------------------
  rhel9: 2145 rules with OVAL
```

Groups rules by platform extracted from `oval_filename` field.

---

#### **Test 3: Testing OVAL definition ID extraction**
```
Test 3: Testing OVAL definition ID extraction
--------------------------------------------------------------------------------
Sample rule: xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs
OVAL filename: rhel9/accounts_password_minlen_login_defs.xml
SUCCESS: Extracted OVAL ID: oval:ssg-accounts_password_minlen_login_defs:def:1
```

Validates that OVAL definition IDs can be extracted from individual OVAL files.

---

#### **Test 4: Testing OVAL aggregation**
```
Test 4: Testing OVAL aggregation
--------------------------------------------------------------------------------

Aggregating OVAL for platform: rhel9
  Rules for rhel9: 2145
  Framework filter: cis
  Rules matching framework: 1345
  SUCCESS: Created oval-definitions-rhel9-cis.xml (2,345,678 bytes)
```

Aggregates individual OVAL files into a single platform-specific file.

---

#### **Test 5: Verifying aggregated OVAL files**
```
Test 5: Verifying aggregated OVAL files
--------------------------------------------------------------------------------

Verifying rhel9...
  Definitions: 1345
  Tests: 2890
  Objects: 2456
  States: 1789
  Variables: 234
  SUCCESS: Valid OVAL file with 1345 definitions
```

Parses generated XML and validates OVAL structure.

---

#### **Test 6: Testing XCCDF benchmark generation with OVAL**
```
Test 6: Testing XCCDF benchmark generation with OVAL
--------------------------------------------------------------------------------
Generating XCCDF for rhel9 with 10 rules
Framework: cis
  SUCCESS: Generated XCCDF benchmark
  File: /tmp/oval_test/test-benchmark-rhel9-cis.xml (234,567 bytes)
  SUCCESS: XCCDF contains OVAL references
```

Creates a test XCCDF benchmark that references the aggregated OVAL file.

---

### Summary Output

```
================================================================================
Test Summary
================================================================================
Total rules with OVAL: 1345
Platforms tested: 1
Framework filter: cis
Successful aggregations: 1/1

Generated files:
  oval-definitions-rhel9-cis.xml (2,345,678 bytes)
  test-benchmark-rhel9-cis.xml (234,567 bytes)

All tests completed successfully!
```

---

## Common Use Cases

### Use Case 1: Validate New SCAP Content Upload

After uploading a new SCAP content bundle:

```bash
# Check what was imported
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list

# Test the specific platform
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9
```

---

### Use Case 2: Pre-Scan Validation

Before running a compliance scan with a specific profile:

```bash
# Test STIG profile for RHEL 8 (before running actual scan)
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel8 \
  --framework stig
```

If this succeeds, you know the OVAL aggregation will work during the actual scan.

---

### Use Case 3: Troubleshooting OVAL Aggregation Failures

If scans are failing with OVAL-related errors:

```bash
# Run with verbose logging to see detailed MongoDB queries
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel8 \
  --framework stig \
  --verbose
```

Check the output for:
- Missing OVAL files
- Incorrect `oval_filename` paths
- Framework mapping issues

---

### Use Case 4: Framework Coverage Analysis

Determine which frameworks are available for a platform:

```bash
# List all frameworks
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list

# Test each framework individually
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework cis
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework nist
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework stig
```

Compare rule counts to identify coverage gaps.

---

## Output Files Explained

### 1. `oval-definitions-{platform}.xml`

**Example**: `oval-definitions-rhel9.xml`

**Content**: Aggregated OVAL definitions for all rules on the platform

**Structure**:
```xml
<oval_definitions>
  <definitions>
    <definition id="oval:ssg-accounts_password_minlen:def:1" ...>
      <metadata>...</metadata>
      <criteria>...</criteria>
    </definition>
    <!-- 2145 more definitions -->
  </definitions>
  <tests>...</tests>
  <objects>...</objects>
  <states>...</states>
</oval_definitions>
```

**Use**: Referenced by XCCDF benchmarks during scanning.

---

### 2. `oval-definitions-{platform}-{framework}.xml`

**Example**: `oval-definitions-rhel9-cis.xml`

**Content**: OVAL definitions for rules mapped to a specific framework

**Use**: Scanning with a specific compliance framework (e.g., CIS Level 1 Server).

---

### 3. `test-benchmark-{platform}.xml`

**Example**: `test-benchmark-rhel9.xml`

**Content**: XCCDF benchmark with 10 sample rules (for quick validation)

**Structure**:
```xml
<Benchmark id="test_rhel9" ...>
  <Profile id="default">
    <select idref="xccdf_rule_1" selected="true"/>
    <!-- 9 more rules -->
  </Profile>
  <Group id="authentication">
    <Rule id="xccdf_rule_1">
      <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <check-content-ref href="oval-definitions.xml" name="oval:ssg-rule1:def:1"/>
      </check>
    </Rule>
  </Group>
</Benchmark>
```

**Use**: Validates that XCCDF correctly references OVAL definitions.

---

## Troubleshooting

### Error: "No rules with OVAL definitions found!"

**Cause**: No SCAP content with OVAL support has been imported.

**Solution**:
```bash
# Upload SCAP content bundle
# Example using ComplianceAsCode content
docker exec openwatch-backend python3 /app/backend/app/cli/scap_json_to_openwatch_converter.py \
  --product rhel9 \
  --import
```

---

### Error: "No rules found for platform: rhel9"

**Cause**: Specified platform doesn't exist in database.

**Solution**:
```bash
# List available platforms
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list

# Use correct platform name (check spelling: rhel9, not rhel-9)
```

---

### Error: "No rules found for platform with framework cis"

**Cause**: No rules on that platform have CIS framework mappings.

**Solution**:
```bash
# Check which frameworks are available for the platform
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list

# Use a framework that exists for that platform
```

---

### Error: "Failed to extract OVAL ID from {filename}"

**Cause**: OVAL file is missing or corrupted.

**Solution**:
```bash
# Check if OVAL files exist
docker exec openwatch-backend ls -la /app/data/oval_definitions/rhel9/

# Re-import SCAP content bundle
```

---

### Warning: "XCCDF does not contain expected OVAL references"

**Cause**: XCCDF generation didn't include OVAL check references.

**Impact**: Low (this is a test benchmark, not production)

**Solution**: Check XCCDFGeneratorService for OVAL reference generation logic.

---

## MongoDB Query Details

### Query for All Rules with OVAL

```javascript
db.compliance_rules.find({
  "is_latest": true,
  "oval_filename": { "$exists": true, "$ne": null }
})
```

---

### Query for Platform-Specific Rules

Filtering happens in Python after retrieval:

```python
platform_rules = [
    r for r in all_rules
    if r.get("oval_filename", "").startswith("rhel9/")
]
```

---

### Query for Framework-Specific Rules

```javascript
db.compliance_rules.find({
  "is_latest": true,
  "oval_filename": { "$exists": true, "$ne": null },
  "frameworks.cis": { "$exists": true }
})
```

Then filtered by platform in Python.

---

## Integration with OpenWatch Scanning

### How Test Output Relates to Real Scans

When you run an actual compliance scan:

1. **User triggers scan**: `POST /api/scans` with `platform=rhel9`, `framework=cis`
2. **XCCDFGeneratorService** uses the same logic tested by this script:
   - `generate_oval_definitions_file()` → Creates aggregated OVAL
   - `generate_benchmark()` → Creates XCCDF benchmark
3. **SCAP Scanner** uploads XCCDF + OVAL to remote host
4. **OpenSCAP** runs `oscap xccdf eval` with the generated files

**This test script validates steps 2-3 work correctly before the actual scan.**

---

## Best Practices

### 1. Test After Every SCAP Content Import

```bash
# After uploading new content
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9
```

---

### 2. Test Framework Coverage Before Compliance Audit

```bash
# Before FedRAMP audit (requires NIST 800-53)
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel8 \
  --framework nist

# Check rule count matches expected coverage
```

---

### 3. Use Verbose Mode for Development

```bash
# When developing OVAL aggregation features
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel9 \
  --verbose
```

---

### 4. Archive Test Output for Compliance Evidence

```bash
# Save test output as evidence of OVAL validation
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel8 \
  --framework stig \
  --output-dir /app/data/compliance_evidence/oval_validation_$(date +%Y%m%d)
```

---

## Related Documentation

- **XCCDF Generator Service**: `backend/app/services/xccdf_generator_service.py`
- **MongoDB SCAP Scanner**: `backend/app/services/mongodb_scap_scanner.py`
- **SCAP Import Service**: `backend/app/services/scap_import_service.py`
- **OVAL Storage**: `/app/data/oval_definitions/{platform}/`
- **Compliance Rules Model**: `backend/app/models/mongo_models.py` (ComplianceRule)

---

## Summary

The enhanced `test_oval_aggregation.py` script provides:

1. **Discovery**: `--list` to see available platforms and frameworks
2. **Filtering**: `--platform` and `--framework` for targeted testing
3. **Validation**: 6-phase test suite validates OVAL aggregation end-to-end
4. **Flexibility**: Test all platforms or specific platform+framework combinations
5. **Evidence**: Generates XML files for compliance audit evidence

**Key Use Cases**:
- Validate SCAP content imports
- Pre-scan validation for specific profiles (CIS, STIG, NIST)
- Troubleshoot OVAL aggregation failures
- Framework coverage analysis
- Compliance audit evidence generation
