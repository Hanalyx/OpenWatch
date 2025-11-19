# OVAL Aggregation Test Script - Quick Reference

## Basic Commands

```bash
# List available platforms and frameworks
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list

# Test all platforms (default)
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py

# Test specific platform
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9

# Test platform + framework
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework cis
```

---

## Common Test Scenarios

### CIS Benchmark Testing

```bash
# CIS for RHEL 9
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework cis

# CIS for RHEL 8
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel8 --framework cis

# CIS for Ubuntu 22.04
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform ubuntu2204 --framework cis
```

### DISA STIG Testing

```bash
# STIG for RHEL 8
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel8 --framework stig

# STIG for RHEL 9
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework stig
```

### NIST 800-53 Testing

```bash
# NIST for RHEL 9
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework nist

# NIST for Ubuntu 22.04
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform ubuntu2204 --framework nist
```

---

## Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--list` | List available platforms and frameworks | `--list` |
| `--platform` | Test specific platform | `--platform rhel9` |
| `--framework` | Test specific framework | `--framework cis` |
| `--output-dir` | Custom output directory | `--output-dir /app/data/test_results` |
| `--verbose` | Enable debug logging | `--verbose` |

---

## Output Files

### Default Location
`/tmp/oval_test/`

### File Types

| File Pattern | Description |
|--------------|-------------|
| `oval-definitions-{platform}.xml` | Aggregated OVAL for all frameworks |
| `oval-definitions-{platform}-{framework}.xml` | Aggregated OVAL for specific framework |
| `test-benchmark-{platform}.xml` | Test XCCDF benchmark (10 sample rules) |
| `test-benchmark-{platform}-{framework}.xml` | Framework-specific test XCCDF |

### Examples
```
/tmp/oval_test/
├── oval-definitions-rhel9.xml
├── oval-definitions-rhel9-cis.xml
├── oval-definitions-rhel8-stig.xml
├── test-benchmark-rhel9.xml
└── test-benchmark-rhel9-cis.xml
```

---

## Platform Names

| Platform | Description |
|----------|-------------|
| `rhel8` | Red Hat Enterprise Linux 8 |
| `rhel9` | Red Hat Enterprise Linux 9 |
| `rhel10` | Red Hat Enterprise Linux 10 |
| `ubuntu2004` | Ubuntu 20.04 LTS |
| `ubuntu2204` | Ubuntu 22.04 LTS |
| `ubuntu2404` | Ubuntu 24.04 LTS |
| `ol8` | Oracle Linux 8 |
| `ol9` | Oracle Linux 9 |
| `fedora` | Fedora Linux |

---

## Framework Names

| Framework | Description |
|-----------|-------------|
| `cis` | Center for Internet Security Benchmarks |
| `stig` | DISA Security Technical Implementation Guides |
| `nist` | NIST SP 800-53 / 800-171 Controls |
| `pci_dss` | Payment Card Industry Data Security Standard |
| `hipaa` | Health Insurance Portability and Accountability Act |
| `iso27001` | ISO/IEC 27001 Information Security |

---

## Workflow Examples

### After Uploading New SCAP Content

```bash
# 1. Check what was imported
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --list

# 2. Test the new platform
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9

# 3. Test specific frameworks
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework cis
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --platform rhel9 --framework stig
```

### Before Running Compliance Scan

```bash
# Validate OVAL aggregation works for your scan profile
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel8 \
  --framework stig
```

### Troubleshooting OVAL Issues

```bash
# Enable verbose logging
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py \
  --platform rhel8 \
  --framework stig \
  --verbose
```

---

## Expected Test Output

```
================================================================================
OVAL Aggregation Test Suite
Platform Filter: rhel9
Framework Filter: cis
================================================================================

Connecting to MongoDB...

Test 1: Fetching rules with OVAL definitions
--------------------------------------------------------------------------------
Found 1345 rules with OVAL definitions

Test 2: Rules grouped by platform
--------------------------------------------------------------------------------
  rhel9: 1345 rules with OVAL

Test 3: Testing OVAL definition ID extraction
--------------------------------------------------------------------------------
Sample rule: xccdf_org.ssgproject.content_rule_accounts_password_minlen
OVAL filename: rhel9/accounts_password_minlen.xml
SUCCESS: Extracted OVAL ID: oval:ssg-accounts_password_minlen:def:1

Test 4: Testing OVAL aggregation
--------------------------------------------------------------------------------

Aggregating OVAL for platform: rhel9
  Rules for rhel9: 1345
  Framework filter: cis
  Rules matching framework: 1345
  SUCCESS: Created oval-definitions-rhel9-cis.xml (2,345,678 bytes)

Test 5: Verifying aggregated OVAL files
--------------------------------------------------------------------------------

Verifying rhel9...
  Definitions: 1345
  Tests: 2890
  Objects: 2456
  States: 1789
  Variables: 234
  SUCCESS: Valid OVAL file with 1345 definitions

Test 6: Testing XCCDF benchmark generation with OVAL
--------------------------------------------------------------------------------
Generating XCCDF for rhel9 with 10 rules
Framework: cis
  SUCCESS: Generated XCCDF benchmark
  File: /tmp/oval_test/test-benchmark-rhel9-cis.xml (234,567 bytes)
  SUCCESS: XCCDF contains OVAL references

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

## Troubleshooting

| Error Message | Solution |
|---------------|----------|
| "No rules with OVAL definitions found!" | Upload SCAP content with OVAL support |
| "No rules found for platform: rhel9" | Check platform spelling with `--list` |
| "No rules found for platform with framework cis" | Framework not available, check with `--list` |
| "Failed to extract OVAL ID" | OVAL file missing or corrupted, re-import content |

---

## Help

```bash
# Show help message
docker exec openwatch-backend python3 /app/backend/test_oval_aggregation.py --help
```

---

## Full Documentation

See [TEST_OVAL_AGGREGATION_USAGE.md](./TEST_OVAL_AGGREGATION_USAGE.md) for complete documentation.
