# SCAP to OpenWatch Converter Guide

## Overview

The Enhanced SCAP to OpenWatch Converter transforms ComplianceAsCode YAML rules from the upstream SCAP Security Guide repository into OpenWatch-compatible BSON bundles. This tool bridges the gap between the ComplianceAsCode project and OpenWatch's MongoDB-based compliance rules system.

**Key Features:**
- Dry-run mode to preview conversions without making changes
- Direct BSON bundle creation for seamless uploads
- MongoDB comparison to identify new and modified rules
- Comprehensive statistics and change tracking
- Support for framework mappings (NIST, CIS, STIG, PCI DSS, ISO 27001, HIPAA)
- Platform-specific implementation expansion (RHEL, Ubuntu)

---

## Prerequisites

### 1. ComplianceAsCode Content Repository

Clone the upstream ComplianceAsCode repository:

```bash
cd /home/rracine/hanalyx
git clone https://github.com/ComplianceAsCode/content.git scap_content
```

**Repository Structure:**
```
/home/rracine/hanalyx/scap_content/content/
├── linux_os/
│   └── guide/
│       ├── system/
│       │   ├── accounts/
│       │   │   └── [rule-name]/
│       │   │       └── rule.yml    # SCAP rule definitions
│       │   ├── auditing/
│       │   ├── network/
│       │   └── ...
│       └── ...
├── products/
│   ├── rhel8/
│   ├── rhel9/
│   ├── ubuntu2204/
│   └── ...
└── shared/
    └── references/
```

### 2. Python Environment

The converter requires the following Python packages:

```bash
# Ensure you're in the OpenWatch backend environment
cd /home/rracine/hanalyx/openwatch/backend

# Install required packages (if not already installed)
pip install pyyaml pymongo motor bson
```

### 3. MongoDB Access (for comparison feature)

If you want to compare converted rules with existing MongoDB rules, ensure MongoDB is running:

```bash
# Check MongoDB status
docker ps | grep mongodb

# Or start the OpenWatch stack
cd /home/rracine/hanalyx/openwatch
./start-podman.sh
```

---

## Quick Start

### Basic Conversion Workflow

```bash
# Step 1: Preview what will be converted (dry-run)
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --dry-run

# Step 2: Convert to JSON format for review
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --format json

# Step 3: Create BSON bundle for upload
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --format bson \
  --create-bundle \
  --bundle-version 0.0.2

# Step 4: Upload the bundle to OpenWatch
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@/home/rracine/hanalyx/openwatch/data/uploads/openwatch-rules-bundle_v0.0.2.tar.gz"
```

---

## Command Reference

### 1. Convert Command

Transform ComplianceAsCode YAML rules into OpenWatch format.

#### Syntax

```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert [OPTIONS]
```

#### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--scap-path` | Path | `/home/rracine/hanalyx/scap_content/content` | Source directory containing SCAP YAML rules |
| `--output-path` | Path | `/home/rracine/hanalyx/openwatch/data/compliance_rules_converted` | Output directory for converted rules |
| `--format` | Choice | `json` | Output format: `json` or `bson` |
| `--dry-run` | Flag | `false` | Preview mode - no files written |
| `--create-bundle` | Flag | `false` | Create tar.gz bundle after conversion |
| `--bundle-version` | String | `0.0.1` | Version string for the bundle |

#### Examples

**Dry-Run Mode (Preview Only)**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --dry-run
```

**Output:**
```
2025-10-14 15:30:45 - INFO - Starting dry-run conversion from /home/rracine/hanalyx/scap_content/content
2025-10-14 15:30:45 - INFO - Found 2847 rule files
2025-10-14 15:30:45 - INFO - DRY RUN MODE - No files will be written
2025-10-14 15:30:46 - INFO - [DRY RUN] Would convert: account_disable_inactivity_password_auth
2025-10-14 15:30:46 - INFO - [DRY RUN] Would convert: account_emergency_admin
...

============================================================
CONVERSION SUMMARY
============================================================
Total rules found:        2847
Successfully converted:   2354
Conversion errors:        12
Skipped (Jinja2):         481
Template expansions:      756
Framework mappings:       2198
Platform implementations: 1512
============================================================
```

**Convert to JSON Format**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --format json \
  --output-path /home/rracine/hanalyx/openwatch/data/rules_v0.0.2
```

Creates JSON files:
```
/home/rracine/hanalyx/openwatch/data/rules_v0.0.2/
├── ow-account_disable_inactivity_password_auth.json
├── ow-account_emergency_admin.json
├── ow-accounts_password_pam_minlen.json
└── ...
```

**Convert to BSON with Bundle Creation**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --format bson \
  --create-bundle \
  --bundle-version 0.0.2
```

Creates:
1. BSON files in `/home/rracine/hanalyx/openwatch/data/compliance_rules_converted/*.bson`
2. Bundle at `/home/rracine/hanalyx/openwatch/data/openwatch-rules-bundle_v0.0.2.tar.gz`

**Custom Paths**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --scap-path /custom/path/to/content \
  --output-path /custom/output/path \
  --format json
```

---

### 2. Bundle Command

Create a tar.gz bundle from existing JSON or BSON files.

#### Syntax

```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle [OPTIONS]
```

#### Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `--source` | Path | Yes | Source directory containing rule files (JSON or BSON) |
| `--output` | Path | Yes | Output path for bundle tar.gz file |
| `--version` | String | No | Bundle version string (default: `0.0.1`) |

#### Examples

**Bundle from JSON Files**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle \
  --source /home/rracine/hanalyx/openwatch/data/compliance_rules_converted \
  --output /home/rracine/hanalyx/openwatch/data/uploads/my-bundle_v0.0.2.tar.gz \
  --version 0.0.2
```

**Output:**
```
2025-10-14 15:35:12 - INFO - Creating bundle from /home/.../compliance_rules_converted to /home/.../my-bundle_v0.0.2.tar.gz
2025-10-14 15:35:12 - INFO - Found 2354 JSON rule files
2025-10-14 15:35:12 - INFO - Converting JSON files to BSON...
2025-10-14 15:35:18 - INFO - Creating tar.gz bundle: /home/.../my-bundle_v0.0.2.tar.gz
2025-10-14 15:35:20 - INFO - Bundle created successfully: /home/.../my-bundle_v0.0.2.tar.gz (2354 rules)
```

**Bundle Structure:**
```
openwatch-rules-bundle_v0.0.2.tar.gz
├── manifest.json           # Bundle metadata
└── rules/
    ├── ow-account_disable_inactivity_password_auth.bson
    ├── ow-account_emergency_admin.bson
    └── ...
```

**Bundle from BSON Files**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle \
  --source /path/to/bson/files \
  --output /home/rracine/hanalyx/openwatch/data/uploads/bundle_v1.0.0.tar.gz \
  --version 1.0.0
```

---

### 3. Compare Command

Compare local rules with existing MongoDB rules to identify changes.

#### Syntax

```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare [OPTIONS]
```

#### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--local` | Path | Required | Local rules directory (JSON format) |
| `--mongodb-url` | URL | `mongodb://openwatch:secure_mongo_password@localhost:27017` | MongoDB connection URL |
| `--database` | String | `openwatch_rules` | MongoDB database name |

#### Examples

**Compare with Local MongoDB**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /home/rracine/hanalyx/openwatch/data/compliance_rules_converted \
  --mongodb-url mongodb://openwatch:secure_mongo_password@localhost:27017 \
  --database openwatch_rules
```

**Output:**
```
2025-10-14 15:40:23 - INFO - Comparing local rules in /home/.../compliance_rules_converted with MongoDB
2025-10-14 15:40:23 - INFO - Found 2354 local rules
2025-10-14 15:40:28 - INFO - Comparison complete: 127 new, 43 modified, 2184 unchanged

[NEW] ow-accounts_password_pam_enforce_for_root
[NEW] ow-file_permissions_systemd_generator
[NEW] ow-kernel_config_debug_sg
...

[MODIFIED] ow-accounts_password_pam_minlen - Changed fields: severity, frameworks
[MODIFIED] ow-firewall_sshd_port_enabled - Changed fields: check_content, platform_implementations
[MODIFIED] ow-sysctl_net_ipv4_conf_all_accept_redirects - Changed fields: remediation_complexity, identifiers
...
```

**Compare with Remote MongoDB**
```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /home/rracine/hanalyx/openwatch/data/compliance_rules_converted \
  --mongodb-url mongodb://admin:password@mongodb.example.com:27017 \
  --database production_openwatch
```

**Use Case - Pre-Upload Validation:**
```bash
# Step 1: Convert new rules
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --format json

# Step 2: Compare with production MongoDB
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /home/rracine/hanalyx/openwatch/data/compliance_rules_converted \
  --mongodb-url mongodb://openwatch:password@production-server:27017

# Step 3: Review changes before creating bundle
# (Review the [MODIFIED] entries to ensure changes are expected)

# Step 4: Create bundle only if changes are acceptable
python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle \
  --source /home/rracine/hanalyx/openwatch/data/compliance_rules_converted \
  --output /tmp/production-update_v1.2.0.tar.gz \
  --version 1.2.0
```

---

## Conversion Process Deep Dive

### What Gets Converted

The converter processes all `rule.yml` files in the ComplianceAsCode repository and transforms them into OpenWatch's MongoDB schema.

#### Source: SCAP YAML Format

**Example: `/scap_content/content/linux_os/guide/system/accounts/accounts-restrictions/password_storage/accounts_password_pam_minlen/rule.yml`**

```yaml
documentation_complete: true

prodtype: alinux2,alinux3,anolis8,ol7,ol8,ol9,rhel7,rhel8,rhel9,rhv4,sle12,sle15

title: 'Set Password Minimum Length in login.defs'

description: |-
    To specify password length requirements for new accounts,
    edit the file <tt>/etc/login.defs</tt> and add or correct the following
    line:
    <pre>PASS_MIN_LEN {{{ xccdf_value("var_accounts_password_minlen_login_defs") }}}</pre>

rationale: |-
    Requiring a minimum password length makes password
    cracking attacks more difficult by ensuring a larger
    search space.

severity: medium

identifiers:
    cce@rhel7: CCE-82046-4
    cce@rhel8: CCE-80652-1
    cce@rhel9: CCE-83481-2

references:
    cis@rhel7: 5.4.1.1
    cis@rhel8: 5.5.1.1
    nist: IA-5(1)(a),IA-5(f)
    nist@sle15: IA-5(1).1(v)
    srg: SRG-OS-000078-GPOS-00046
    stigid@ol8: OL08-00-020231
    stigid@rhel8: RHEL-08-020231

template:
    name: accounts_password
    vars:
        variable: minlen
        operation: greater than or equal
```

#### Target: OpenWatch JSON/BSON Format

**Output: `ow-accounts_password_minlen_login_defs.json`**

```json
{
  "_id": "ow-accounts_password_minlen_login_defs",
  "rule_id": "ow-accounts_password_minlen_login_defs",
  "scap_rule_id": "xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs",
  "parent_rule_id": null,
  "metadata": {
    "name": "Set Password Minimum Length in login.defs",
    "description": "To specify password length requirements for new accounts...",
    "rationale": "Requiring a minimum password length makes password cracking attacks more difficult...",
    "source": {
      "upstream_id": "accounts_password_minlen_login_defs",
      "complianceascode_version": "0.1.73",
      "source_file": "converted_from_yaml",
      "cce_id": "CCE-80652-1",
      "imported_at": "2025-10-14T15:30:45.123456+00:00"
    }
  },
  "abstract": false,
  "severity": "medium",
  "category": "authentication",
  "security_function": "access_control",
  "tags": ["scap", "ssg", "converted", "password", "severity_medium"],
  "frameworks": {
    "nist": {
      "800-53r5": ["IA-5(1)(a)", "IA-5(f)"]
    },
    "cis": {
      "controls_v8": ["5.4.1.1", "5.5.1.1"]
    },
    "stig": {
      "current": ["SRG-OS-000078-GPOS-00046", "RHEL-08-020231", "OL08-00-020231"]
    }
  },
  "platform_implementations": {
    "rhel": {
      "versions": ["7", "8", "9"],
      "check_method": "file",
      "check_command": "grep '^PASS_MIN_LEN\\s\\+14' /etc/login.defs",
      "enable_command": "sed -i 's/^#\\?PASS_MIN_LEN.*/PASS_MIN_LEN 14/' /etc/login.defs",
      "config_files": ["/etc/login.defs"],
      "service_dependencies": []
    },
    "ubuntu": {
      "versions": ["18.04", "20.04", "22.04", "24.04"],
      "check_method": "file",
      "check_command": "grep '^PASS_MIN_LEN\\s\\+14' /etc/login.defs",
      "enable_command": "sed -i 's/^#\\?PASS_MIN_LEN.*/PASS_MIN_LEN 14/' /etc/login.defs",
      "config_files": ["/etc/login.defs"],
      "service_dependencies": []
    }
  },
  "platform_requirements": {
    "required_capabilities": [],
    "excluded_environments": []
  },
  "check_type": "template",
  "check_content": {
    "scap_rule_id": "xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs",
    "method": "xccdf_evaluation",
    "expected_result": "pass"
  },
  "fix_available": true,
  "fix_content": {},
  "manual_remediation": "Edit /etc/login.defs and set PASS_MIN_LEN to 14 or greater",
  "remediation_complexity": "medium",
  "remediation_risk": "low",
  "dependencies": {
    "requires": [],
    "conflicts": [],
    "related": []
  },
  "source_file": "linux_os/guide/system/accounts/accounts-restrictions/password_storage/accounts_password_pam_minlen/rule.yml",
  "source_hash": "sha256:b153f8a48fa9c2e1",
  "version": "2024.2",
  "imported_at": "2025-10-14T15:30:45.123456+00:00",
  "updated_at": "2025-10-14T15:30:45.123456+00:00",
  "identifiers": {
    "cce": "CCE-80652-1"
  }
}
```

### Transformation Mappings

#### 1. Framework Reference Mapping

| SCAP Reference | OpenWatch Framework | Version |
|----------------|---------------------|---------|
| `nist: IA-5(1)(a)` | `nist.800-53r5` | Auto-detected (r4 or r5) |
| `cis@rhel8: 5.5.1.1` | `cis.controls_v8` | Based on reference format |
| `srg: SRG-OS-000078` | `stig.current` | Default version |
| `pcidss: 8.2.3` | `pci.v4.0` | v3.2.1 or v4.0 |
| `iso27001-2013: A.9.4.3` | `iso27001.2013` | 2013 or 2022 |
| `hipaa: 164.308(a)(5)(ii)(D)` | `hipaa.current` | Current version |

#### 2. Template Expansion

ComplianceAsCode templates are expanded into platform-specific implementations:

**Template: `sshd_lineinfile`**
```yaml
template:
  name: sshd_lineinfile
  vars:
    parameter: PermitRootLogin
    value: 'no'
```

**Expands to:**
```json
{
  "platform_implementations": {
    "rhel": {
      "versions": ["7", "8", "9"],
      "service_name": "sshd",
      "config_files": ["/etc/ssh/sshd_config"],
      "check_method": "file",
      "check_command": "grep '^PermitRootLogin\\s\\+no' /etc/ssh/sshd_config",
      "enable_command": "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
      "validation_command": "sshd -t",
      "service_dependencies": ["openssh-server"]
    },
    "ubuntu": {
      "versions": ["18.04", "20.04", "22.04", "24.04"],
      "service_name": "ssh",
      "config_files": ["/etc/ssh/sshd_config"],
      "check_method": "file",
      "check_command": "grep '^PermitRootLogin\\s\\+no' /etc/ssh/sshd_config",
      "enable_command": "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
      "validation_command": "sshd -t",
      "service_dependencies": ["openssh-server"]
    }
  }
}
```

**Supported Templates:**
- `sshd_lineinfile` - SSH configuration
- `package_installed` - Package management
- `service_enabled` - Systemd service management
- `sysctl` - Kernel parameter tuning
- Generic fallback for unknown templates

#### 3. Category Detection

Categories are determined from the file path:

| Path Contains | OpenWatch Category |
|---------------|-------------------|
| `ssh`, `login`, `password` | `authentication` |
| `audit`, `logging` | `audit_logging` |
| `firewall`, `network` | `network_security` |
| `crypto`, `encryption` | `cryptography` |
| `access`, `permission` | `access_control` |
| `service`, `kernel`, `mount` | `system_hardening` |
| (default) | `system_hardening` |

#### 4. Identifier Extraction

CCE (Common Configuration Enumeration) IDs are extracted with RHEL 8/9 preference:

```yaml
identifiers:
  cce@rhel7: CCE-82046-4
  cce@rhel8: CCE-80652-1  # Preferred
  cce@rhel9: CCE-83481-2  # Preferred
```

**Result:**
```json
{
  "identifiers": {
    "cce": "CCE-80652-1"
  }
}
```

### Skipped Content

The converter skips certain files to avoid processing errors:

1. **Jinja2 Templated Files** - Files containing `{{{`, `{{%`, or `{%-` are skipped as they cannot be parsed as pure YAML
2. **Test Files** - Any file path containing "test" or "unit" is excluded
3. **Invalid YAML** - Files that fail YAML parsing are logged and skipped

**Statistics Track:**
- Total files found
- Successfully converted
- Skipped (Jinja2)
- Conversion errors

---

## Bundle Structure

### Manifest Format

Every bundle includes a `manifest.json` file with metadata:

```json
{
  "name": "openwatch-rules-bundle_v0.0.2",
  "version": "0.0.2",
  "rules_count": 2354,
  "format": "bson",
  "created_at": "2025-10-14T15:35:20.789123+00:00"
}
```

### Bundle Contents

```
openwatch-rules-bundle_v0.0.2.tar.gz
├── manifest.json                                           # Bundle metadata
└── rules/                                                  # BSON-encoded rules
    ├── ow-account_disable_inactivity_password_auth.bson   # Individual rule (BSON format)
    ├── ow-account_emergency_admin.bson
    ├── ow-accounts_authorized_local_users_sidadm_orasid.bson
    ├── ow-accounts_have_homedir_login_defs.bson
    └── ... (2354 total rules)
```

### BSON Format

Each `.bson` file contains a binary-encoded MongoDB document with the complete rule structure. BSON provides:
- **Compact storage** - Smaller file sizes than JSON
- **Fast parsing** - Direct MongoDB compatibility
- **Type preservation** - Maintains data types (dates, binary, etc.)
- **Efficient uploads** - Reduces network transfer time

---

## Upload to OpenWatch

### Upload via API

```bash
# Upload bundle to OpenWatch
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@/home/rracine/hanalyx/openwatch/data/uploads/openwatch-rules-bundle_v0.0.2.tar.gz"
```

**Expected Response:**
```json
{
  "success": true,
  "upload_id": "3f7d8a9b-4c2e-4f3a-9b1a-8e7d6c5b4a3f",
  "filename": "openwatch-rules-bundle_v0.0.2.tar.gz",
  "file_hash": "a75458ffae8e748e...",
  "statistics": {
    "imported": 127,
    "updated": 43,
    "skipped": 2184,
    "errors": 0
  },
  "manifest": {
    "name": "openwatch-rules-bundle_v0.0.2",
    "version": "0.0.2",
    "rules_count": 2354,
    "created_at": "2025-10-14T15:35:20+00:00"
  },
  "processing_time_seconds": 4.23
}
```

### Idempotency

The upload system implements smart deduplication:
- **First upload**: Rules are imported
- **Subsequent uploads** (same content): Rules are skipped
- **Modified rules**: Only changed rules are updated

**Example:**
```bash
# Upload 1
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@bundle_v0.0.2.tar.gz"
# Result: 2354 imported, 0 updated, 0 skipped

# Upload 2 (same bundle)
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@bundle_v0.0.2.tar.gz"
# Result: 0 imported, 0 updated, 2354 skipped ✅ Idempotent!
```

---

## Common Workflows

### Workflow 1: Initial Setup - Convert All SCAP Rules

**Goal:** Convert the entire ComplianceAsCode repository for the first time.

```bash
# Step 1: Clone ComplianceAsCode repository
cd /home/rracine/hanalyx
git clone https://github.com/ComplianceAsCode/content.git scap_content

# Step 2: Preview conversion (dry-run)
cd /home/rracine/hanalyx/openwatch/backend
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --dry-run

# Step 3: Convert to JSON for review
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --format json

# Step 4: Spot-check a few rules
head -100 /home/rracine/hanalyx/openwatch/data/compliance_rules_converted/ow-accounts_password_pam_minlen.json

# Step 5: Create BSON bundle
python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle \
  --source /home/rracine/hanalyx/openwatch/data/compliance_rules_converted \
  --output /home/rracine/hanalyx/openwatch/data/uploads/openwatch-rules-bundle_v1.0.0.tar.gz \
  --version 1.0.0

# Step 6: Upload to OpenWatch
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@/home/rracine/hanalyx/openwatch/data/uploads/openwatch-rules-bundle_v1.0.0.tar.gz"
```

### Workflow 2: Update Existing Rules

**Goal:** Pull upstream ComplianceAsCode updates and create an incremental bundle.

```bash
# Step 1: Update ComplianceAsCode repository
cd /home/rracine/hanalyx/scap_content
git pull origin main

# Step 2: Convert with new version
cd /home/rracine/hanalyx/openwatch/backend
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --format json \
  --output-path /tmp/rules_v1.1.0

# Step 3: Compare with MongoDB to see what changed
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /tmp/rules_v1.1.0 \
  --mongodb-url mongodb://openwatch:secure_mongo_password@localhost:27017 \
  --database openwatch_rules

# Review output:
# [NEW] ow-new_rule_from_upstream
# [MODIFIED] ow-existing_rule - Changed fields: severity, frameworks
# ...

# Step 4: Create incremental bundle
python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle \
  --source /tmp/rules_v1.1.0 \
  --output /home/rracine/hanalyx/openwatch/data/uploads/openwatch-update_v1.1.0.tar.gz \
  --version 1.1.0

# Step 5: Upload
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@/home/rracine/hanalyx/openwatch/data/uploads/openwatch-update_v1.1.0.tar.gz"

# Result: Only new/modified rules will be imported/updated
```

### Workflow 3: Custom Rule Subset

**Goal:** Convert only rules for a specific product (e.g., RHEL 9).

```bash
# Step 1: Create filtered copy of SCAP content
mkdir -p /tmp/scap_rhel9
cp -r /home/rracine/hanalyx/scap_content/content/linux_os /tmp/scap_rhel9/
cp -r /home/rracine/hanalyx/scap_content/content/products/rhel9 /tmp/scap_rhel9/

# Step 2: Convert filtered content
cd /home/rracine/hanalyx/openwatch/backend
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --scap-path /tmp/scap_rhel9 \
  --output-path /tmp/rhel9_rules \
  --format bson \
  --create-bundle \
  --bundle-version 1.0.0-rhel9

# Step 3: Upload RHEL 9-specific bundle
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@/tmp/openwatch-rules-bundle_v1.0.0-rhel9.tar.gz"
```

### Workflow 4: Production Deployment

**Goal:** Safely deploy updated rules to production with validation.

```bash
# Step 1: Convert latest rules
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --format json \
  --output-path /tmp/prod_rules_v2.0.0

# Step 2: Compare with production MongoDB
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /tmp/prod_rules_v2.0.0 \
  --mongodb-url mongodb://admin:password@production-db.example.com:27017 \
  --database openwatch_production > /tmp/prod_comparison.txt

# Step 3: Review changes
cat /tmp/prod_comparison.txt
# Verify that [MODIFIED] entries are expected

# Step 4: Create production bundle
python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle \
  --source /tmp/prod_rules_v2.0.0 \
  --output /tmp/openwatch-prod_v2.0.0.tar.gz \
  --version 2.0.0

# Step 5: Test upload on staging first
curl -X POST "https://staging.example.com/api/v1/compliance/upload-rules" \
  -H "Authorization: Bearer $STAGING_TOKEN" \
  -F "file=@/tmp/openwatch-prod_v2.0.0.tar.gz"

# Step 6: Deploy to production (after staging validation)
curl -X POST "https://production.example.com/api/v1/compliance/upload-rules" \
  -H "Authorization: Bearer $PROD_TOKEN" \
  -F "file=@/tmp/openwatch-prod_v2.0.0.tar.gz"
```

---

## Troubleshooting

### Issue: Conversion Errors

**Symptom:**
```
2025-10-14 15:30:45 - ERROR - Error converting /path/to/rule.yml: 'title'
```

**Cause:** Rule is missing required fields (title, description, etc.)

**Solution:**
```bash
# Check the specific rule file
cat /home/rracine/hanalyx/scap_content/content/path/to/rule.yml

# Skip problematic rules by filtering
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --dry-run \
  2>&1 | grep ERROR > /tmp/errors.log

# Review errors and manually fix or report upstream
```

### Issue: Jinja2 Template Skips

**Symptom:**
```
Skipped (Jinja2):         481
```

**Cause:** Some ComplianceAsCode rules use Jinja2 templating that cannot be parsed as pure YAML.

**Impact:** These rules cannot be automatically converted and must be handled separately.

**Solution:**
```bash
# List skipped files
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --dry-run \
  2>&1 | grep "Skipping.*Jinja2" > /tmp/skipped_jinja2.log

# Review skipped files
cat /tmp/skipped_jinja2.log

# Option 1: Convert manually by rendering Jinja2 first
# Option 2: Wait for upstream to provide non-templated versions
# Option 3: Skip these rules (they are often platform-specific)
```

### Issue: MongoDB Connection Failed

**Symptom:**
```
ERROR - Failed to connect to MongoDB: [Errno 111] Connection refused
```

**Cause:** MongoDB is not running or connection URL is incorrect.

**Solution:**
```bash
# Check MongoDB status
docker ps | grep mongodb

# Start OpenWatch stack
cd /home/rracine/hanalyx/openwatch
./start-podman.sh

# Verify connection
docker exec openwatch-mongodb mongosh \
  "mongodb://openwatch:secure_mongo_password@localhost:27017/openwatch_rules?authSource=admin" \
  --eval "db.compliance_rules.countDocuments({})"

# Use correct connection URL in compare command
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /tmp/rules \
  --mongodb-url mongodb://openwatch:secure_mongo_password@localhost:27017 \
  --database openwatch_rules
```

### Issue: Bundle Upload Fails

**Symptom:**
```json
{
  "detail": "Method Not Allowed"
}
```

**Cause:** Wrong API endpoint or HTTP method.

**Solution:**
```bash
# Check OpenAPI documentation
curl http://localhost:8000/openapi.json | python -m json.tool | grep -A5 "upload-rules"

# Use correct endpoint
curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -F "file=@/path/to/bundle.tar.gz"

# If authentication required, add token
TOKEN=$(curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}' | jq -r '.access_token')

curl -X POST "http://localhost:8000/api/v1/compliance/upload-rules" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/bundle.tar.gz"
```

### Issue: Import Shows Unexpected Changes

**Symptom:**
```
Comparison complete: 0 new, 2354 modified, 0 unchanged
```

**Cause:** Field structure changed between conversions or Pydantic defaults changed.

**Solution:**
```bash
# Compare specific rule to see what changed
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /tmp/rules \
  --mongodb-url mongodb://openwatch:secure_mongo_password@localhost:27017 \
  --database openwatch_rules \
  | grep "ow-accounts_password_pam_minlen"

# Output shows specific fields:
# [MODIFIED] ow-accounts_password_pam_minlen - Changed fields: identifiers, platform_implementations

# Investigate by comparing JSON directly
jq '.' /tmp/rules/ow-accounts_password_pam_minlen.json > /tmp/new.json

# Export from MongoDB for comparison
docker exec openwatch-mongodb mongosh \
  "mongodb://openwatch:secure_mongo_password@localhost:27017/openwatch_rules?authSource=admin" \
  --eval "printjson(db.compliance_rules.findOne({rule_id: 'ow-accounts_password_pam_minlen'}))" \
  > /tmp/old.json

# Compare
diff /tmp/old.json /tmp/new.json
```

---

## Best Practices

### 1. Always Use Dry-Run First

Before any conversion, preview what will be converted:

```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --dry-run
```

This helps identify issues without writing files.

### 2. Version Your Bundles

Use semantic versioning for bundles:

```bash
# Initial release
--bundle-version 1.0.0

# Patch updates (bug fixes, minor changes)
--bundle-version 1.0.1

# Minor updates (new rules added)
--bundle-version 1.1.0

# Major updates (breaking changes)
--bundle-version 2.0.0
```

### 3. Compare Before Upload

Always compare with MongoDB before creating production bundles:

```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /tmp/new_rules \
  --mongodb-url mongodb://...
```

Review the output to ensure changes are expected.

### 4. Test on Staging First

Never upload directly to production:

```bash
# Test on staging
curl -X POST "http://staging:8000/api/v1/compliance/upload-rules" ...

# Verify upload
curl "http://staging:8000/api/v1/compliance-rules?limit=10"

# Deploy to production only after validation
```

### 5. Keep Conversion Logs

Save conversion output for troubleshooting:

```bash
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert \
  --format json \
  2>&1 | tee /var/log/openwatch/conversion_$(date +%Y%m%d_%H%M%S).log
```

### 6. Regular Upstream Sync

Update ComplianceAsCode regularly to get security fixes:

```bash
# Weekly sync
cd /home/rracine/hanalyx/scap_content
git pull origin main

# Convert and compare
cd /home/rracine/hanalyx/openwatch/backend
python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --format json
python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
  --local /home/rracine/hanalyx/openwatch/data/compliance_rules_converted
```

### 7. Document Custom Modifications

If you modify converted rules, document changes:

```bash
# Create a changes log
echo "Modified ow-accounts_password_pam_minlen: Changed severity from medium to high" \
  >> /home/rracine/hanalyx/openwatch/data/CONVERSION_CHANGES.log
```

---

## Integration with OpenWatch

### Upload API Integration

The converter produces bundles compatible with OpenWatch's compliance rules upload API:

**Endpoint:** `POST /api/v1/compliance/upload-rules`

**Request:**
- Content-Type: `multipart/form-data`
- Field: `file` (tar.gz bundle)

**Response:**
```json
{
  "success": true,
  "upload_id": "uuid",
  "statistics": {
    "imported": 127,
    "updated": 43,
    "skipped": 2184,
    "errors": 0
  }
}
```

### Idempotency Guarantees

The upload system implements content-addressed deduplication:

1. **Content Hash Calculation** - SHA-256 hash of rule content (excluding metadata)
2. **Smart Comparison** - Compares hashes to detect changes
3. **Field-Level Change Detection** - Identifies specific fields that changed
4. **Pydantic Default Normalization** - Handles missing vs. default value differences

**Result:** Uploading the same bundle multiple times results in:
- Upload 1: Rules imported
- Upload 2+: Rules skipped (idempotent ✅)

### MongoDB Schema Compatibility

The converter outputs match OpenWatch's `ComplianceRule` MongoDB model:

**Key Fields:**
- `_id`, `rule_id` - Unique identifiers
- `metadata` - Rich metadata with source provenance
- `frameworks` - Multi-version framework mappings
- `platform_implementations` - Platform-specific check/remediation commands
- `identifiers` - CCE, CVE, OVAL cross-references
- `version`, `version_hash` - Immutable versioning for FISMA/FedRAMP compliance
- `is_latest` - Denormalized flag for query performance

---

## Appendix

### A. Supported Frameworks

| Framework | Versions | Example Reference |
|-----------|----------|-------------------|
| NIST 800-53 | r4, r5 | `nist: IA-5(1)(a)` |
| CIS Controls | v7, v8 | `cis@rhel8: 5.5.1.1` |
| DISA STIG | current, rhel8_v1r11, rhel9_v1r3 | `stigid@rhel8: RHEL-08-020231` |
| PCI DSS | v3.2.1, v4.0 | `pcidss: 8.2.3` |
| ISO 27001 | 2013, 2022 | `iso27001-2013: A.9.4.3` |
| HIPAA | current | `hipaa: 164.308(a)(5)(ii)(D)` |

### B. Supported Templates

| Template Name | Description | Platforms |
|---------------|-------------|-----------|
| `sshd_lineinfile` | SSH configuration file parameters | RHEL, Ubuntu |
| `package_installed` | Package installation checks | RHEL (yum/dnf), Ubuntu (apt) |
| `service_enabled` | Systemd service management | RHEL, Ubuntu |
| `sysctl` | Kernel parameter tuning | RHEL, Ubuntu |
| `accounts_password` | Password policy settings | RHEL, Ubuntu |
| `file_permissions` | File/directory permissions | RHEL, Ubuntu |
| `mount_option` | Filesystem mount options | RHEL, Ubuntu |
| Generic | Fallback for unknown templates | RHEL |

### C. Rule Categories

| Category | Description | Example Rules |
|----------|-------------|---------------|
| `authentication` | User authentication, passwords, SSH | `accounts_password_*`, `sshd_*` |
| `audit_logging` | System auditing and logging | `audit_rules_*`, `rsyslog_*` |
| `network_security` | Firewall, network services | `firewalld_*`, `network_*` |
| `cryptography` | Encryption, certificates, crypto policies | `crypto_*`, `tls_*` |
| `access_control` | File permissions, SELinux, AppArmor | `file_permissions_*`, `selinux_*` |
| `system_hardening` | Kernel, services, system configuration | `kernel_*`, `sysctl_*`, `service_*` |

### D. File Paths Reference

| Path | Description |
|------|-------------|
| `/home/rracine/hanalyx/scap_content/content` | ComplianceAsCode repository (source) |
| `/home/rracine/hanalyx/openwatch/data/compliance_rules_converted` | Converted rules (JSON/BSON) |
| `/home/rracine/hanalyx/openwatch/data/uploads` | Bundles ready for upload |
| `/home/rracine/hanalyx/openwatch/backend/app/cli/scap_to_openwatch_converter_enhanced.py` | Enhanced converter script |

### E. Related Documentation

- [CLAUDE.md](../../CLAUDE.md) - OpenWatch development guide
- [ComplianceAsCode Documentation](https://complianceascode.readthedocs.io/)
- [OpenWatch Compliance Rules API](../../../openwatch/docs/API_COMPLIANCE_RULES.md)
- [MongoDB Integration Guide](../../../openwatch/docs/MONGODB_INTEGRATION.md)

---

## Support

For issues or questions:

1. **GitHub Issues**: [OpenWatch Repository](https://github.com/Hanalyx/OpenWatch/issues)
2. **Documentation**: Check [OpenWatch Docs](../README.md)
3. **ComplianceAsCode**: [Upstream Repository](https://github.com/ComplianceAsCode/content)

---

**Last Updated:** 2025-10-14
