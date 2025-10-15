# OpenWatch Remediation with XCCDF Variables (Solution A)

## Overview

This document describes how OpenWatch integrates with OSCAP remediation automation while supporting user-customizable XCCDF variables. Solution A provides native OSCAP compatibility and maximum flexibility.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      OpenWatch Backend                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. User Customizes Variables                                    │
│     └─> API: POST /api/v1/scan-configs                          │
│         {                                                         │
│           "profile": "stig",                                     │
│           "variable_overrides": {                                │
│             "var_accounts_tmout": "900",                         │
│             "login_banner_text": "ACME Corp"                     │
│           }                                                       │
│         }                                                         │
│                                                                   │
│  2. Generate XCCDF Tailoring File                               │
│     └─> TailoringGenerator.create_tailoring()                   │
│         - Preserves native XCCDF variable structure              │
│         - Compatible with oscap --tailoring-file                 │
│                                                                   │
│  3. Execute Scan with Remediation                               │
│     └─> RemediationService.scan_and_remediate()                 │
│         - Passes tailoring file to OSCAP                         │
│         - OSCAP handles variable injection automatically         │
│                                                                   │
│  4. OSCAP Remediation Engine                                    │
│     └─> oscap xccdf eval --remediate                            │
│         - Reads variable values from tailoring                   │
│         - Injects into Ansible/Bash scripts                      │
│         - Executes remediation with custom values                │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. XCCDF Tailoring Generator

```python
# backend/app/services/xccdf_tailoring_generator.py

from typing import Dict, List, Optional
from pathlib import Path
from lxml import etree

class XCCDFTailoringGenerator:
    """
    Generate XCCDF 1.2 tailoring files with custom variable values

    Tailoring files allow runtime customization of XCCDF content without
    modifying the original data-stream. OSCAP natively supports this.
    """

    XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
    NSMAP = {None: XCCDF_NS}

    def create_tailoring(
        self,
        profile_id: str,
        variable_overrides: Dict[str, str],
        benchmark_href: str,
        output_path: Path
    ) -> Path:
        """
        Create XCCDF tailoring file with custom variable values

        Args:
            profile_id: XCCDF profile ID (e.g., "xccdf_org.ssgproject.content_profile_stig")
            variable_overrides: Dict mapping variable IDs to custom values
            benchmark_href: Reference to the benchmark (data-stream component ID)
            output_path: Where to write the tailoring file

        Returns:
            Path to generated tailoring file
        """
        root = etree.Element(
            f"{{{self.XCCDF_NS}}}Tailoring",
            nsmap=self.NSMAP,
            id="openwatch_tailoring"
        )

        # Benchmark reference
        etree.SubElement(
            root,
            f"{{{self.XCCDF_NS}}}benchmark",
            href=benchmark_href
        )

        # Version info
        version = etree.SubElement(root, f"{{{self.XCCDF_NS}}}version")
        version.text = "1.0"
        version.set("time", datetime.utcnow().isoformat())

        # Custom profile with variable overrides
        profile = etree.SubElement(
            root,
            f"{{{self.XCCDF_NS}}}Profile",
            id=f"{profile_id}_customized"
        )

        # Title and description
        title = etree.SubElement(profile, f"{{{self.XCCDF_NS}}}title")
        title.text = f"OpenWatch Customized Profile: {profile_id}"

        description = etree.SubElement(profile, f"{{{self.XCCDF_NS}}}description")
        description.text = f"Custom variable values applied via OpenWatch"

        # Extend original profile
        etree.SubElement(
            profile,
            f"{{{self.XCCDF_NS}}}extends",
            idref=profile_id
        )

        # Apply variable overrides
        for var_id, value in variable_overrides.items():
            # Ensure fully-qualified XCCDF variable ID
            if not var_id.startswith("xccdf_"):
                var_id = f"xccdf_org.ssgproject.content_value_{var_id}"

            set_value = etree.SubElement(
                profile,
                f"{{{self.XCCDF_NS}}}set-value",
                idref=var_id
            )
            set_value.text = str(value)

        # Write to file
        tree = etree.ElementTree(root)
        tree.write(
            str(output_path),
            pretty_print=True,
            xml_declaration=True,
            encoding="UTF-8"
        )

        return output_path

    async def create_from_scan_config(
        self,
        scan_config_id: str,
        output_dir: Path
    ) -> Path:
        """
        Create tailoring file from stored scan configuration

        Args:
            scan_config_id: UUID of scan configuration
            output_dir: Directory to write tailoring file

        Returns:
            Path to generated tailoring file
        """
        # Load scan config from database
        scan_config = await ScanConfiguration.get(scan_config_id)

        # Decrypt sensitive variables
        variable_overrides = await self._decrypt_sensitive_vars(
            scan_config.variable_overrides
        )

        # Get profile metadata
        profile = await ComplianceProfile.find_one(
            ComplianceProfile.name == scan_config.profile
        )

        # Generate tailoring file
        tailoring_path = output_dir / f"tailoring_{scan_config_id}.xml"

        return self.create_tailoring(
            profile_id=profile.xccdf_id,
            variable_overrides=variable_overrides,
            benchmark_href=f"#{profile.benchmark_id}",
            output_path=tailoring_path
        )
```

### 2. Example Tailoring File

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2"
           id="openwatch_tailoring">
  <benchmark href="#scap_org.open-scap_cref_ssg-rhel8-ds.xml"/>
  <version time="2025-10-14T10:30:00">1.0</version>

  <Profile id="xccdf_org.ssgproject.content_profile_stig_customized">
    <title>OpenWatch Customized Profile: DISA STIG for RHEL 8</title>
    <description>Custom variable values applied via OpenWatch</description>

    <!-- Extend the base STIG profile -->
    <extends idref="xccdf_org.ssgproject.content_profile_stig"/>

    <!-- Custom variable values -->
    <set-value idref="xccdf_org.ssgproject.content_value_var_accounts_tmout">900</set-value>
    <set-value idref="xccdf_org.ssgproject.content_value_var_password_pam_minlen">15</set-value>
    <set-value idref="xccdf_org.ssgproject.content_value_login_banner_text">ACME Corporation - Authorized Access Only

This system is for authorized use only. Unauthorized access is prohibited
and will be prosecuted to the fullest extent of the law.</set-value>
    <set-value idref="xccdf_org.ssgproject.content_value_grub2_bootloader_username">admin</set-value>
    <set-value idref="xccdf_org.ssgproject.content_value_grub2_bootloader_password">grub.pbkdf2.sha512.10000.ABC123...</set-value>
  </Profile>
</Tailoring>
```

### 3. Remediation Service Integration

```python
# backend/app/services/remediation_service.py

from typing import Dict, Optional
from pathlib import Path
import asyncio

class RemediationService:
    """
    Execute OSCAP remediation with custom variable values

    Uses XCCDF tailoring files to pass variable overrides to OSCAP,
    which then injects them into Ansible/Bash remediation scripts.
    """

    def __init__(self):
        self.tailoring_gen = XCCDFTailoringGenerator()
        self.scan_service = ScanService()

    async def scan_and_remediate(
        self,
        host_id: str,
        scan_config_id: str,
        remediation_type: str = "ansible"  # or "bash"
    ) -> RemediationResult:
        """
        Execute compliance scan with automatic remediation

        Args:
            host_id: Target host UUID
            scan_config_id: Scan configuration with variable overrides
            remediation_type: "ansible" or "bash"

        Returns:
            RemediationResult with scan results and remediation actions
        """
        # Get host and scan config
        host = await Host.get(host_id)
        scan_config = await ScanConfiguration.get(scan_config_id)

        # Create working directory
        work_dir = Path(f"/tmp/remediation_{host_id}_{scan_config_id}")
        work_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Generate tailoring file with custom variables
            tailoring_file = await self.tailoring_gen.create_from_scan_config(
                scan_config_id=scan_config_id,
                output_dir=work_dir
            )

            # Get SCAP content path
            scap_content = await self._get_scap_content(scan_config.profile)

            # Build oscap command
            cmd = [
                "oscap", "xccdf", "eval",
                "--profile", scan_config.profile,
                "--tailoring-file", str(tailoring_file),
                "--remediate",  # Enable automatic remediation
                "--results-arf", str(work_dir / "results.xml"),
                "--report", str(work_dir / "report.html")
            ]

            # Add remediation type flag
            if remediation_type == "ansible":
                cmd.extend(["--remediation-type", "ansible"])
            elif remediation_type == "bash":
                cmd.extend(["--remediation-type", "bash"])

            cmd.append(str(scap_content))

            # Execute remotely via SSH if needed
            if host.connection_type == "ssh":
                result = await self._execute_remote_remediation(
                    host=host,
                    command=cmd,
                    work_dir=work_dir,
                    tailoring_file=tailoring_file
                )
            else:
                result = await self._execute_local_remediation(
                    command=cmd,
                    work_dir=work_dir
                )

            # Parse results
            remediation_result = await self._parse_remediation_results(
                results_file=work_dir / "results.xml",
                report_file=work_dir / "report.html"
            )

            # Store in database
            await self._store_remediation_results(
                host_id=host_id,
                scan_config_id=scan_config_id,
                result=remediation_result
            )

            return remediation_result

        finally:
            # Cleanup
            if not scan_config.keep_temp_files:
                shutil.rmtree(work_dir, ignore_errors=True)

    async def _execute_remote_remediation(
        self,
        host: Host,
        command: List[str],
        work_dir: Path,
        tailoring_file: Path
    ) -> subprocess.CompletedProcess:
        """
        Execute remediation on remote host via SSH

        Steps:
        1. Copy tailoring file to remote host
        2. Execute oscap command remotely
        3. Retrieve results
        """
        # Decrypt SSH credentials
        credentials = await self._decrypt_credentials(host.encrypted_credentials)

        # Copy tailoring file to remote
        async with asyncssh.connect(
            host.hostname,
            username=credentials["username"],
            password=credentials.get("password"),
            client_keys=credentials.get("private_key")
        ) as conn:
            # Create remote work directory
            await conn.run(f"mkdir -p /tmp/openwatch_remediation")

            # Copy tailoring file
            async with conn.start_sftp_client() as sftp:
                await sftp.put(
                    str(tailoring_file),
                    f"/tmp/openwatch_remediation/tailoring.xml"
                )

            # Update command with remote paths
            remote_cmd = [
                "sudo",  # Remediation requires root
                *command
            ]
            remote_cmd[remote_cmd.index(str(tailoring_file))] = "/tmp/openwatch_remediation/tailoring.xml"

            # Execute remediation
            result = await conn.run(" ".join(remote_cmd))

            # Retrieve results
            async with conn.start_sftp_client() as sftp:
                await sftp.get(
                    "/tmp/openwatch_remediation/results.xml",
                    str(work_dir / "results.xml")
                )
                await sftp.get(
                    "/tmp/openwatch_remediation/report.html",
                    str(work_dir / "report.html")
                )

            return result

    async def _parse_remediation_results(
        self,
        results_file: Path,
        report_file: Path
    ) -> RemediationResult:
        """
        Parse OSCAP remediation results

        Returns:
            RemediationResult with:
            - Rules evaluated
            - Rules that passed/failed
            - Remediation actions taken
            - Success rate
        """
        tree = etree.parse(str(results_file))

        # Parse results using XCCDF namespace
        rules_evaluated = len(tree.xpath("//xccdf:rule-result", namespaces={"xccdf": self.XCCDF_NS}))

        rules_passed = len(tree.xpath(
            "//xccdf:rule-result[xccdf:result='pass']",
            namespaces={"xccdf": self.XCCDF_NS}
        ))

        rules_failed = len(tree.xpath(
            "//xccdf:rule-result[xccdf:result='fail']",
            namespaces={"xccdf": self.XCCDF_NS}
        ))

        # Find remediation actions (fixes applied)
        remediation_actions = []
        for fix in tree.xpath("//xccdf:fix", namespaces={"xccdf": self.XCCDF_NS}):
            remediation_actions.append({
                "rule_id": fix.getparent().get("idref"),
                "system": fix.get("system"),  # "urn:xccdf:fix:script:ansible" or "bash"
                "complexity": fix.get("complexity"),
                "disruption": fix.get("disruption"),
                "success": fix.get("success") == "true"
            })

        return RemediationResult(
            rules_evaluated=rules_evaluated,
            rules_passed=rules_passed,
            rules_failed=rules_failed,
            remediation_actions=remediation_actions,
            success_rate=rules_passed / rules_evaluated if rules_evaluated > 0 else 0,
            results_file=results_file,
            report_file=report_file
        )
```

### 4. API Endpoints

```python
# backend/app/routes/remediation.py

from fastapi import APIRouter, Depends, BackgroundTasks
from app.services.remediation_service import RemediationService
from app.models.remediation import RemediationRequest, RemediationResult

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])

@router.post("/scan-and-remediate")
async def scan_and_remediate(
    request: RemediationRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
) -> RemediationResult:
    """
    Execute compliance scan with automatic remediation

    This endpoint:
    1. Generates XCCDF tailoring file from scan config
    2. Executes oscap with --remediate flag
    3. OSCAP injects custom variable values into remediation scripts
    4. Returns results with remediation actions taken

    Example:
        POST /api/v1/remediation/scan-and-remediate
        {
            "host_id": "host-uuid-1234",
            "scan_config_id": "cfg-uuid-5678",
            "remediation_type": "ansible",
            "async": false
        }
    """
    service = RemediationService()

    if request.async_execution:
        # Run in background
        background_tasks.add_task(
            service.scan_and_remediate,
            host_id=request.host_id,
            scan_config_id=request.scan_config_id,
            remediation_type=request.remediation_type
        )
        return {"status": "queued", "task_id": "..."}
    else:
        # Run synchronously
        result = await service.scan_and_remediate(
            host_id=request.host_id,
            scan_config_id=request.scan_config_id,
            remediation_type=request.remediation_type
        )
        return result

@router.get("/preview-tailoring/{scan_config_id}")
async def preview_tailoring(
    scan_config_id: str,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Preview the XCCDF tailoring file that would be generated

    Useful for debugging variable overrides before executing scan.
    """
    generator = XCCDFTailoringGenerator()
    temp_file = Path(f"/tmp/preview_{scan_config_id}.xml")

    tailoring_path = await generator.create_from_scan_config(
        scan_config_id=scan_config_id,
        output_dir=temp_file.parent
    )

    with open(tailoring_path, 'r') as f:
        content = f.read()

    return {
        "scan_config_id": scan_config_id,
        "tailoring_xml": content
    }
```

## How Variables Flow Through System

```
User Customization (UI)
  ↓
API: POST /api/v1/scan-configs
  {
    "profile": "stig",
    "variable_overrides": {
      "var_accounts_tmout": "900"
    }
  }
  ↓
Database: ScanConfiguration document
  - Stores variable overrides (encrypted if sensitive)
  ↓
XCCDFTailoringGenerator.create_from_scan_config()
  - Loads scan config from DB
  - Generates tailoring.xml with <set-value> elements
  ↓
RemediationService.scan_and_remediate()
  - Passes tailoring.xml to oscap via --tailoring-file
  ↓
OSCAP Remediation Engine
  - Reads variable values from tailoring.xml
  - Injects into Ansible playbooks: {{ var_accounts_tmout }}
  - Injects into Bash scripts: $XCCDF_VALUE_VAR_ACCOUNTS_TMOUT
  ↓
Ansible/Bash Execution
  - Uses custom values (900 instead of default 600)
  - Applies remediation with user's requirements
  ↓
Results Stored in Database
  - Which remediations succeeded/failed
  - Audit trail of changes made
```

## Example: Complete Remediation Flow

### 1. User Creates Custom Scan Config

```bash
curl -X POST http://localhost:8000/api/v1/scan-configs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production STIG - Extended Timeouts",
    "profile": "stig",
    "variable_overrides": {
      "var_accounts_tmout": "1800",
      "var_password_pam_minlen": "15",
      "login_banner_text": "ACME Corp - Authorized Users Only"
    }
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "config_id": "cfg-abc123",
    "name": "Production STIG - Extended Timeouts",
    "variables_customized": 3
  }
}
```

### 2. Execute Scan with Remediation

```bash
curl -X POST http://localhost:8000/api/v1/remediation/scan-and-remediate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "host-xyz789",
    "scan_config_id": "cfg-abc123",
    "remediation_type": "ansible"
  }'
```

### 3. Backend Generates Tailoring File

```xml
<!-- /tmp/remediation_host-xyz789_cfg-abc123/tailoring.xml -->
<Tailoring>
  <Profile id="xccdf_org.ssgproject.content_profile_stig_customized">
    <extends idref="xccdf_org.ssgproject.content_profile_stig"/>
    <set-value idref="xccdf_org.ssgproject.content_value_var_accounts_tmout">1800</set-value>
    <set-value idref="xccdf_org.ssgproject.content_value_var_password_pam_minlen">15</set-value>
    <set-value idref="xccdf_org.ssgproject.content_value_login_banner_text">ACME Corp - Authorized Users Only</set-value>
  </Profile>
</Tailoring>
```

### 4. Backend Executes OSCAP

```bash
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig_customized \
  --tailoring-file /tmp/remediation_host-xyz789_cfg-abc123/tailoring.xml \
  --remediate \
  --remediation-type ansible \
  --results-arf /tmp/remediation_host-xyz789_cfg-abc123/results.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
```

### 5. OSCAP Injects Variables into Ansible

Original Ansible task from ComplianceAsCode:
```yaml
# From /usr/share/scap-security-guide/ansible/accounts_tmout.yml
- name: Set Account Inactivity Timeout
  lineinfile:
    path: /etc/profile
    regexp: '^TMOUT='
    line: "TMOUT={{ var_accounts_tmout }}"  # Variable placeholder
```

OSCAP resolves `{{ var_accounts_tmout }}` to `1800` from tailoring file:
```yaml
# Executed by OSCAP
- name: Set Account Inactivity Timeout
  lineinfile:
    path: /etc/profile
    regexp: '^TMOUT='
    line: "TMOUT=1800"  # Custom value from user
```

### 6. Results Returned to User

```json
{
  "success": true,
  "data": {
    "scan_id": "scan-def456",
    "rules_evaluated": 150,
    "rules_passed": 120,
    "rules_failed": 30,
    "remediation_actions": [
      {
        "rule_id": "xccdf_org.ssgproject.content_rule_accounts_tmout",
        "system": "urn:xccdf:fix:script:ansible",
        "complexity": "low",
        "disruption": "low",
        "success": true,
        "details": "Set TMOUT=1800 in /etc/profile"
      },
      {
        "rule_id": "xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_systemauth",
        "system": "urn:xccdf:fix:script:ansible",
        "complexity": "low",
        "disruption": "low",
        "success": true
      }
    ],
    "success_rate": 0.80,
    "report_url": "/api/v1/reports/scan-def456/html"
  }
}
```

## Advantages of Solution A for Remediation

### ✅ Native OSCAP Integration
- No custom variable substitution code needed
- OSCAP handles all variable resolution
- Standard XCCDF tailoring mechanism

### ✅ Reliability
- Proven, battle-tested approach
- Used by Red Hat, DISA, NSA
- Extensive upstream testing

### ✅ Flexibility
- Any variable can be customized
- Supports all XCCDF variable types (string, number, boolean)
- Works with all remediation types (Ansible, Bash, Puppet)

### ✅ Maintainability
- Upstream remediation scripts work unchanged
- Easy to sync new content from ComplianceAsCode
- No OpenWatch-specific modifications to remediation code

### ✅ Auditability
- Tailoring files provide audit trail
- Shows exactly what was customized
- Can reproduce scans with same tailoring file

### ✅ Standards Compliance
- XCCDF 1.2 tailoring is standard mechanism
- Compatible with other SCAP tools
- Exportable tailoring files

## Solution C Problems for Remediation

### ❌ Variable Binding Lost
```python
# Solution C pre-renders everything
"remediation": {
  "ansible": "lineinfile: line='TMOUT=600'"  # Hardcoded 600
}

# User wants 900 - OpenWatch must:
# 1. Detect that variable changed
# 2. Find original template
# 3. Re-render with new value
# 4. Generate custom Ansible playbook
# 5. Execute custom playbook instead of upstream one
```

### ❌ Complexity Explosion
- Must maintain rendered versions for every variable combination
- 10 customizable variables = 1024 possible combinations
- 20 customizable variables = 1,048,576 combinations
- Impractical to pre-render all possibilities

### ❌ Upstream Sync Issues
- ComplianceAsCode updates remediation scripts frequently
- Must re-render all custom variations on every update
- Easy to get out of sync

### ❌ Non-Standard Approach
- Custom OpenWatch-specific mechanism
- Not compatible with standard SCAP tools
- Can't export/import tailoring files

## Recommendation

**Use Solution A for remediation support.** It provides:

1. **Maximum reliability**: Native OSCAP integration, no custom variable substitution
2. **Maximum flexibility**: Any variable can be customized at scan time
3. **Maintainability**: Upstream remediation scripts work unchanged
4. **Standards compliance**: Standard XCCDF tailoring mechanism
5. **Auditability**: Clear audit trail of customizations

Solution C adds complexity without providing remediation benefits. The "performance optimization" of pre-rendering is irrelevant for remediation, since:
- Remediation is infrequent (typically once per host after initial scan)
- Variable substitution overhead is negligible compared to actual remediation time
- OSCAP handles variable injection efficiently

## Next Steps

1. Implement `XCCDFTailoringGenerator` class
2. Enhance `ComplianceRule` model with `xccdf_variables` field
3. Update converter to extract variable metadata
4. Implement `RemediationService` with tailoring support
5. Create API endpoints for scan-and-remediate
6. Build UI for variable customization
7. Test with real OSCAP remediation on test hosts

---
*Last updated: 2025-10-14*
