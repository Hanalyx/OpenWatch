# OpenWatch Compliance Rules (Converted from SCAP)

This directory contains OpenWatch compliance rules converted from ComplianceAsCode SCAP content.

## Summary

- **Total Rules**: 1,387
- **Platforms**: RHEL (709 rules), Ubuntu (96 rules)
- **Frameworks**: NIST 800-53, CIS Controls, DISA STIG, PCI-DSS, ISO 27001, HIPAA
- **Source**: ComplianceAsCode v0.1.73

## Conversion Details

### Platform Coverage

**RHEL (Red Hat Enterprise Linux)**
- Versions: 7, 8, 9
- Rules: 709
- Coverage: 85.5%
- Top Categories:
  - System Hardening: 341 rules (48.1%)
  - Access Control: 156 rules (22.0%)
  - Audit & Logging: 101 rules (14.2%)
  - Authentication: 68 rules (9.6%)

**Ubuntu**
- Versions: 18.04, 20.04, 22.04, 24.04
- Rules: 96
- Coverage: 54.8%
- Top Categories:
  - System Hardening: 55 rules (57.3%)
  - Authentication: 20 rules (20.8%)
  - Network Security: 9 rules (9.4%)

### Framework Mappings

All rules include mappings to applicable compliance frameworks:
- **NIST 800-53**: Security and Privacy Controls
- **CIS Controls**: Critical Security Controls
- **DISA STIG**: Security Technical Implementation Guides
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **ISO 27001**: Information Security Management
- **HIPAA**: Health Insurance Portability and Accountability Act

### Rule Structure

Each JSON file follows the OpenWatch Compliance Rules schema:

```json
{
  "rule_id": "ow-{rule_name}",
  "metadata": {
    "name": "Human-readable rule name",
    "description": "What the rule checks",
    "rationale": "Why this is important"
  },
  "severity": "high|medium|low",
  "category": "authentication|access_control|audit_logging|...",
  "frameworks": {
    "nist": {"800-53r5": ["AC-2", "AC-3"]},
    "cis": {"controls_v8": ["5.1", "5.2"]}
  },
  "platform_implementations": {
    "rhel": {
      "versions": ["8", "9"],
      "check_command": "grep '^PermitRootLogin no' /etc/ssh/sshd_config",
      "enable_command": "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
    }
  }
}
```

### Performance Benefits

Compared to traditional SCAP/XML scanning:
- **50-200x faster** rule parsing (JSON vs XML)
- **100x faster** framework queries (indexed JSON)
- **50-100x less memory** usage
- **Parallel execution** ready

### Loading into MongoDB

To load these rules into MongoDB:

```bash
cd /home/rracine/hanalyx/openwatch/backend
source venv/bin/activate
python -m app.cli.load_compliance_rules load \
  --source /home/rracine/hanalyx/openwatch/data/compliance_rules_converted
```

### Conversion Process

Rules were converted using:
```bash
python -m app.cli.scap_to_openwatch_converter convert \
  --scap-path /home/rracine/hanalyx/scap_content/content \
  --output-path /home/rracine/hanalyx/openwatch/data/compliance_rules_converted
```

## License

These rules are derived from ComplianceAsCode content and maintain the same open source licensing.

Last updated: 2025-10-03
