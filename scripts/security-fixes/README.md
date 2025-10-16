# Security Fixes Application Scripts

This directory contains automated scripts for applying security fixes identified in the comprehensive security assessment conducted on October 15, 2025.

## Quick Start

```bash
# Navigate to OpenWatch root
cd /home/rracine/hanalyx/openwatch

# Run in check-only mode first (no changes)
./scripts/security-fixes/apply-critical-fixes.sh --check-only

# Apply fixes
./scripts/security-fixes/apply-critical-fixes.sh
```

## What Gets Fixed

### Critical Issues
1. **Outdated cryptography library** (CVE-2024-26130)
2. **Outdated PyJWT** (CVE-2024-33663)
3. **Outdated Pillow** (CVE-2024-28219)
4. **Outdated requests** (CVE-2024-35195)
5. **Outdated PyYAML** (CVE-2024-11167)
6. **Outdated Jinja2** (CVE-2024-34064)
7. **Secure secret generation**

### Manual Fixes Required

The following issues require manual code changes (see SECURITY_ASSESSMENT_COMPLETE.md):

1. **Hardcoded secrets** in source code (3 files)
2. **MD5 hash usage** (3 files)
3. **Insecure random number generation** (1 file)

## Full Security Assessment

See the complete security assessment report:
```
/home/rracine/hanalyx/openwatch/SECURITY_ASSESSMENT_COMPLETE.md
```

## Additional Reports

- **Hardcoded Secrets:** SECURITY_SCAN_REPORT.md
- **Cryptography & Dependencies:** SECURITY_AUDIT_REPORT.md
- **API Security:** SECURITY_AUDIT_API_2025.md
- **Executive Summary:** SECURITY_FINDINGS_SUMMARY.md

## Contact

For questions about security fixes, refer to the comprehensive assessment report or contact the security team.

**Last Updated:** October 15, 2025
