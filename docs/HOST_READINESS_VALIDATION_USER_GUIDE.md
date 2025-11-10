# Host Readiness Validation - User Guide

**Feature**: Pre-flight Validation System
**Version**: 1.0
**Date**: 2025-11-09
**Status**: Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [What is Host Readiness Validation?](#what-is-host-readiness-validation)
3. [When to Use Readiness Validation](#when-to-use-readiness-validation)
4. [Validation Checks Explained](#validation-checks-explained)
5. [How to Run Validation](#how-to-run-validation)
6. [Understanding Validation Results](#understanding-validation-results)
7. [Troubleshooting Failed Checks](#troubleshooting-failed-checks)
8. [Best Practices](#best-practices)
9. [Technical Details](#technical-details)

---

## Overview

Host Readiness Validation is OpenWatch's pre-flight check system that verifies whether target hosts are properly configured and ready for compliance scanning. Running validation **before** executing expensive SCAP scans saves time, compute resources, and prevents scan failures due to misconfiguration.

**Key Benefits**:
- Prevents failed scans due to connectivity/authentication issues
- Identifies missing dependencies (OpenSCAP, Python, required packages)
- Validates system configurations (SELinux, memory, permissions)
- Provides actionable remediation guidance
- Supports bulk validation of multiple hosts simultaneously

---

## What is Host Readiness Validation?

Readiness validation performs a comprehensive series of checks against target hosts to ensure they meet all prerequisites for successful SCAP compliance scanning.

### Validation Categories

1. **Connectivity Checks** (Network reachability)
   - ICMP ping test
   - TCP port accessibility
   - Network latency measurement

2. **SSH Authentication** (Credential validation)
   - SSH key/password authentication
   - Sudo privilege verification
   - Session establishment

3. **Dependency Checks** (Required software)
   - OpenSCAP scanner installation
   - Python interpreter availability
   - Required system utilities

4. **Configuration Validation** (System settings)
   - SELinux policy compliance
   - Available memory/disk space
   - File system permissions

---

## When to Use Readiness Validation

### Recommended Use Cases

**Before Initial Scan Setup**:
- After adding new hosts to OpenWatch
- Before scheduling recurring scan jobs
- When deploying to new environments

**Troubleshooting Scan Failures**:
- Investigate why a scan failed
- Verify fixes after configuration changes
- Confirm credentials still work

**Infrastructure Changes**:
- After network reconfiguration
- Following security policy updates
- Post OS upgrades or patching

**Compliance Audits**:
- Verify scanning infrastructure health
- Document host configuration status
- Generate readiness reports

### When NOT to Use

- **During Active Scans**: Validation adds overhead; wait for scans to complete
- **Known Good Hosts**: If recent validation passed and nothing changed
- **Emergency Scanning**: Skip validation if immediate results needed (use with caution)

---

## Validation Checks Explained

### 1. Connectivity Checks

#### ICMP Ping Test
- **Purpose**: Verify host is online and network-reachable
- **Pass Criteria**: Host responds to ICMP echo request within 2 seconds
- **Severity**: ERROR (scan cannot proceed if host unreachable)

**Example Output**:
```
Check: ICMP Ping Test
Status: PASS
Message: Host is reachable via ICMP
Details:
  - Latency: 12.34ms
  - Packet Loss: 0%
```

#### TCP Port Connectivity
- **Purpose**: Verify SSH port (22) is accessible
- **Pass Criteria**: TCP connection established to port 22
- **Severity**: ERROR (SSH required for scanning)

**Example Output**:
```
Check: TCP Port 22 Accessibility
Status: PASS
Message: SSH port is accessible
Details:
  - Port: 22
  - Response Time: 45ms
```

---

### 2. SSH Authentication

#### SSH Connection Test
- **Purpose**: Validate credentials and establish authenticated session
- **Pass Criteria**: Successfully authenticate with provided credentials
- **Severity**: ERROR (authentication required for remote scanning)

**Example Output**:
```
Check: SSH Authentication
Status: PASS
Message: SSH authentication successful
Details:
  - Authentication Method: publickey
  - Protocol: SSH-2.0
  - Cipher: aes256-gcm@openssh.com
```

#### Sudo Privilege Check
- **Purpose**: Verify user has sudo access (required for SCAP scanning)
- **Pass Criteria**: Can execute commands with sudo (passwordless preferred)
- **Severity**: ERROR (many SCAP checks require root privileges)

**Example Output**:
```
Check: Sudo Privileges
Status: PASS
Message: User has passwordless sudo access
Details:
  - Sudo Method: NOPASSWD
  - Test Command: sudo -n whoami
  - Result: root
```

---

### 3. Dependency Checks

#### OpenSCAP Scanner
- **Purpose**: Verify oscap binary is installed
- **Pass Criteria**: `oscap --version` executes successfully
- **Severity**: ERROR (oscap is required for scanning)

**Example Output**:
```
Check: OpenSCAP Scanner Installation
Status: PASS
Message: OpenSCAP scanner is installed
Details:
  - Version: 1.3.12
  - Path: /usr/bin/oscap
  - Features: OVAL, XCCDF, DataStream
```

**Remediation (if failed)**:
```bash
# RHEL/CentOS/Rocky Linux
sudo yum install -y openscap-scanner

# Ubuntu/Debian
sudo apt-get install -y libopenscap8

# Verify installation
oscap --version
```

#### Python Interpreter
- **Purpose**: Verify Python 3 is available (used by some SCAP checks)
- **Pass Criteria**: `python3 --version` succeeds
- **Severity**: WARNING (most scans work without Python, but some checks may fail)

**Example Output**:
```
Check: Python Interpreter
Status: PASS
Message: Python 3 is available
Details:
  - Version: 3.9.16
  - Path: /usr/bin/python3
```

---

### 4. Configuration Validation

#### SELinux Policy Check
- **Purpose**: Verify SELinux is configured correctly
- **Pass Criteria**: SELinux is enforcing or permissive (not disabled)
- **Severity**: WARNING (some SCAP profiles require SELinux)

**Example Output**:
```
Check: SELinux Configuration
Status: PASS
Message: SELinux is in enforcing mode
Details:
  - Mode: enforcing
  - Policy: targeted
  - Status: enabled
```

**Remediation (if disabled)**:
```bash
# Enable SELinux (requires reboot)
sudo vi /etc/selinux/config
# Set: SELINUX=enforcing

sudo reboot

# Verify after reboot
getenforce  # Should return "Enforcing"
```

#### Memory Availability
- **Purpose**: Ensure sufficient RAM for SCAP scanning
- **Pass Criteria**: At least 512MB of free memory available
- **Severity**: WARNING (scans may be slow or fail with low memory)

**Example Output**:
```
Check: Available Memory
Status: PASS
Message: Sufficient memory available for scanning
Details:
  - Total Memory: 8192 MB
  - Available Memory: 4096 MB
  - Free Memory: 2048 MB
  - Threshold: 512 MB
```

---

## How to Run Validation

### Option 1: Single Host Validation (Web UI)

#### From Hosts Page

1. Navigate to **Hosts** in the sidebar
2. Locate the host you want to validate
3. Click the **Actions** dropdown for that host
4. Select **Validate Readiness**
5. View results in the modal dialog

#### From Host Detail Page

1. Navigate to **Hosts** and click on a hostname
2. In the Actions Bar (top-right), click **Validate Readiness**
3. View results in the modal dialog

#### From Scans Page (Before Running Scan)

1. Navigate to **Scans** in the sidebar
2. Click the **Validate Readiness** button in the Actions Bar
3. Select one or more hosts from the list
4. Click **Validate Selected Hosts**
5. View results for each host

---

### Option 2: Bulk Validation (Multiple Hosts)

#### Validate All Hosts

1. Navigate to **Scans** page
2. Click **Validate Readiness** button
3. Click **Validate All Hosts**
4. Wait for parallel validation to complete
5. Review aggregated results

**Performance Note**: Bulk validation runs in parallel (up to 5 hosts simultaneously) for faster results.

#### Validate Specific Hosts

1. Navigate to **Scans** page
2. Click **Validate Readiness** button
3. Select hosts from the checkbox list
4. Click **Validate Selected Hosts** (bottom of dialog)
5. View per-host results

---

### Option 3: API Integration

#### Single Host Validation

```bash
# Validate single host (uses cache if available)
curl -X POST https://openwatch.example.com/api/v1/scans/readiness/validate-bulk \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host_ids": ["550e8400-e29b-41d4-a716-446655440000"],
    "parallel": false,
    "use_cache": true,
    "cache_ttl_hours": 1
  }'
```

#### Bulk Validation (All Hosts)

```bash
# Validate all hosts in parallel
curl -X POST https://openwatch.example.com/api/v1/scans/readiness/validate-bulk \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host_ids": [],
    "parallel": true,
    "use_cache": true,
    "cache_ttl_hours": 24
  }'
```

**API Response Example**:
```json
{
  "hosts": [
    {
      "host_id": "550e8400-e29b-41d4-a716-446655440000",
      "hostname": "web-server-01",
      "ip_address": "192.168.1.100",
      "status": "ready",
      "overall_passed": true,
      "checks": [
        {
          "check_type": "connectivity",
          "check_name": "ICMP Ping Test",
          "passed": true,
          "severity": "info",
          "message": "Host is reachable via ICMP",
          "details": {"latency_ms": 12.34},
          "check_duration_ms": 50.0
        }
      ],
      "total_checks": 10,
      "passed_checks": 10,
      "failed_checks": 0,
      "warnings_count": 0,
      "validation_duration_ms": 2345.6,
      "completed_at": "2025-11-09T14:23:00Z"
    }
  ]
}
```

---

## Understanding Validation Results

### Validation Status

| Status | Icon | Meaning | Action Required |
|--------|------|---------|-----------------|
| **READY** | Green Checkmark | All checks passed | Proceed with scanning |
| **DEGRADED** | Yellow Warning | Some non-critical checks failed | Review warnings, may proceed |
| **NOT_READY** | Red X | Critical checks failed | Must fix issues before scanning |

### Check Severity Levels

| Severity | Impact | Scanning Possible? |
|----------|--------|--------------------|
| **ERROR** | Critical - scan will fail | No |
| **WARNING** | Non-critical - scan may succeed with limitations | Yes (with caution) |
| **INFO** | Informational only | Yes |

---

### Interpreting Results

#### Scenario 1: All Checks Pass (READY)

```
Status: READY
Overall: PASS
Checks: 10/10 passed, 0 failed, 0 warnings
```

**Action**: Proceed with SCAP scanning. Host is fully configured.

---

#### Scenario 2: Non-Critical Warnings (DEGRADED)

```
Status: DEGRADED
Overall: PASS (with warnings)
Checks: 8/10 passed, 0 failed, 2 warnings

Warnings:
- Python Interpreter: Not found (some checks may fail)
- Available Memory: Only 400MB free (below 512MB threshold)
```

**Action**: Review warnings. Scans will likely succeed but:
- Python-based SCAP checks may fail
- Scan performance may be degraded with low memory

**Recommendation**: Fix warnings before production scanning.

---

#### Scenario 3: Critical Failures (NOT_READY)

```
Status: NOT_READY
Overall: FAIL
Checks: 6/10 passed, 4 failed, 0 warnings

Failed Checks:
- OpenSCAP Scanner: Not installed
- SSH Authentication: Permission denied
- Sudo Privileges: User lacks sudo access
- SELinux: Disabled
```

**Action**: **DO NOT SCAN**. Must resolve all ERROR-level failures first.

**Remediation Steps**:
1. Install OpenSCAP: `yum install openscap-scanner`
2. Fix SSH credentials in Host settings
3. Grant sudo access: Add user to sudoers
4. Enable SELinux: Edit `/etc/selinux/config`

---

## Troubleshooting Failed Checks

### Connectivity Failures

#### ICMP Ping Fails
**Symptom**: "Host unreachable"

**Possible Causes**:
- Host is offline or powered down
- Firewall blocking ICMP packets
- Incorrect IP address configured
- Network routing issues

**Resolution**:
```bash
# Test manually from OpenWatch server
ping -c 3 192.168.1.100

# Check firewall (on target host)
sudo firewall-cmd --list-all | grep icmp

# Allow ICMP (if blocked)
sudo firewall-cmd --add-service=icmp --permanent
sudo firewall-cmd --reload
```

---

#### SSH Port Not Accessible
**Symptom**: "Connection refused on port 22"

**Possible Causes**:
- SSH service not running
- Firewall blocking port 22
- SSH listening on non-standard port

**Resolution**:
```bash
# Check SSH service status
sudo systemctl status sshd

# Start SSH if stopped
sudo systemctl start sshd
sudo systemctl enable sshd

# Check firewall
sudo firewall-cmd --list-services | grep ssh

# Allow SSH port
sudo firewall-cmd --add-service=ssh --permanent
sudo firewall-cmd --reload

# Verify SSH listening
sudo ss -tlnp | grep :22
```

---

### Authentication Failures

#### SSH Authentication Denied
**Symptom**: "Permission denied (publickey,password)"

**Possible Causes**:
- Incorrect username/password
- SSH key not authorized
- Account locked or expired
- SSH configured to deny password auth

**Resolution**:
```bash
# Test credentials manually
ssh user@192.168.1.100

# For key-based auth, verify key is authorized
cat ~/.ssh/authorized_keys | grep <public_key_content>

# Check SSH daemon config
sudo grep -E "PubkeyAuthentication|PasswordAuthentication" /etc/ssh/sshd_config

# Restart SSH after config changes
sudo systemctl restart sshd
```

**Update Credentials in OpenWatch**:
1. Navigate to **Hosts** page
2. Click on the affected host
3. Click **Edit Host** button
4. Update credentials in **SSH Configuration** section
5. Save and re-run validation

---

#### Sudo Access Denied
**Symptom**: "User lacks sudo privileges"

**Possible Causes**:
- User not in sudoers file
- Sudo requires password (passwordless needed for automated scans)
- Sudo command restricted

**Resolution**:
```bash
# Add user to sudoers (as root)
echo "scanuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/scanuser
chmod 0440 /etc/sudoers.d/scanuser

# Verify sudo access
sudo -l -U scanuser

# Test passwordless sudo
sudo -n whoami  # Should return "root" without password prompt
```

---

### Dependency Failures

#### OpenSCAP Not Installed
**Symptom**: "oscap: command not found"

**Resolution**:
```bash
# RHEL/CentOS/Rocky Linux 8+
sudo dnf install -y openscap-scanner

# RHEL/CentOS 7
sudo yum install -y openscap-scanner

# Ubuntu 20.04+
sudo apt-get update
sudo apt-get install -y libopenscap8

# Debian 11+
sudo apt-get update
sudo apt-get install -y libopenscap-utils

# Verify installation
oscap --version
```

---

#### Python Not Available
**Symptom**: "python3: command not found"

**Resolution**:
```bash
# RHEL/CentOS/Rocky Linux
sudo dnf install -y python3

# Ubuntu/Debian
sudo apt-get install -y python3

# Verify installation
python3 --version
```

---

### Configuration Failures

#### SELinux Disabled
**Symptom**: "SELinux is disabled"

**Why It Matters**: Many STIG and CIS controls require SELinux enforcing mode.

**Resolution**:
```bash
# Edit SELinux config
sudo vi /etc/selinux/config

# Change from:
SELINUX=disabled

# To:
SELINUX=enforcing

# Save and reboot (SELinux mode change requires reboot)
sudo reboot

# After reboot, verify
getenforce  # Should return "Enforcing"
sestatus    # Shows detailed status
```

**Warning**: Enabling SELinux may cause application issues if policies not configured correctly. Test in non-production first.

---

#### Insufficient Memory
**Symptom**: "Available memory below threshold (512MB)"

**Resolution**:
```bash
# Check current memory usage
free -h

# Identify memory hogs
ps aux --sort=-%mem | head -10

# Stop unnecessary services
sudo systemctl stop <service_name>

# Consider increasing RAM allocation (VM/container)
# Or run scans during off-peak hours
```

---

## Best Practices

### 1. Run Validation Before First Scan
Always validate new hosts before adding them to scan schedules. This prevents recurring scan failures.

### 2. Use Caching Appropriately
- **Pre-flight checks (before scan)**: 1-hour cache TTL
- **Bulk validation (monitoring)**: 24-hour cache TTL
- **After configuration changes**: Bypass cache (set TTL to 0)

### 3. Address Warnings Proactively
Even if status is DEGRADED, fix WARNING-level issues to ensure optimal scan results.

### 4. Automate Validation
Integrate validation into CI/CD pipelines or scheduled jobs:

```bash
#!/bin/bash
# validate-before-scan.sh

TOKEN="your-api-token"
HOST_ID="550e8400-e29b-41d4-a716-446655440000"

# Run validation
RESULT=$(curl -s -X POST https://openwatch.example.com/api/v1/scans/readiness/validate-bulk \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"host_ids\": [\"$HOST_ID\"], \"use_cache\": false}")

STATUS=$(echo $RESULT | jq -r '.hosts[0].status')

if [ "$STATUS" != "ready" ]; then
  echo "Host not ready for scanning. Status: $STATUS"
  echo $RESULT | jq '.hosts[0].checks[] | select(.passed == false)'
  exit 1
fi

echo "Host ready. Proceeding with scan..."
# Trigger scan here
```

### 5. Document Baseline Configuration
After successful validation, document the host configuration as a baseline for future reference.

---

## Technical Details

### Validation Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                  Validation Request                          │
│  (User clicks "Validate Readiness" or API POST)             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  Check Cache         │
            │  (TTL: 1h or 24h)    │
            └──────┬───────────────┘
                   │
          ┌────────┴────────┐
          │ Cache Hit?      │
          └────┬────────┬───┘
          YES  │        │  NO
               │        │
               ▼        ▼
     ┌─────────────┐  ┌────────────────────────┐
     │ Return      │  │  Execute Validation    │
     │ Cached      │  │  Checks (live)         │
     │ Result      │  └─────────┬──────────────┘
     └─────────────┘            │
                                ▼
                    ┌────────────────────────┐
                    │  1. Connectivity       │
                    │     - ICMP Ping        │
                    │     - TCP Port 22      │
                    └─────────┬──────────────┘
                              ▼
                    ┌────────────────────────┐
                    │  2. SSH Auth           │
                    │     - Authenticate     │
                    │     - Test sudo        │
                    └─────────┬──────────────┘
                              ▼
                    ┌────────────────────────┐
                    │  3. Dependencies       │
                    │     - oscap version    │
                    │     - Python version   │
                    └─────────┬──────────────┘
                              ▼
                    ┌────────────────────────┐
                    │  4. Configuration      │
                    │     - SELinux status   │
                    │     - Memory available │
                    └─────────┬──────────────┘
                              ▼
                    ┌────────────────────────┐
                    │  Aggregate Results     │
                    │  - Calculate status    │
                    │  - Store in database   │
                    └─────────┬──────────────┘
                              ▼
                    ┌────────────────────────┐
                    │  Return to User        │
                    │  (Web UI or API)       │
                    └────────────────────────┘
```

---

### Caching Strategy

**Purpose**: Avoid redundant validation checks that add latency and load.

**Cache Levels**:

| Use Case | TTL | Reasoning |
|----------|-----|-----------|
| Pre-flight (before scan) | 1 hour | Configurations may change; ensure fresh validation |
| Bulk validation (monitoring) | 24 hours | Infrastructure relatively stable; reduce overhead |
| Post-configuration change | 0 (bypass cache) | Verify fixes immediately |

**Cache Invalidation**:
- Automatic expiration based on TTL
- Manual bypass via API (`use_cache: false`)
- Host credential updates invalidate cache for that host

---

### Performance Characteristics

**Single Host Validation**:
- Average duration: 2-5 seconds
- Network-dependent (ping, SSH handshake)
- Fastest with cached credentials

**Bulk Validation (10 hosts)**:
- Sequential: 20-50 seconds
- Parallel (5 workers): 5-10 seconds
- Scales linearly with host count

**Database Impact**:
- Validation results stored in PostgreSQL (`host_readiness_validations` table)
- Check details stored separately (`host_readiness_checks` table)
- Automatic cleanup after 90 days (configurable)

---

### Security Considerations

**Credential Handling**:
- Credentials encrypted at rest (AES-256-GCM)
- Credentials decrypted only in memory during validation
- SSH sessions closed immediately after validation

**Audit Logging**:
- All validation attempts logged with user ID
- Failed authentication attempts logged separately
- Logs retained per compliance requirements (90+ days)

**Network Security**:
- Validation traffic encrypted (SSH protocol)
- No plaintext credentials transmitted
- Respects host firewall rules

---

## Related Documentation

- [Advanced Scanning Architecture](ADVANCED_SCANNING_ARCHITECTURE.md) - Full SCAP scanning workflow
- [Host SSH Validation Implementation](HOST_SSH_VALIDATION_IMPLEMENTATION.md) - Original SSH validation (predecessor)
- [Adaptive Scheduler Implementation](ADAPTIVE_SCHEDULER_IMPLEMENTATION_COMPLETE.md) - Automated scan scheduling

---

## Support

For issues or questions:
1. Check [Troubleshooting](#troubleshooting-failed-checks) section above
2. Review [OpenWatch CLAUDE.md](../CLAUDE.md) for development details
3. Open a GitHub issue with validation results and error logs

---

**Document Version**: 1.0
**Last Updated**: 2025-11-09
**Maintained By**: OpenWatch Development Team
