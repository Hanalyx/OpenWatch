# Host Management and Remediation

This guide covers adding and managing hosts, organizing them into groups,
understanding server intelligence data, and using automated remediation to fix
compliance findings. Most of these tasks are performed in the web UI.

---

## Adding a Host

### From the UI

1. Navigate to **Hosts** in the left sidebar.
2. Click **Add Host**.
3. Fill in the host details:

| Field | Required | Example |
|-------|----------|---------|
| Hostname | Yes | `web-01` |
| IP Address | Yes | `192.168.1.10` |
| SSH Port | Yes | `22` |
| Display Name | No | `Web Server 01` |
| Operating System | No | `RHEL 9` |
| Environment | No | `production` |

4. Click **Save**.

![Add Host dialog](../images/hosts/add-host.png)

The host appears in the host list immediately after creation.

### Bulk Import

For adding many hosts at once:

1. Navigate to **Hosts** and click **Bulk Import**.
2. Download the CSV template.
3. Fill in the template with your host data.
4. Upload the CSV file.
5. Review the auto-detected field mappings.
6. Confirm the import.

![Bulk import CSV mapping review](../images/hosts/bulk-import.png)

Set **Dry Run** to validate the file without creating hosts. Set **Update
Existing** to overwrite hosts that match by hostname or IP address.

---

## Configuring SSH Credentials

OpenWatch connects to hosts over SSH to run compliance checks. No agent is
installed on target hosts.

### From the UI

1. Navigate to the host detail page.
2. Go to the **Credentials** section.
3. Select an authentication method:

| Method | When to Use |
|--------|-------------|
| **SSH Key** (recommended) | Paste or upload the private key. Stored encrypted. |
| **Password** | Enter the SSH password. Stored encrypted with AES-256-GCM. |
| **System Default** | Uses the credential configured in Settings > System Credentials. |

4. Enter the SSH username.
5. Click **Save**.

![Credential configuration form](../images/hosts/credentials.png)

### Testing Connectivity

After saving credentials, click **Test Connection** to verify that OpenWatch
can reach the host via SSH. The test checks:

- Network reachability
- SSH port availability
- Authentication success

Fix any connection issues before running a scan.

### System Credentials

For organizations where all hosts share the same SSH credentials, configure a
system-wide default:

1. Go to **Settings > System Credentials**.
2. Add the shared SSH key or password.
3. When adding hosts, select **System Default** as the auth method.

### Credential Security

All credentials are encrypted with AES-256-GCM before being stored in the
database. Decryption happens only at scan time, in memory. Plaintext credentials
are never written to disk or logs.

---

## Host Groups

Host groups let you organize hosts into logical collections for group-level
compliance reporting and batch scanning.

### Creating a Group

1. Navigate to **Host Groups** in the sidebar.
2. Click **Create Group**.
3. Enter a name, description, OS family, and compliance framework.
4. Click **Save**.

![Create host group dialog](../images/hosts/create-group.png)

### Assigning Hosts

1. Open the group detail page.
2. Click **Add Hosts**.
3. Select hosts from the list.
4. Click **Confirm**.

Each host can belong to one group at a time.

### Smart Group Creation

Select multiple hosts and click **Smart Group**. OpenWatch analyzes their OS,
architecture, and compliance profile to recommend group settings automatically.

### Group Scanning

From the group detail page, click **Scan Group** to start a compliance scan
for all hosts in the group simultaneously. Monitor progress on the group's
scan session page.

---

## Host Discovery

### OS Detection

OpenWatch automatically detects the operating system for hosts during scans.
You can also trigger manual OS discovery from the host detail page by clicking
**Discover OS**.

A scheduled task runs daily at 02:00 UTC to discover the OS for all active
hosts that have not been identified yet.

### Connectivity Monitoring

Host connectivity is checked every 30 seconds automatically. Each check
verifies ICMP reachability, SSH port availability, and SSH authentication.
Host status (online, offline, degraded) updates in the host list.

---

## Server Intelligence

During compliance scans, OpenWatch collects detailed information about each host.
This data is available on the host detail page under the **Intelligence** tab.

![Server intelligence overview](../images/hosts/server-intelligence.png)

### Data Collected

| Category | What It Contains |
|----------|------------------|
| Packages | Installed packages, versions, sources |
| Services | Running services, listening ports, enabled state |
| Users | User accounts, groups, shell, last login |
| Network | Interfaces, IP addresses, firewall rules |

### System Information

The host detail page also shows:

- OS name, version, and kernel release
- CPU model, core count, and architecture
- Total and available memory
- SELinux or AppArmor status
- Firewall status and active service

This data helps operators understand the security surface of each host without
needing to SSH in manually.

---

## Remediation Overview

OpenWatch can automatically fix compliance findings through Kensa's 23
remediation mechanisms. All changes are made over SSH -- nothing is installed
on target hosts.

### What Remediation Can Fix

| Category | Examples |
|----------|----------|
| Boot configuration | GRUB settings, boot parameters |
| Authentication | PAM modules, password policies |
| Filesystem | fstab mount options, file permissions |
| Kernel | sysctl parameters, module blacklisting |
| Services | systemd service management, cron restrictions |
| Audit | auditd rules, log configuration |
| Network | SSH daemon settings, firewall rules |

---

## Starting a Remediation

### From the UI

1. Navigate to the host detail page and view the scan results.
2. Select the failing findings you want to remediate (use checkboxes).
3. Click **Remediate Selected**.

![Selecting findings for remediation](../images/hosts/select-remediation.png)

4. Review the proposed changes. Each finding shows what will be modified.
5. Click **Start Remediation** to confirm.

![Remediation confirmation dialog](../images/hosts/confirm-remediation.png)

For organizations that require approval workflows:

1. Select findings and click **Request Remediation**.
2. Enter a justification for the changes.
3. An admin reviews and approves the request.
4. Once approved, the remediation executes automatically.

---

## Monitoring Remediation Progress

After starting a remediation, track its progress on the host detail page
under the **Remediation** tab.

![Remediation progress view](../images/hosts/remediation-progress.png)

The progress view shows:

- **Job status**: pending, running, completed, failed, partial, cancelled
- **Progress percentage**: how many rules have been processed
- **Per-rule results**: which fixes succeeded, failed, or were skipped
- **Execution log**: timestamps and details for each step

---

## Rollback

Pre-state snapshots are captured automatically before any remediation changes.
If a remediation causes problems, you can roll back to the pre-change state.

### From the UI

1. Go to the **Remediation** tab on the host detail page.
2. Find the remediation job you want to roll back.
3. Click **Rollback**.
4. Enter a reason for the rollback (logged for audit purposes).
5. Click **Confirm Rollback**.

![Rollback confirmation](../images/hosts/rollback.png)

Rollback requires SUPER_ADMIN or SECURITY_ADMIN role (scan:rollback permission).

### After Rolling Back

After a rollback completes, run a follow-up compliance scan to verify the host
returned to its previous state.

---

## Required Permissions

| Operation | Minimum Role |
|-----------|-------------|
| View hosts | GUEST |
| Add / edit / delete hosts | SECURITY_ANALYST |
| Bulk import / export | SUPER_ADMIN, SECURITY_ADMIN |
| Start remediation | SECURITY_ADMIN (scan:execute) |
| Approve remediation | SUPER_ADMIN (scan:approve) |
| Rollback remediation | SUPER_ADMIN, SECURITY_ADMIN (scan:rollback) |
| View server intelligence | SECURITY_ANALYST |
| Manage host groups | SECURITY_ANALYST |

---

## Best Practices

1. **Test credentials before scanning.** Use the Test Connection button to
   confirm SSH access before running a compliance scan.
2. **Use SSH keys, not passwords.** Key-based authentication is more secure
   and works reliably with automated scanning.
3. **Start remediation on a single host.** Test changes on one host before
   applying to a group.
4. **Review findings before remediating.** Understand what each rule checks
   and what the fix changes.
5. **Monitor compliance score after remediation.** The adaptive scheduler will
   automatically scan again, but you can force a scan for immediate results.
6. **Use groups for consistent scanning.** Hosts in the same group share OS
   family, framework, and scan schedule settings.

---

## What's Next

- [Scanning and Compliance](SCANNING_AND_COMPLIANCE.md) -- understanding scan results and posture
- [User Roles](USER_ROLES.md) -- role permissions and what each role can access
- [API Guide](API_GUIDE.md) -- REST API for automation

---

## Appendix: API Automation

For operators who want to script host management or integrate with CI/CD
pipelines, here are the key API endpoints.

### Add a Host

```bash
curl -s -X POST http://localhost:8000/api/hosts/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "web-01", "ip_address": "192.168.1.10", "ssh_port": 22}'
```

### Bulk Import (JSON)

```bash
curl -s -X POST http://localhost:8000/api/bulk/hosts/bulk-import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [
      {"hostname": "web-01", "ip_address": "192.168.1.10", "port": 22},
      {"hostname": "db-01", "ip_address": "192.168.1.20", "port": 22}
    ],
    "update_existing": false,
    "dry_run": false
  }'
```

### Export Hosts to CSV

```bash
curl -s http://localhost:8000/api/bulk/hosts/export-csv \
  -H "Authorization: Bearer $TOKEN" -o hosts_export.csv
```

### Create a Host Group

```bash
curl -s -X POST http://localhost:8000/api/host-groups/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production Web Servers", "os_family": "rhel"}'
```

### Start Remediation

```bash
curl -s -X POST http://localhost:8000/api/remediation/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "SCAN_UUID",
    "host_id": "HOST_UUID",
    "failed_rules": ["sshd-disable-root-login", "sshd-strong-ciphers"],
    "provider": "kensa"
  }'
```

### Rollback

```bash
curl -s -X POST http://localhost:8000/api/automated-fixes/rollback/REQUEST_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rollback_reason": "Change caused SSH connectivity loss"}'
```

See the [API Guide](API_GUIDE.md) for the complete endpoint reference.
