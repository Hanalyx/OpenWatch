# Host management and remediation

**Last updated:** 2026-06-25 · **Applies to:** OpenWatch v0.2.0-rc series (Go single-binary)

This guide covers adding and managing hosts, organizing them into groups,
understanding server intelligence data, and using automated remediation to fix
compliance findings. Most of these tasks are performed in the web UI.

---

## Adding a host

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

### Bulk import

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

## Configuring SSH credentials

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

### Testing connectivity

After saving credentials, click **Test Connection** to verify that OpenWatch
can reach the host via SSH. The test checks:

- Network reachability
- SSH port availability
- Authentication success

Fix any connection issues before running a scan.

### System credentials

For organizations where all hosts share the same SSH credentials, configure a
system-wide default:

1. Go to **Settings > System Credentials**.
2. Add the shared SSH key or password.
3. When adding hosts, select **System Default** as the auth method.

### Credential security

All credentials are encrypted with AES-256-GCM before being stored in the
database. Decryption happens only at scan time, in memory. Plaintext credentials
are never written to disk or logs.

---

## Host groups

Host groups let you organize hosts into logical collections for group-level
compliance reporting and batch scanning.

### Creating a group

1. Navigate to **Host Groups** in the sidebar.
2. Click **Create Group**.
3. Enter a name, description, OS family, and compliance framework.
4. Click **Save**.

![Create host group dialog](../images/hosts/create-group.png)

### Assigning hosts

1. Open the group detail page.
2. Click **Add Hosts**.
3. Select hosts from the list.
4. Click **Confirm**.

Each host can belong to one group at a time.

### Smart group creation

Select multiple hosts and click **Smart Group**. OpenWatch analyzes their OS,
architecture, and compliance profile to recommend group settings automatically.

### Group scanning

From the group detail page, click **Scan Group** to start a compliance scan
for all hosts in the group simultaneously. Monitor progress on the group's
scan session page.

---

## Host discovery

### OS detection

OpenWatch automatically detects the operating system for hosts during scans.
You can also trigger manual OS discovery from the host detail page by clicking
**Discover OS**.

A scheduled task runs daily at 02:00 UTC to discover the OS for all active
hosts that have not been identified yet.

### Connectivity monitoring

Host connectivity is probed every 5 minutes by default (operator-tunable, with
a 60-second floor). Each probe layers ICMP reachability, then SSH port + banner
reachability, then a privilege check; a host is marked degraded when a higher
layer fails after a lower one succeeds. Host status (online, degraded,
unreachable) updates in the host list.

---

## Server intelligence

During compliance scans, OpenWatch collects detailed information about each host.
This data is available on the host detail page under the **Intelligence** tab.

![Server intelligence overview](../images/hosts/server-intelligence.png)

### Data collected

| Category | What It Contains |
|----------|------------------|
| Packages | Installed packages, versions, sources |
| Services | Running services, listening ports, enabled state |
| Users | User accounts, groups, shell, last login |
| Network | Interfaces, IP addresses, firewall rules |

### System information

The host detail page also shows:

- OS name, version, and kernel release
- CPU model, core count, and architecture
- Total and available memory
- SELinux or AppArmor status
- Firewall status and active service

This data helps operators understand the security surface of each host without
needing to SSH in manually.

---

## Remediation overview

OpenWatch can automatically fix compliance findings through Kensa's 27
remediation mechanisms. All changes are made over SSH—nothing is installed
on target hosts.

### What remediation can fix

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

## Starting a remediation

### From the UI

1. Navigate to the host detail page and view the scan results.
2. Select the failing findings you want to remediate (use checkboxes).
3. Click **Remediate Selected**.

![Selecting findings for remediation](../images/hosts/select-remediation.png)

4. Review the proposed changes. Each finding shows what will be modified.
5. Click **Start Remediation** to confirm.

![Remediation confirmation dialog](../images/hosts/confirm-remediation.png)

For organizations that require an approval step:

1. A user with `remediation:request` (`ops_lead`, `security_admin`, or `admin`)
   selects findings, clicks **Request Remediation**, and enters a justification.
2. A **different** user with `remediation:approve` (`security_admin` or `admin`)
   reviews and approves or rejects it. You cannot approve your own request
   (separation of duties; self-approval returns `409 self_review`).
3. Once approved, a user with `remediation:execute` clicks **Fix** to apply the
   change. Execution is operator-initiated, not automatic.

See [User roles](USER_ROLES.md) for the full role matrix. Single-operator
workspaces cannot self-approve a bulk/automated remediation request today.

---

## Monitoring remediation progress

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

Rollback requires the `remediation:rollback` permission (`ops_lead`,
`security_admin`, or `admin`).

### After rolling back

After a rollback completes, run a follow-up compliance scan to verify the host
returned to its previous state.

---

## Required permissions

Built-in roles, least to most privilege: `viewer` → `auditor` → `ops_lead` →
`security_admin` → `admin` (`admin` holds every permission). The authoritative
role-to-permission mapping is served by the roles API, `GET /api/v1/roles`; see
[User roles](USER_ROLES.md) for the complete matrix.

| Operation | Permission | Roles that hold it |
|-----------|------------|--------------------|
| View hosts | `host:read` | viewer, auditor, ops_lead, security_admin, admin |
| Add / edit hosts | `host:write` | ops_lead, security_admin, admin |
| Delete hosts | `host:delete` | security_admin, admin |
| Request remediation | `remediation:request` | ops_lead, security_admin, admin |
| Approve / reject remediation | `remediation:approve` | security_admin, admin |
| Execute remediation (Fix) | `remediation:execute` | ops_lead, security_admin, admin |
| Rollback remediation | `remediation:rollback` | ops_lead, security_admin, admin |
| View server intelligence | `host:read` | viewer, auditor, ops_lead, security_admin, admin |

---

## Best practices

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

## What's next

- [Scanning and compliance](SCANNING_AND_COMPLIANCE.md)—understanding scan results and posture
- [User roles](USER_ROLES.md)—role permissions and what each role can access
- [API guide](API_GUIDE.md)—REST API for automation

---

## Appendix: API automation

For operators who want to script host management or integrate with CI/CD
pipelines, here are the key API endpoints. OpenWatch serves the REST API over
HTTPS on port `8443`; every path lives under `/api/v1`. The contract source of
truth is the served `/api/v1` OpenAPI document. Replace `openwatch.example.com` with your host.

### Add a host

```bash
curl -s -X POST https://openwatch.example.com:8443/api/v1/hosts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "web-01", "ip_address": "192.168.1.10", "port": 22, "environment": "prod"}'
```

`hostname` and `ip_address` are required; `port` defaults to 22. Other optional
fields: `display_name`, `description`, `tags`, `group_id`, `username`. There is
no bulk-import or CSV-export API endpoint. Import many hosts from a CSV in the
web UI (Hosts, Import), which validates each row before insert.

### Create a group

```bash
curl -s -X POST https://openwatch.example.com:8443/api/v1/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production Web Servers", "kind": "site", "membership": "manual"}'
```

`kind` is `site` or `os_category`; `membership` is `manual` or `auto` (an `auto`
group also needs `match_family`). Add a host to a manual group via
`POST /api/v1/groups/{id}/members`.

### Request and execute remediation

Remediation is a request lifecycle, not a single call: request a fix for a
failing rule on a host, then execute it (free-core single-rule fixes
auto-approve on request; the licensed bulk track keeps the approve/reject step).

```bash
# 1. Request a fix for one failing rule on one host.
RID=$(curl -s -X POST https://openwatch.example.com:8443/api/v1/remediation/requests \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host_id": "HOST_UUID", "rule_id": "sshd-disable-root-login"}' \
  | jq -r '.id')

# 2. Execute it (mutates the host; runs serialized per host).
curl -s -X POST "https://openwatch.example.com:8443/api/v1/remediation/requests/${RID}:execute" \
  -H "Authorization: Bearer $TOKEN"
```

### Roll back

```bash
curl -s -X POST "https://openwatch.example.com:8443/api/v1/remediation/requests/${RID}:rollback" \
  -H "Authorization: Bearer $TOKEN"
```

See the [API guide](API_GUIDE.md) for authentication and the complete endpoint
reference.
