# Host management and remediation

**Last updated:** 2026-07-30 · **Applies to:** OpenWatch v0.8.0 (Eyrie)

This guide covers adding and managing hosts, organizing them into groups,
understanding server intelligence data, and using automated remediation to fix
compliance findings. Most of these tasks are performed in the web UI.

---

## Adding a host

### From the UI

1. Navigate to **Hosts** in the left sidebar.
2. Select **Add host**. The page opens on the **Single** tab.
3. Fill in the host details:

| Field | Required | Example |
|-------|----------|---------|
| Hostname | Yes | `web-01` |
| IP address | Yes | `192.168.1.10` |
| Port | Yes | `22` |
| Environment | No | `production` |
| SSH username | Yes | `owadmin` |
| Auth method | Yes | password, or SSH private key |

   Tick **Use system default credential** to skip the auth fields and use the
   credential configured under Settings. The operating system is not entered
   here; discovery fills it in (see "Host discovery" below).

4. Select **Add host**.

The host appears in the host list immediately after creation.

### Bulk import

For adding many hosts at once, use the **Bulk** tab of the same Add host
page. It is a three-step wizard: **Upload CSV**, **Map fields**, **Preview &
import**.

1. Upload a CSV file. There is no template to download: the wizard reads
   your file's header row, shows a column analysis, and reports any shape it
   recognizes under "Detected templates".
2. Review the mappings from your columns to host fields. Columns it could
   auto-map are marked; fix the rest. Choose the credential for the imported
   hosts: **Use system default**, or **Clone an existing credential**.
3. Preview the valid rows and import them.

Under **Import options**, **Dry run** validates the file without creating
hosts; the button then reads "Dry-run N valid rows" instead of "Import N
valid rows". **Update existing** is shown but not yet wired: the API has no
per-host update by hostname or IP, so a matching row is reported rather than
overwritten.

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
5. Select **Save**.


### Testing connectivity

After saving credentials, select **Test Connection** to verify that OpenWatch
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

Host groups organize hosts into collections for group-level compliance
reporting, a shared compliance target, and maintenance windows.

### Creating a group

1. Navigate to **Groups** in the sidebar.
2. Select **New group**.
3. Enter a **Name**, choose a **Kind** (**Site**, or **OS category**), an
   optional **Subtype**, and the **Membership** mode: **Manual**, or **Auto
   (OS family)** with the OS family to match, such as `rhel` or `ubuntu`.
   Sites are always manual.
4. Select **Create group**.

### Membership

An automatic group populates itself from each host's discovered OS family.
A manual group's members are set through the API today,
`POST /api/v1/groups/{id}/members` and `DELETE /api/v1/groups/{id}/members/{host_id}`,
both requiring `host:write`; the Groups page shows the membership mode and
the member count but does not yet offer an add-hosts control. A host can
belong to more than one group.

### Per-group controls

Each group card offers a **Maintenance** toggle, which pauses scans and
alerts for every member, a **Compliance target** selector that sets the
framework the group's score is measured against, and a delete control.
There is no group-level scan: scans are started per host from the host
page, or on the schedule, and the Scans page shows the fleet queue.

---

## Host discovery

### OS detection

OpenWatch detects each host's operating system by discovery, a short SSH
session that reads OS facts without running a scan. To run it by hand, open
the host detail page: **Re-run Discovery** on the System card of the
**Overview** tab, or **Reconnect** in the connectivity area, which does the
same thing and is the quickest way to validate a credential you just edited.
Both need `host:write`.

A background scheduler ticks every 60 seconds and enqueues discovery for any
host whose OS has never been discovered or whose last discovery is older than
the per-host interval (default 24 hours, operator-tunable between 1 hour and 7
days). There is no fixed time-of-day anchor: discovery runs continuously as
hosts become due.

### Connectivity monitoring

Host connectivity is probed every 15 minutes by default (`online_sec`,
operator-tunable with a 60-second floor); a host in the degraded state is
probed more frequently, every 5 minutes by default (`degraded_sec`). Each
probe layers ICMP reachability, then SSH port + banner reachability, then a
privilege check; a host is marked degraded when a higher layer fails after a
lower one succeeds. Host status (online, degraded, unreachable) updates in the
host list.

---

## Server intelligence

During compliance scans, OpenWatch collects detailed information about each host.
This data is available on the host detail page under the **Intelligence** tab.


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

OpenWatch can automatically fix compliance findings through Kensa's 29
registered remediation handlers. All changes are made over SSH: nothing is
installed on target hosts.

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

Remediation in OpenWatch Core is one rule on one host at a time.

1. Open the host detail page and the **Compliance** tab.
2. Find the failing rule and select **Request remediation** on its row. The
   request is auto-approved and appears on the **Remediation** tab with the
   status Approved.
3. On the **Remediation** tab, expand the request to see what the fix will
   do, then select **Fix**. The row shows Executing, then the outcome:
   **Fixed**, **Staged, reboot required** for a change written but not yet
   live, or one of the other outcomes described below.

Selecting many rules at once and remediating them together is **Bulk
remediation**, an OpenWatch Enterprise feature; the Remediation tab shows it
as a disabled control in Core.

Fixing one rule on one host, with rollback, is free. A single-rule remediation
request auto-approves on submission. There is no separate approval step, and no
per-organization toggle to require one. The request is still recorded and audited
(with a note that it was auto-approved), and a user with `remediation:execute`
applies it.

**Roadmap (Enterprise).** A request/approve/reject workflow with separation of
duties is planned for the Enterprise bulk and automated remediation track, not
yet available today:

1. A user with `remediation:request` (`ops_lead`, `security_admin`, or `admin`)
   selects findings, chooses **Request Remediation**, and enters a justification.
2. A **different** user with `remediation:approve` (`security_admin` or `admin`)
   reviews and approves or rejects it. The reviewer cannot be the requester
   (separation of duties; self-review returns `409 remediation.self_review`).
3. Once approved, a user with `remediation:execute` selects **Fix** to apply the
   change. Execution is operator-initiated, not automatic.

See [User roles](USER_ROLES.md) for the full role matrix.

---

## Monitoring remediation progress

After starting a remediation, track its progress on the host detail page
under the **Remediation** tab.


Each request is one rule on one host. Expanding a row shows either what the
fix will do, or what it did.

**Before it runs.** Expanding an approved request plans the fix against the
host and shows the result without changing anything:

- **What is there now**: the state the engine found on the host.
- **What it will change**: the steps that would be applied.
- **How it will be checked**: after applying, the rule's own check runs again,
  and the captured state is restored if it does not pass.
- **How it can be undone**, including how many steps can be reversed. That
  count comes from what was actually captured, not from what the rule claims.

A fix that touches SSH, networking, PAM or firewall state is called out. The
engine arms a timer before applying such a change, so it reverts by itself if
the host stops answering.

Planning contacts the host, so it fails the way a scan does if the host is
unreachable. When that happens the panel says nothing was changed.

**After it runs.** Expanding an executed request shows the transaction the
engine performed, phase by phase, with its own account of each:

- **Capture**, **Apply**, **Validate**, **Commit** or **Rollback**, each with
  the detail the engine recorded. When a fix fails, this is where the reason
  is.
- **Before**: a one-line summary of the state captured for each step, with the
  full captured state available beneath it. The summary is for reading; the
  full capture is the evidence.

Three things are called out in words, because none can be inferred from the
status alone: a step that rollback will not reverse, a change that was written
but is not live until the host reboots, and a step that cannot be rolled back
at all.

---

## Rollback

Pre-state snapshots are captured automatically before any remediation changes.
If a remediation causes problems, you can roll back to the pre-change state.

Not every request offers a rollback, and the absence of the control is
meaningful. A request that reports no change was made because the host already
satisfied the rule has nothing to restore, so no rollback is offered. Steps
whose mechanism cannot capture pre-state are named in the transaction view for
the same reason.

### From the UI

1. Go to the **Remediation** tab on the host detail page.
2. Find the request you want to roll back. The **Roll back** button appears on
   a request whose status is **Fixed** or **Staged, reboot required**.
3. Select **Roll back**.

The rollback runs immediately. There is no reason field and no confirmation
step: one click queues the rollback job, and the row changes to **Rolled
back** when it completes. Expand the row to see the captured pre-state the
rollback restored.

Every rollback is recorded in the audit log as `remediation.rolled_back`,
carrying the request, host, rule, job id and the user who clicked, so the
action is attributable without a typed reason. If your change process needs a
written justification, record it in your ticketing system before you click.

Rollback requires the `remediation:rollback` permission (`ops_lead`,
`security_admin`, or `admin`).

### After rolling back

Confirm the result on the host, not only in the UI: the file or setting the
transaction changed should be back to its captured pre-state. Then run a
follow-up compliance scan; the rule returns to the result it had before the
fix. For a staged change that was rolled back before a reboot, the running
host never changed, so nothing on it needs checking beyond the file.

---

## Required permissions

Built-in roles, in precedence order: `viewer` → `auditor` → `ops_lead` →
`security_admin` → `admin` (`admin` holds every permission). A user with several
roles is bound as the highest-precedence one, not as their union. The
authoritative role-to-permission mapping is served by the roles API,
`GET /api/v1/roles`; see [User roles](USER_ROLES.md) for the complete matrix.

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
5. **Monitor compliance score after remediation.** The adaptive scheduler
   automatically scans again, but you can force a scan for immediate results.
6. **Use groups for consistent scanning.** Hosts in the same group share OS
   family, framework, and scan schedule settings.

---

## What's next

- [Scanning and compliance](SCANNING_AND_COMPLIANCE.md): understanding scan results and posture
- [User roles](USER_ROLES.md): role permissions and what each role can access
- [API guide](API_GUIDE.md): REST API for automation

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
failing rule on a host, then execute it. Single-rule fixes are free and
auto-approve on request. The Enterprise bulk track keeps the approve/reject step.

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
