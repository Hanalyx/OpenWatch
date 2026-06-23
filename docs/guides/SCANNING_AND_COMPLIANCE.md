# Scanning and Compliance

**Last Updated:** 2026-06-22 · **Applies to:** OpenWatch 0.2.0-rc series (Go single-binary)

This guide covers how OpenWatch performs compliance scanning, how to read
results and posture scores, and how to use drift detection, alerts, and
audit exports. Most of these tasks are performed in the web UI.

---

## How Scanning Works

When a scan runs, OpenWatch uses the Kensa compliance engine to connect to the
target host over SSH, execute each rule's check command, and return a pass/fail
result with machine-verifiable evidence.

```
Operator clicks "Run Scan" (or adaptive scheduler triggers)
        |
        v
Scan job enqueued on the PostgreSQL job queue (SKIP LOCKED)
        |
        v
Kensa retrieves SSH credentials from OpenWatch's encrypted store
        |
        v
SSH connection to target host
        |
        v
539 YAML rules evaluated (check commands, config values, file permissions)
        |
        v
Each rule returns: pass/fail, severity, detail, evidence
        |
        v
Write-on-change: changed verdicts -> transactions; current state -> host_rule_state
        |
        v
Daily posture snapshot rolls up; drift alerts generated if thresholds met
```

Key points:

- **No agent on targets.** Kensa connects over SSH, runs commands, and
  disconnects. Nothing is installed on the scanned host.
- **One scan, many frameworks.** A single scan produces results that map to
  CIS, STIG, NIST, PCI-DSS, and FedRAMP simultaneously.
- **Evidence captured.** Each check records the command executed, the raw
  output, the expected value, and the actual value found.

---

## Available Frameworks

| Framework | Mapping ID | Rules |
|-----------|------------|-------|
| CIS RHEL 9 v2.0.0 | cis-rhel9-v2.0.0 | 271 |
| STIG RHEL 9 V2R7 | stig-rhel9-v2r7 | 338 |
| NIST 800-53 Rev 5 | nist-800-53-r5 | 87 |
| PCI-DSS v4.0 | pci-dss-v4.0 | 45 |
| FedRAMP Moderate | fedramp-moderate | 87 |

Framework mappings are carried per-rule as Kensa's normalized `framework_refs`
(a multi-valued framework_id -> control-ids map, since one rule can satisfy
several controls within a framework). They are stored on each `host_rule_state`
row as `framework_refs` JSONB and projected into the lens views at query time --
there is no separate sync service in the Go rebuild.

---

## Running a Scan

### From the UI

1. Navigate to **Hosts** and select the host you want to scan.
2. On the host detail page, click **Run Scan**.

A scan always runs the **full applicable rule corpus** -- you do not pick a
framework to scan. Frameworks (CIS, STIG, NIST, PCI) are **reporting lenses**
applied at view time on the Compliance tab: one scan, viewed through any
framework. The lens bar only offers frameworks compatible with the host's
detected OS (a RHEL 8 host does not show CIS/STIG RHEL 9 or 10 lenses);
OS-neutral frameworks (NIST, PCI, SRG) always appear.

![Running a scan from the host detail page](../images/scanning/run-scan.png)

The scan runs in the background. A progress indicator shows the scan status.
Results appear on the host's compliance tab once the scan completes
(typically 1--5 minutes).

### Automatic Scanning

Most hosts are scanned automatically by the adaptive scheduler. You do not need
to trigger scans manually unless you want immediate results. See the
[Adaptive Scheduling](#adaptive-scheduling) section below.

---

## Reading Scan Results

After a scan completes, the results are displayed on the host detail page under
the **Compliance** tab.

![Scan results page with findings table](../images/scanning/scan-results.png)

### What You See

- **Compliance score** -- percentage of rules passing (e.g., 85.0%)
- **Summary bar** -- pass, fail, error, and skipped counts
- **Severity breakdown** -- counts by critical, high, medium, low
- **Findings table** -- sortable, filterable list of all findings

### Finding Details

Click any finding row to expand it. Each finding shows:

| Field | Description |
|-------|-------------|
| Rule ID | Kensa rule identifier (e.g., `sshd-disable-root-login`) |
| Title | Human-readable description |
| Severity | critical, high, medium, or low |
| Status | pass, fail, error, or skipped |
| Detail | Explanation of the check result |
| Evidence | Command executed, expected value, actual value |

### Filtering Results

Use the filter controls above the findings table to narrow results:

- **By severity** -- show only critical and high findings
- **By status** -- show only failures
- **By search** -- search rule titles and descriptions

---

## Compliance Posture

### What the Score Means

The compliance score is the percentage of evaluated rules that passed:

```
compliance_score = (passed_rules / total_rules) * 100
```

A score of 85.0 means 85% of rules passed. Skipped rules are excluded from
the total.

### Viewing Posture in the Dashboard

Navigate to the **Dashboard** from the sidebar. The posture overview shows:

- **Aggregate score** across all hosts
- **Per-host scores** in the host list
- **Trend chart** showing score changes over time
- **Framework breakdown** with per-framework compliance percentages

![Compliance posture dashboard](../images/scanning/posture-dashboard.png)

### Historical Posture

OpenWatch captures daily posture snapshots at 00:30 UTC. To view historical
posture:

1. Navigate to the host detail page.
2. Select the **Posture History** tab.
3. Choose a date range to view the compliance trend.

Historical posture queries with specific `as_of` dates require OpenWatch+.

---

## Drift Detection

Drift occurs when a rule's status changes between two points in time. A rule
that was passing and now fails is a **regression**. A rule that was failing
and now passes is an **improvement**.

### Viewing Drift in the UI

1. Navigate to the host detail page.
2. Select the **Drift** tab.
3. Choose a date range (start date and end date).

![Drift detection showing regressions and improvements](../images/scanning/drift-view.png)

The drift view shows:

- **Score delta** -- how much the compliance score changed
- **Drift type** -- stable, minor, major, or improvement
- **Rules improved** and **rules regressed** -- counts with expandable lists
- **Timeline** -- when each drift event occurred

### Field-Level Value Drift

Enable **Include value drift** to see rules where the underlying configuration
value changed even though the pass/fail status did not. For example, a password
minimum length changing from 14 to 12 while both still pass the threshold.

### What to Do When Drift Is Detected

1. Review the regressed rules and their evidence.
2. Investigate the root cause on the host (configuration change, package update).
3. Remediate the finding, or create a compliance exception if the risk is accepted.

---

## Adaptive Scheduling

The compliance scheduler automatically scans hosts at intervals based on their
compliance state. You do not need to trigger manual scans for routine monitoring.

### How It Works

A host is classified into one of five score bands (plus Unknown for
never-scanned hosts) after every scan, and the next scan is scheduled from the
band's interval. The intervals below are the **defaults** -- they are
operator-editable per band under **Settings -> Scanning & monitoring ->
Compliance scanner**, clamped to a 5-minute floor and a 48-hour ceiling.

| Compliance State | Score Range | Default Interval |
|------------------|-------------|------------------|
| Critical | < 20%, or any critical finding | Every 4 hours |
| Non-compliant | 20--49% | Every 8 hours |
| Partial | 50--69% | Every 12 hours |
| Mostly compliant | 70--89% | Every 24 hours |
| Compliant | >= 90% | Every 48 hours |
| Unknown | Never scanned | Every 6 hours (due immediately on first sight) |

The maximum interval is 48 hours. No active host goes unscanned longer than
that. A per-host or fleet-wide maintenance flag pauses scheduled scans without
affecting on-demand Run Scan.

### Viewing a Host's Schedule

On the host detail page, the **Scheduling** section shows:

- Current scan interval
- Next scheduled scan time
- Compliance state driving the interval
- Whether the host is in maintenance mode

### Maintenance Mode

To pause scanning for a host (during planned maintenance):

1. Go to the host detail page.
2. Click **Maintenance Mode**.
3. Set the duration (1--168 hours).
4. Click **Enable**.

Maintenance mode expires automatically. You can disable it early from the same page.

### Force Scan

To trigger an immediate scan outside the normal schedule, click **Force Scan**
on the host detail page. This bypasses the schedule and runs at highest priority.

---

## Compliance Exceptions

A compliance exception is a documented, operator-approved waiver for a failing
rule on a host -- accepted risk ("rule X on host Y is accepted because Z, until
date D"). Exceptions are governed through a request and approval workflow.

**Overlay model (important):** an exception **never changes a rule's scan
verdict**. A failing rule with an active exception still shows as failing in the
raw results and still counts against the raw compliance score -- Kensa's verdict
is authoritative. The exception is a governance annotation that marks the
failure as accepted risk wherever it surfaces. This keeps the score honest and
keeps the audit trail showing both "the control failed" and "the failure was
formally accepted."

### Lifecycle

```
requested -> approved  -> (active until expiry) -> revoked | expired
          -> rejected
```

### Who can do what (separation of duties)

| Action | Permission | Roles |
|--------|------------|-------|
| Request an exception | exception:request | ops_lead, auditor, security_admin, admin |
| Approve / reject a request | exception:approve | auditor, security_admin, admin |
| Revoke an active exception | exception:revoke | security_admin, admin |
| View exceptions | exception:read | all roles above + viewer |

The requester **cannot** approve their own request.

### Requesting an exception

1. On the host's **Compliance** tab, find a failing rule.
2. Click **Request exception** in its row.
3. Enter the reason (required) and an optional expiry date.
4. Submit. The rule now shows a **Pending** badge.

### Approving / managing exceptions

The fleet queue lives at **Settings -> Compliance policies -> Exception
workflow**. Filter by status (Pending / Active / Rejected / Revoked / Expired),
and on a pending request an approver can **Approve** or **Reject**; on an active
exception, **Revoke** ends it before its expiry. Once approved, the rule shows a
**Waived** badge everywhere it appears (the host's Compliance tab, the Watchlist
tile, the Server-intelligence Open-exceptions count). Approved exceptions whose
expiry passes are swept to **expired** automatically.

---

## Alert Management

Alerts are generated automatically when scan results meet configured thresholds.

### Alert Categories

| Category | Alert Types |
|----------|-------------|
| Compliance | Critical finding, high finding, score drop, non-compliant, degrading trend |
| Operational | Host unreachable, scan failed, scheduler stopped, scan backlog |
| Exception | Exception expiring, exception expired, exception requested |
| Drift | Configuration drift, unexpected remediation, mass drift |

### Viewing Alerts

Navigate to **Alerts** in the sidebar. The alert list shows all active,
acknowledged, and recently resolved alerts.

![Alert management page](../images/scanning/alerts.png)

Use filters to narrow by:

- **Status** -- active, acknowledged, resolved
- **Severity** -- critical, high, medium, low
- **Category** -- compliance, operational, exception, drift

### Alert Lifecycle

```
Active --> Acknowledged --> Resolved
```

- **Active**: Alert generated, requires attention.
- **Acknowledged**: Click **Acknowledge** to indicate you are investigating.
- **Resolved**: Click **Resolve** after the issue is fixed or accepted.

### Configuring Thresholds

Navigate to **Settings > Alert Thresholds** to customize when alerts fire.

| Setting | Default | Meaning |
|---------|---------|---------|
| Score drop threshold | 20 points | Alert if score drops 20+ points in 24h |
| Non-compliant threshold | 80% | Alert if score falls below 80% |
| Degrading trend scans | 3 | Alert after 3 consecutive declining scans |
| Max scan age | 48 hours | Alert if host not scanned in 48 hours |
| Exception expiry warning | 7 days | Warn 7 days before exception expires |
| Mass drift threshold | 10 hosts | Alert if 10+ hosts drift simultaneously |

---

## Exporting for Audits

OpenWatch provides audit query and export tools for generating compliance
evidence.

### Creating a Saved Query

1. Navigate to **Compliance > Audit Queries**.
2. Click **New Query**.
3. Define filter criteria (severities, statuses, date range, hosts).
4. Name the query and set visibility (private or shared).
5. Click **Save**.

### Previewing Results

Before generating a full export, click **Preview** to see a sample of matching
findings and the total count.

### Generating an Export

1. From a saved query, click **Export**.
2. Choose a format: **CSV**, **JSON**, or **PDF**.
3. The export generates in the background. A download link appears when ready.

![Audit export download](../images/scanning/audit-export.png)

Exports include a SHA-256 checksum for integrity verification. Exports expire
after 7 days by default.

---

## What's Next

- [Hosts and Remediation](HOSTS_AND_REMEDIATION.md) -- managing hosts and fixing findings
- [User Roles](USER_ROLES.md) -- role-based access control
- [API Guide](API_GUIDE.md) -- REST API for automation and scripting

---

## Appendix: API Automation

For operators who want to script scanning workflows or integrate with CI/CD
pipelines, here are the key API endpoints.

### Start a Scan

Enqueue an on-demand scan for one host. The scan runs the full Kensa rule corpus
(frameworks are lenses applied to the results, not a scan parameter). The call
returns `202` with the new scan id; the scan itself runs asynchronously on the
worker.

```bash
curl -k -X POST https://localhost:8443/api/v1/hosts/HOST_UUID/scans \
  -H "Authorization: Bearer $TOKEN"
```

### Query Posture

```bash
curl -k "https://localhost:8443/api/v1/compliance/posture?host_id=HOST_UUID" \
  -H "Authorization: Bearer $TOKEN"
```

### Query Historical Posture

```bash
curl -k "https://localhost:8443/api/v1/compliance/posture?host_id=HOST_UUID&as_of=2026-02-15" \
  -H "Authorization: Bearer $TOKEN"
```

### Query Drift

```bash
curl -k "https://localhost:8443/api/v1/compliance/posture/drift?host_id=HOST_UUID&start_date=2026-02-01&end_date=2026-02-28" \
  -H "Authorization: Bearer $TOKEN"
```

### List Alerts

```bash
curl -k "https://localhost:8443/api/v1/compliance/alerts?status=active" \
  -H "Authorization: Bearer $TOKEN"
```

### Acknowledge an Alert

```bash
curl -k -X POST "https://localhost:8443/api/v1/compliance/alerts/ALERT_ID/acknowledge" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{}'
```

### Create an Export

```bash
curl -k -X POST https://localhost:8443/api/v1/compliance/audit/exports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query_definition": {"severities": ["critical"], "statuses": ["fail"]}, "format": "csv"}'
```

See the [API Guide](API_GUIDE.md) for the complete endpoint reference.
