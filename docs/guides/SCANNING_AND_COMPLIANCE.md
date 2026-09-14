# Scanning and compliance

**Last updated:** 2026-07-30 · **Applies to:** OpenWatch v0.8.0 (Eyrie)

This guide covers how OpenWatch performs compliance scanning, how to read
results and posture scores, and how to use drift detection, alerts, and
audit exports. Most of these tasks are performed in the web UI.

---

## How scanning works

When a scan runs, OpenWatch uses the Kensa compliance engine to connect to the
target host over SSH, execute each rule's check command, and return a pass/fail
result with machine-verifiable evidence.

```
Operator selects "Run Scan" (or adaptive scheduler triggers)
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
Rules from the bundled corpus run: check commands, config values, permissions
        |
        v
Each rule returns: pass/fail, severity, detail, evidence
        |
        v
Only changed verdicts are recorded; current per-rule state is kept up to date
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

## Available frameworks

| Framework | Mapping ID | Rules |
|-----------|------------|-------|
| CIS RHEL 9 v2.0.0 | cis-rhel9-v2.0.0 | 271 |
| STIG RHEL 9 V2R7 | stig-rhel9-v2r7 | 338 |
| CIS Ubuntu 24.04 LTS | cis-ubuntu24 | (see Ubuntu rule applicability in the distribution support guide) |
| STIG Ubuntu 22.04 | stig-ubuntu22 | (see Ubuntu rule applicability above) |
| NIST 800-53 Rev 5 | nist-800-53-r5 | 87 |
| PCI-DSS v4.0 | pci-dss-v4.0 | 45 |
| FedRAMP Moderate | fedramp-moderate | 87 |

RHEL and Ubuntu are both supported scan targets. See
[Linux distribution support](LINUX_DISTRIBUTION_SUPPORT.md) for the full
per-OS rule applicability matrix.

Framework mappings are carried per-rule as Kensa's normalized `framework_refs`
(a multi-valued framework_id -> control-ids map, since one rule can satisfy
several controls within a framework). They are stored per host-rule as
`framework_refs` JSONB and projected into the lens views at query time: there is no separate sync service in the Go rebuild.

---

## Running a scan

### From the UI

1. Navigate to **Hosts** and select the host you want to scan.
2. On the host detail page, select **Run Scan**.

A scan always runs the **full applicable rule corpus**. You do not pick a
framework to scan. Frameworks (CIS, STIG, NIST, PCI) are **reporting lenses**
applied at view time on the Compliance tab: one scan, viewed through any
framework. The lens bar only offers frameworks compatible with the host's
detected OS (a RHEL 8 host does not show CIS/STIG RHEL 9 or 10 lenses);
OS-neutral frameworks (NIST, PCI, SRG) always appear.

The scan runs in the background. A progress indicator shows the scan status.
Results appear on the host's compliance tab once the scan completes
(typically 1–5 minutes).

### Automatic scanning

Most hosts are scanned automatically by the adaptive scheduler. You do not need
to trigger scans manually unless you want immediate results. See the
[Adaptive Scheduling](#adaptive-scheduling) section below.

---

## Operating the scan engine

The Kensa engine runs inside the OpenWatch binary. There is no separate engine
service to start, stop, or restart.

A packaged install runs one service, `openwatch serve`, and that process runs
the scan worker in-process. You do not need to start anything else to scan.
`openwatch worker` is a separate long-lived process for scaling scan capacity
out to more hosts. It is optional, and several may run against one database.

Check which engine version is linked into the running binary:

```bash
curl -sk https://localhost:8443/api/v1/health
```

The response carries a `kensa` field. The value is read from the binary's build
information, so it always reports the engine actually linked in.

Check the service state and follow its logs:

```bash
systemctl status openwatch.service
journalctl -u openwatch.service -f
```

Scan jobs queue in PostgreSQL. The connection string lives in
`/etc/openwatch/secrets.env`, which is mode `0640` and owned `root:openwatch`,
so read it as the `openwatch` user rather than as yourself. Load the file inside
the same command that uses it:

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; \
  psql "$OPENWATCH_DATABASE_DSN" -c \
  "select id, status, created_at from job_queue order by created_at desc limit 10;"'
```

The single quotes matter. They keep `$OPENWATCH_DATABASE_DSN` unexpanded in your
own shell, where it is empty, so it resolves after the file is loaded.

A job that stays queued usually means the service is not running. Check the
service first, then the logs.

---

## Reading scan results

After a scan completes, the results are displayed on the host detail page under
the **Compliance** tab.

### What you see

- **Compliance score**: passing rules over rules that reached a verdict (for
  example, 85.0%). It can be absent; absent is not zero
- **Summary bar**: pass, fail, error, and skipped counts
- **Severity breakdown**: counts by critical, high, medium, low
- **Findings table**: sortable, filterable list of all findings

### Finding details

Select any finding row to expand it. Each finding shows:

| Field | Description |
|-------|-------------|
| Rule ID | Kensa rule identifier (for example, `sshd-disable-root-login`) |
| Title | Human-readable description |
| Severity | critical, high, medium, or low |
| Status | pass, fail, error, or skipped |
| Detail | Explanation of the check result |
| Evidence | Command executed, expected value, actual value |

### Filtering results

Use the filter controls above the findings table to narrow results:

- **By severity**: show only critical and high findings
- **By status**: show only failures
- **By search**: search rule titles and descriptions

---

## Compliance posture

### What the score means

The compliance score counts only the rules that reached a verdict:

```
score_pct = passing / (passing + failing) * 100
```

A score of 85.0 means 85% of the rules that produced a pass or a fail passed.

**Only `pass` and `fail` count.** A rule that was skipped, that did not apply,
or that errored stays out of the numerator and out of the denominator. It is
not counted as a failure. A host where most rules were skipped is not scored
low for it; see coverage below.

The score is shown to one decimal place. Rounding happens once, when the API
answers, so an aggregate is averaged before it is rounded.

### A missing score is not a zero

`score_pct` can be absent. Absence and zero mean different things, and the API
keeps them apart:

| Value | Meaning |
|---|---|
| `null` | No rule produced a pass or a fail. There is nothing to score. |
| `0` | Rules produced verdicts and every one of them failed. |

A zero is a real, measured result. Treat it as a finding. An absent score is
the absence of a measurement, so do not render it as `0`, color it as a
failure, or average it into a fleet number.

### Coverage is a separate question

Coverage says whether a score could be produced at all. It never changes the
score itself. `coverage_status` is exactly one of three values:

| `coverage_status` | Meaning |
|---|---|
| `available` | Enough rules reached a verdict. A coverage percentage is reported. |
| `unavailable_unclassified_skips` | Rules were skipped for reasons the engine did not classify, so coverage cannot be computed. |
| `unavailable_no_outcomes` | No rule produced any outcome at all. |

**A coverage percentage exists only when the status is `available`.** For the
other two the number is absent, because there is nothing honest to put in it.

### Fleet and group scores

A fleet or group score is an **equal-host mean**: the mean of the host scores,
with every scored host counting once, whatever its rule count:

```
fleet score = mean(score of each scored host)
```

It is not a pooled ratio over rule rows. Pooling would let a host carrying 700
rules outvote a host carrying 50, so two fleets with identical host postures
would report different numbers.

**Hosts with no score are left out of the mean, not counted as zero.** They
stay visible in the participation counts that travel with the score, such as
`hosts_total`, `hosts_scored` and `hosts_without_score`. Read those counts
before reading the score: a 92.0 over three of two hundred hosts is not a fleet
result.

### Scores from older releases

The formula has changed, and history records which one produced each point.
Every trend day carries a `formula_status`:

| `formula_status` | Meaning |
|---|---|
| `identified` | The day used the current formula. |
| `legacy_unknown` | The day predates it, and the formula is not recorded. |
| `mixed` | That day's snapshots disagree about the formula. |

**A mixed day carries no score.** Its `score_pct` and `formula_version` are
both `null`, and it must not produce a delta, a comparison, or an arrow. Two
numbers from different formulas do not describe a change in posture.

Reports signed before the change carry a `compliance_pct` field instead of
`score_pct`. **The two are not comparable.** `compliance_pct` was a pooled
whole percent over every rule outcome in scope. Those artifacts keep their
original bytes so their signatures still verify, and nothing rewrites them.

The full response envelope, including the provenance fields that record the
engine and rule corpus behind a score, is in
[the OpenAPI contract](../../api/openapi.yaml). It is the authority; this guide
does not restate every field.

### Viewing posture in the dashboard

Navigate to the **Dashboard** from the sidebar. The posture overview shows:

- **Aggregate score** across all hosts
- **Per-host scores** in the host list
- **Trend chart** showing score changes over time
- **Framework breakdown** with per-framework compliance percentages

### Historical posture

OpenWatch captures a posture snapshot rollup on an hourly tick (plus once
immediately at boot). To view historical posture:

1. Navigate to the host detail page.
2. Select the **Posture History** tab.
3. Choose a date range to view the compliance trend.

---

## Drift detection

Drift occurs when a rule's status changes between two points in time. A rule
that was passing and now fails is a **regression**. A rule that was failing
and now passes is an **improvement**.

### Viewing drift in the UI

1. Navigate to the host detail page.
2. Select the **Drift** tab.
3. Choose a date range (start date and end date).

The drift view shows:

- **Score delta**: how much the compliance score changed
- **Drift type**: stable, minor, major, or improvement
- **Rules improved** and **rules regressed**: counts with expandable lists
- **Timeline**: when each drift event occurred

### Field-level value drift

Enable **Include value drift** to see rules where the underlying configuration
value changed even though the pass/fail status did not. For example, a password
minimum length changing from 14 to 12 while both still pass the threshold.

### What to do when drift is detected

1. Review the regressed rules and their evidence.
2. Investigate the root cause on the host (configuration change, package update).
3. Remediate the finding, or create a compliance exception if the risk is accepted.

---

## Adaptive scheduling

The compliance scheduler automatically scans hosts at intervals based on their
compliance state. You do not need to trigger manual scans for routine monitoring.

### How it works

A host is classified into one of five score bands (plus Unknown for
never-scanned hosts) after every scan, and the next scan is scheduled from the
band's interval. The intervals below are the **defaults**. They are
operator-editable per band under **Settings -> Scanning and monitoring ->
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

### Viewing a host's schedule

On the host detail page, the **Scheduling** section shows:

- Current scan interval
- Next scheduled scan time
- Compliance state driving the interval
- Whether the host is in maintenance mode

### Maintenance mode

Maintenance mode is a manual on/off flag that pauses scheduled scans, alerts,
and connectivity probes for a host during planned maintenance. It has no timer
and does not expire on its own: it stays on until you turn it off.

To pause a host:

1. Go to the host detail page.
2. Turn on the **Maintenance** toggle in the host action row.

To resume, turn the toggle off. On-demand **Run Scan** still works while a host
is in maintenance. You can also set maintenance for a whole group from the group
detail page.

### Force scan

To trigger an immediate scan outside the normal schedule, select **Force Scan**
on the host detail page. This bypasses the schedule and runs at highest priority.

---

## Compliance exceptions

A compliance exception is a documented, operator-approved waiver for a failing
rule on a host: accepted risk ("rule X on host Y is accepted because Z, until
date D"). Exceptions are governed through a request and approval workflow.

**Overlay model (important):** an exception **never changes a rule's scan
verdict**. A failing rule with an active exception still shows as failing in the
raw results and still counts against the raw compliance score. Kensa's verdict
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
2. Select **Request exception** in its row.
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

## Alert management

Alerts are generated automatically when scan results meet configured thresholds.

### Alert categories

| Category | Alert Types |
|----------|-------------|
| Compliance | Critical finding, high finding, score drop, non-compliant, degrading trend |
| Operational | Host unreachable, scan failed, scheduler stopped, scan backlog |
| Exception | Exception expiring, exception expired, exception requested |
| Drift | Configuration drift, unexpected remediation, mass drift |

### Viewing alerts

Navigate to **Alerts** in the sidebar. The alert list shows all active,
acknowledged, and recently resolved alerts.

Use filters to narrow by:

- **Status**: active, acknowledged, silenced, resolved, dismissed
- **Severity**: critical, high, medium, low, info
- **Category**: compliance, operational, exception, drift

### Alert lifecycle

```
Active --> Acknowledged --> Silenced --> Resolved --> Dismissed
```

Transitions do not have to pass through every state in order; each of
Acknowledged, Silenced, Resolved, and Dismissed can follow directly from
Active (see the state list above).

- **Active**: Alert generated, requires attention.
- **Acknowledged**: Select **Acknowledge** to indicate you are investigating.
- **Silenced**: Select **Silence** to suppress an alert until a chosen time,
  without resolving it.
- **Resolved**: Select **Resolve** after the issue is fixed or accepted.
- **Dismissed**: Select **Dismiss** to close an alert that requires no further
  action (for example, a false positive).

### Configuring thresholds

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

## Exporting for audits

For the audit trail itself, `GET /api/v1/audit/events/export` (`audit:read`)
downloads the events matching the same filters as `GET /api/v1/audit/events`
(`action`, `actor_type`, `resource_type`, `resource_id`, `since`, `until`) as a
synchronous CSV or JSON attachment, capped at 10,000 rows newest-first. There
is no saved-query library, no preview step, no background/async generation,
and no checksum or expiry on this export. It downloads immediately with the
filters you pass.

```bash
curl -k "https://localhost:8443/api/v1/audit/events/export?format=csv&since=2026-06-01T00:00:00Z" \
  -H "Authorization: Bearer $TOKEN" -o audit-events.csv
```

For a curated, point-in-time compliance artifact instead of raw events, use
the **Reports** page (`/api/v1/reports`): it generates a Fleet Compliance
Executive Summary that is Ed25519-signed and content-addressed
(`content_sha256`), and can be exported as JSON, PDF, or (for the attestation
report kind) CSV.

---

## What's next

- [Hosts and remediation](HOSTS_AND_REMEDIATION.md): managing hosts and fixing findings
- [User roles](USER_ROLES.md): role-based access control
- [API guide](API_GUIDE.md): REST API for automation and scripting

---

## Appendix: API automation

For operators who want to script scanning workflows or integrate with CI/CD
pipelines, here are the key API endpoints.

### Start a scan

Enqueue an on-demand scan for one host. The scan runs the full Kensa rule corpus
(frameworks are lenses applied to the results, not a scan parameter). The call
returns `202` with the new scan id; the scan itself runs asynchronously on the
worker.

```bash
curl -k -X POST https://localhost:8443/api/v1/hosts/HOST_UUID/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: $(uuidgen)"
```

### Query compliance (current lens)

Per-host compliance is read from the host's lens, not a `/compliance/posture`
endpoint. Add `?framework=cis-rhel9-v2.0.0` to project a specific framework.

```bash
curl -k "https://localhost:8443/api/v1/hosts/HOST_UUID/compliance" \
  -H "Authorization: Bearer $TOKEN"
```

### Query compliance trend

Point-in-time posture history is served as a trend over the last N days (daily
posture snapshots), not an `as_of` query.

```bash
curl -k "https://localhost:8443/api/v1/hosts/HOST_UUID/compliance/trend?days=30" \
  -H "Authorization: Bearer $TOKEN"
```

### List alerts

```bash
curl -k "https://localhost:8443/api/v1/alerts?state=active" \
  -H "Authorization: Bearer $TOKEN"
```

### Acknowledge an alert

```bash
curl -k -X POST "https://localhost:8443/api/v1/alerts/ALERT_ID:acknowledge" \
  -H "Authorization: Bearer $TOKEN"
```

### Export audit events

The audit export is a `GET` with query filters (defaults to CSV); add filters
like `action`, `actor_type`, `resource_type`.

```bash
curl -k "https://localhost:8443/api/v1/audit/events/export?format=csv" \
  -H "Authorization: Bearer $TOKEN" -o audit.csv
```

See the [API guide](API_GUIDE.md) for the complete endpoint reference.
