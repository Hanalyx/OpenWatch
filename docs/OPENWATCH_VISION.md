# OpenWatch Vision

**Status:** Founding document, draft v1
**Companion documents:**
- `KENSA_VISION.md` — the transactional primitive OpenWatch is built on
- `HANALYX_MISSION_AND_ROADMAP.md` — company mission and 18-month trust roadmap
- `HANALYX_18_MONTH_STRATEGY.md` — tactical strategy and 90-day plan
- `AI_DEFENSIBILITY.md` — why Hanalyx becomes more valuable as AI improves

---

## What OpenWatch Is

**OpenWatch is the fleet eye, the heartbeat, and the control plane for Kensa.**

Kensa is a passive primitive. It acts only when invoked. It remembers nothing across runs. It knows how to capture, apply, validate, and roll back — but it does not know when to do so, which hosts to do it on, or what happened yesterday. Left alone, Kensa does nothing.

OpenWatch is what turns Kensa from a CLI tool into continuous, proactive, observable infrastructure. It decides when Kensa runs. It remembers every transaction Kensa has ever executed. It notices when today differs from yesterday. It alerts humans to drift. It orchestrates transactions across fleets. It provides the audit trail. It is where the passive primitive becomes an active system.

**Kensa is the transaction. OpenWatch is the fleet that runs on it.**

---

## The Frame: git is to GitHub as Kensa is to OpenWatch

The cleanest mental model for how Kensa and OpenWatch relate is git and GitHub. The pattern repeats because it is correct for a whole class of products.

| git | Kensa | GitHub | OpenWatch |
|---|---|---|---|
| Open-source plumbing | Open-source plumbing | Hosted porcelain | On-prem or hosted porcelain |
| Local, stateless | Local, stateless | Stateful, persistent | Stateful, persistent |
| Powerful primitive | Powerful primitive | Multiplies git's value | Multiplies Kensa's value |
| Used by developers who know it | Used by compliance engineers who know it | Where most users actually work | Where most users actually work |
| Credibility-bearing | Credibility-bearing | Revenue-bearing | Revenue-bearing |
| Can be used alone | Can be used alone | Cannot exist without git | Cannot exist without Kensa |
| Most people don't use it alone | Most people won't use it alone | — | — |

git without GitHub is a programmer's tool. GitHub without git is a dashboard with nothing underneath. They need each other, they reinforce each other, and they divide labor cleanly: one is the open primitive that earns trust through auditability, the other is the product people actually pay for.

Kensa and OpenWatch should be thought of the same way. **Kensa must remain open source, visible, auditable, and community-facing — because credibility demands it and because it is the primitive that defines the category. OpenWatch must become continuous, proactive, and transactional — because it is where value is delivered to customers and where revenue lives.**

This is the architecture of a successful open-core company. It is not an accident that GitHub, GitLab, Grafana, MongoDB, Elastic, Sentry, and HashiCorp all run versions of this pattern. It works because it resolves the central tension in selling infrastructure software: customers need the engine to be transparent, and the company needs the product to be ownable.

---

## The Three Identities of OpenWatch

OpenWatch has three architectural identities. Each one corresponds to a specific customer need and a specific part of the codebase. The three together define what OpenWatch is for.

### 1. The Eye

**OpenWatch is the continuous, comprehensive view of the transactional state of every Linux host under management.** Every change Kensa has ever captured, applied, validated, committed, or rolled back — on every host, across every fleet — is visible here. Nothing is lost. Nothing is invisible. If it happened on a managed host, OpenWatch saw it and recorded it.

The Eye is the component that makes the product trustworthy. You cannot sell "every change is auditable" unless you have a system that actually captures and retains every change in a queryable form. The Eye is that system.

This identity is delivered by the **transaction log** — the primary data structure of OpenWatch, the thing customers look at first, the thing auditors export from, and the thing AI agents will eventually read and write against.

### 2. The Heartbeat

**OpenWatch is continuously and proactively aware of every host's state — not just when a human asks.** The heartbeat runs whether a human is watching or not. It scans hosts on a schedule. It detects drift from baseline. It raises alerts when something changes. It tracks host liveness, reachability, and responsiveness. It is the difference between a tool that answers questions and a tool that tells you when you need to ask one.

The heartbeat is how OpenWatch earns the "continuous compliance" and "continuous state assurance" claims that federal continuous monitoring requires and that commercial SREs intuitively want. It is also the component that makes the Eye's data current — without a heartbeat, the Eye is a photograph, not a live feed.

### 3. The Control Plane

**OpenWatch is where humans and (eventually) AI agents issue instructions to the fleet.** A human who wants to apply a change across 500 hosts describes it in OpenWatch, reviews the preview (what will be captured, what will be applied, what validation will run, what rollback will occur on failure), approves, and OpenWatch orchestrates the transaction across the fleet. The result flows back into the transaction log.

This identity is what turns OpenWatch from a dashboard into infrastructure. A dashboard is something you look at. A control plane is something you operate through. The difference is the difference between Grafana and Kubernetes.

The Control Plane is also the surface that the eventual AI-agent use case will consume. An agent in 2027 or 2028 that wants to apply a change to production does not talk to Kensa directly. It talks to OpenWatch's Control Plane API, which enforces authorization, records intent, captures the transaction, and provides the audit trail. Humans approve; agents operate; OpenWatch mediates.

---

## The Core Architectural Commitment

Every feature in OpenWatch must serve one or more of the three identities above. Features that do not serve any of them do not ship.

Concretely:

- **Scan scheduling** → Heartbeat
- **Drift detection** → Heartbeat → Eye
- **Transaction log UI** → Eye
- **Evidence export (OSCAL, signed bundles)** → Eye
- **Exception workflow** → Control Plane
- **Multi-host orchestration** → Control Plane
- **RBAC, SSO, audit log** → Control Plane
- **API for programmatic access** → Control Plane (future: agents)
- **Alerting and notification** → Heartbeat → Control Plane
- **Host health / liveness monitoring** → Heartbeat
- **Historical posture queries** → Eye
- **Baseline management** → Heartbeat → Eye

Features that do not fit this model — third-party scanner ingestion, cloud provider integrations that aggregate foreign findings, CI/CD security scanning, generic observability dashboards — do not ship. They expand OpenWatch's scope at the cost of its identity. OpenWatch is not a compliance aggregator. It is the Eye, the Heartbeat, and the Control Plane for Kensa transactions.

---

## The Transaction Log as Primary Interface

The most important architectural decision in the next six months is to make the **transaction log** the primary interface of OpenWatch, replacing the current organization around "scans," "findings," and "reports."

### What the transaction log contains

Every entry is a Kensa transaction with:

- **Timestamp and duration**
- **Host and fleet context**
- **Initiator** (human user, scheduled job, drift trigger, AI agent)
- **Pre-state capture** — the exact state of the system before the change
- **Change applied** — the specific remediation handler and parameters
- **Validation result** — did the change produce the intended effect
- **Commit or rollback decision**
- **Post-state** — the exact state of the system after commit, or restored pre-state after rollback
- **Evidence envelope** — structured, signable, exportable to OSCAL
- **Framework mappings** — which compliance controls this transaction satisfies (CIS, STIG, NIST, etc.) — as metadata, not as the primary organizing principle

### Why this reframing matters

- **One data model serves three audiences.** SREs see "what changed." Compliance officers see "what was remediated." Auditors see "the evidence trail." All three views come from the same log; only the filter and the UI differ.
- **It maps 1:1 to the Kensa vision.** Kensa's four phases (capture, apply, validate, commit-or-rollback) are exactly the fields of a transaction log entry. No impedance mismatch between the engine and the product.
- **It is the right surface for the AI-agent future.** When an agent needs to apply a change, it writes a transaction intent to the log. When it needs to understand fleet state, it reads the log. The log is the API.
- **It differentiates from every other compliance tool.** No competitor organizes around transactions. They all organize around findings (scanner mindset) or controls (GRC mindset). The transaction log is a category-defining UI, not just a rename.

### What this replaces

- The current "Scans" top-level navigation becomes "Transactions."
- "Findings" becomes a filtered view of the transaction log (transactions with status = fail).
- "Reports" becomes exports generated from the transaction log.
- "Compliance status" becomes aggregate queries against the transaction log over time ranges.
- The database schema is refactored to treat `scans` + `scan_results` + `scan_findings` as a single `transactions` table, with the existing fields reorganized around the four-phase model.

This is the single highest-leverage change to OpenWatch in the next six months. It is mostly a data-model refactor and UI reorganization, not new feature work. It pays for itself by making every subsequent feature simpler to build.

---

## What OpenWatch Must Never Become

As important as naming what OpenWatch is: naming what it is not, so scope creep does not dilute the identity.

- **OpenWatch is not a compliance aggregator.** It does not ingest findings from Tenable, Qualys, Rapid7, OpenSCAP, or any other scanner. It records Kensa transactions. Customers who want a compliance aggregator should buy a compliance aggregator.
- **OpenWatch is not a GRC platform.** It does not track policies, manage SOC 2 evidence collection, or produce organization-wide compliance dashboards across non-Linux systems. Drata, Vanta, and Secureframe exist for that. OpenWatch is focused on the Linux transactional layer.
- **OpenWatch is not an observability tool.** It does not replace Datadog, Grafana, Prometheus, or New Relic. It tells you what changed, not what is happening. The heartbeat is about state, not about metrics and logs.
- **OpenWatch is not a configuration management system.** Customers should still use Ansible, Chef, Puppet, or Salt for day-to-day provisioning. OpenWatch is where those changes become transactional and auditable — not where they originate.
- **OpenWatch is not a multi-cloud security posture management tool.** It does not talk to AWS Security Hub, Azure Defender, or GCP SCC. It manages Linux hosts directly. Cloud-native posture management is a different market with different competitors and Hanalyx does not play there.
- **OpenWatch is not a scanner without Kensa.** Every transaction runs through the Kensa primitive. There is no parallel scanning path. The architectural commitment is that Kensa is the only engine underneath.

Each of these constraints is load-bearing. Violating any one of them dilutes the identity of the product and pushes it toward being a generic compliance platform — a space where we cannot compete and would not want to.

---

## 12–18 Month Milestones

These milestones are organized around the three identities. They connect directly to the trust moats in `HANALYX_MISSION_AND_ROADMAP.md` — every milestone serves at least one moat.

### Quarter 1 (Months 0–3): Transaction log reframing and heartbeat foundations

**The Eye**
- [ ] Refactor database schema: unify `scans`, `scan_results`, `scan_findings`, `scan_baselines`, `scan_drift_events` around a single `transactions` table with the four-phase model (capture, apply, validate, commit/rollback).
- [ ] Ship the transaction log as the primary top-level UI in OpenWatch. Replace "Scans" / "Findings" / "Reports" navigation with "Transactions."
- [ ] Implement per-transaction detail view: full pre-state, apply, validate, commit/rollback, post-state, evidence envelope, framework mappings as metadata.

**The Heartbeat**
- [ ] Scheduled scans enabled by default on every onboarded host. Remove the opt-in barrier.
- [ ] Host liveness monitoring: last-seen timestamp, reachability check, response time tracking on every managed host.
- [ ] Fleet-level health view: all hosts up, last scan successful, drift events in the last 24 hours visible at a glance.

**The Control Plane**
- [ ] Slack + Jira integration (outbound alerts and bidirectional ticket sync for drift events and failed transactions).
- [ ] SAML/OIDC SSO — required for enterprise and federal sales.

**Moat connection:** Track Record (Eye makes the log auditable from day one), Community (clean data model is foundation for community rule contributions).

---

### Quarter 2 (Months 3–6): Evidence export and auditor-grade outputs

**The Eye**
- [ ] OSCAL export from the transaction log. Every transaction in the log can be exported as an OSCAL-formatted evidence bundle.
- [ ] Signed evidence bundles using Ed25519. Signing key managed per deployment, with published verification instructions.
- [ ] Per-host audit timeline view: every transaction that has ever touched this host, with filter, search, and export.
- [ ] Transaction log retention policy, configurable per fleet.

**The Heartbeat**
- [ ] Drift detection running automatically on every scheduled scan, with no configuration required.
- [ ] First-class drift alert notifications via Slack, email, and webhook.
- [ ] Baseline auto-management: first scan establishes baseline, subsequent scans measured against it, baseline can be explicitly updated.

**The Control Plane**
- [ ] Scheduled scan management UI: when, how often, which rules, which hosts, with a clear preview of what each scheduled scan will do.
- [ ] Exception workflow UI for the transaction log: mark a transaction as accepted (risk acknowledged), escalate, or request re-remediation.

**Moat connection:** Auditor Relationships (OSCAL + signed bundles are the concrete artifacts we will brief auditors on), Liability (the signed evidence is what makes the production SLA defensible).

---

### Quarter 3 (Months 6–9): Proactive remediation and control plane maturity

**The Eye**
- [ ] Query API for the transaction log: REST endpoint that accepts filters (host, fleet, date range, status, mechanism, framework) and returns paginated transactions. This is the foundation of both the advanced UI and the future agent API.
- [ ] Historical posture queries: "what was fleet X's compliance state on date Y?" answered in under 500ms from the transaction log.
- [ ] First public **"State of Production Rollback"** report generated from anonymized aggregate transaction log data across lighthouse customers.

**The Heartbeat**
- [ ] **Proactive remediation workflow:** when drift is detected, OpenWatch automatically drafts a proposed remediation transaction (capture plan, apply plan, validation plan, rollback plan) and raises it to a human for approval. One-click approve → transaction runs → result flows back into the log.
- [ ] Alert routing rules: different drift severities go to different channels (Slack, email, PagerDuty, ticketing).
- [ ] Heartbeat performance: every managed host scanned at least every 6 hours by default, with per-host override.

**The Control Plane**
- [ ] RBAC with role-based approval requirements: certain transactions (e.g., grub parameter changes) require two-human approval before execution.
- [ ] Fleet grouping and per-group policy: different hosts can have different scan cadences, different approval requirements, different drift thresholds.
- [ ] First batch of user-contributed rules merged from the open-source community (tied to Kensa community work).

**Moat connection:** Track Record (proactive remediation is where customers see the closed-loop story in action), Canonical Upstream (public report establishes Hanalyx as the authority on production rollback statistics).

---

### Quarter 4 (Months 9–12): FedRAMP-ready continuous monitoring

**The Eye**
- [ ] Continuous monitoring reporting that meets federal ConMon requirements: rolling 30-day posture, POA&M integration, continuous compliance dashboards, monthly evidence packages.
- [ ] Per-framework filtered views of the transaction log: "show me all transactions that satisfy NIST 800-53 AC-2 over the last 90 days."
- [ ] Export integration with FedRAMP continuous monitoring tooling.

**The Heartbeat**
- [ ] SLO tracking: uptime of OpenWatch itself, time-to-detect drift, time-to-alert, time-to-remediate. Publicly visible on an internal status page first, then externally.
- [ ] Alerting integrations: PagerDuty, Opsgenie, Microsoft Teams (in addition to existing Slack/email/webhook).

**The Control Plane**
- [ ] Audit log for every Control Plane action: who approved what, when, from where, with what justification. The audit log is itself a set of transactions in the transaction log.
- [ ] First signed **production SLA** offered to paying customers, backed by the transaction log as evidence.
- [ ] First federal customer successfully passing a continuous monitoring review with OpenWatch as the ConMon system.

**Moat connection:** FedRAMP (continuous monitoring is one of the largest control families), Liability (SLA backed by transaction log), Auditor Relationships (first auditor success story).

---

### Quarter 5 (Months 12–15): The agent API surface and hosted control plane

**The Eye**
- [ ] Read-only **Agent API**: authenticated, rate-limited, OpenAPI-specified interface that lets an authorized AI agent query the transaction log, read fleet state, and subscribe to drift events. Not write-enabled yet.
- [ ] Anonymized aggregate telemetry (opt-in) from customer deployments feeding the first cross-customer benchmark dataset.

**The Heartbeat**
- [ ] Multi-region heartbeat: OpenWatch can monitor hosts across geographic regions with appropriate latency and reliability guarantees.
- [ ] Graceful degradation: if OpenWatch loses contact with a host, the Heartbeat explicitly distinguishes "host is down" from "host is unreachable from OpenWatch" and alerts accordingly.

**The Control Plane**
- [ ] **First hybrid deployment:** on-prem Kensa agent pushing signed transaction bundles to a Hanalyx-hosted OpenWatch control plane, as an opt-in upgrade for existing customers. Single-tenant at first.
- [ ] Formal API versioning and deprecation policy for the Control Plane API.
- [ ] First non-founder engineering hire (if hiring timing allows) focused on the Control Plane surface.

**Moat connection:** Canonical Upstream (agent API positions OpenWatch as infrastructure, not a tool), Track Record (hybrid deployment is the beginning of the long-term SaaS option).

---

### Quarter 6 (Months 15–18): Write-enabled agent API and multi-tenant readiness

**The Eye**
- [ ] Public transaction log schema specification, versioned and stable. Third parties can build tools against it.
- [ ] Second **"State of Production Rollback"** report with year-over-year trends.

**The Heartbeat**
- [ ] Heartbeat performance SLA: drift detected within 15 minutes of occurrence on any managed host by default.
- [ ] Predictive heartbeat: OpenWatch flags hosts whose behavior is diverging from the fleet norm before an explicit drift event fires.

**The Control Plane**
- [ ] **Write-enabled Agent API:** an authorized AI agent can propose a transaction, which lands in the approval queue for human review. Approved transactions execute through Kensa and flow back into the log. This is the first version of the "AI agents + humans operating the fleet together" vision.
- [ ] **Multi-tenancy groundwork:** `tenant_id` / `org_id` columns on all relevant tables, row-level security policies, tenant-aware RBAC. Not yet exposed to customers; this is the technical foundation for the potential commercial SaaS wedge at month 18+.
- [ ] Decision point on the commercial SaaS wedge: based on federal ARR, community traction, and agent API interest, decide whether to launch a separate commercial brand on top of the multi-tenant foundation.

**Moat connection:** Canonical Upstream (agent API makes OpenWatch the reference integration point for AI infrastructure), FedRAMP (authorization should land around this time — the multi-tenant groundwork is what makes a hosted FedRAMP offering possible).

---

## KPIs

Measured monthly, reviewed quarterly.

**The Eye**
- Transactions per month (cumulative across customers)
- Percentage of transactions with complete evidence envelopes (target: 100%)
- Time to query the transaction log for a typical historical posture question (target: under 500ms)
- Evidence exports generated per month

**The Heartbeat**
- Percentage of managed hosts scanned in the last 24 hours (target: 99%+)
- Median time from drift event to human alert (target: under 15 minutes)
- False positive rate on drift alerts (target: decreasing over time)
- Host liveness coverage: percentage of managed hosts with current liveness data

**The Control Plane**
- Active users per customer per month
- Transactions initiated from the Control Plane (human-initiated) vs the Heartbeat (automatic) — the ratio tells us how proactive the product has become
- Approval latency: median time from proposed transaction to human approval
- API requests per month (once the Agent API is live)

---

## The One-Line Version

**OpenWatch is the Eye, the Heartbeat, and the Control Plane for Kensa. Kensa is the transaction; OpenWatch is the fleet that runs on it.**

---

## The OpenWatch Landing Page Hero

> ### OpenWatch is the fleet eye, the heartbeat, and the control plane for Kensa.
>
> Continuous visibility into every transactional change across your Linux fleet. Proactive drift detection. Auditor-grade evidence, automatically. One transaction log for humans, compliance teams, auditors, and eventually the AI agents that will operate production alongside them.
>
> *Kensa is the transaction. OpenWatch is the fleet that runs on it.*

---

*End of document.*
