# Reports — Design & Architecture

**Status:** Proposed (design). Supersedes the thin executive-only MVP.
**Last updated:** 2026-06-21
**Owner:** (unassigned)
**Related:** `internal/report/`, `internal/scanresult/`, `internal/fleetrollup/`,
`internal/posture/`, `internal/exception/`, `internal/queue/`,
`specs/api/reports.spec.yaml`, `specs/frontend/reports.spec.yaml`,
prototype `docs/engineering/prototypes/openwatch-v1/Reports.html`.

---

## 0. Why this doc exists

`/reports` today is a deliberately thin MVP: one report kind
(`executive`), JSON only, generated synchronously in the request, no
export, no signing, no scheduling, no scope picker. The Templates and
Scheduled tabs are honest `ComingSoon` stubs.

The goal of this document is to define a reports system that serves the
four audiences who actually consume compliance output — **operators,
leadership (CISO), auditors, and compliance/GRC** — without ever
producing the thing that makes compliance reporting hated: a
thousand-page PDF nobody reads.

**The central design problem.** A naive "report" at fleet scale —
100+ hosts × ~500 rules — is ~50,000 result rows. Rendered as one PDF
that is 1,000+ pages. That artifact is useless to every persona: the
CISO won't read it, the auditor can't sample it efficiently, the
operator can't act on it, and the GRC tool can't ingest it. The
architecture below exists to make that artifact structurally
impossible to generate by accident.

**The good news.** Every input a great reports system needs already
exists as data in OpenWatch (see §9). This is a rendering, aggregation,
and delivery problem — **not** a data-collection one. Reports *derive*
from scan truth, so they cannot drift from it.

---

## 1. Design principles

### P1 — A report is a *snapshot with faces*, not a document

A report is **one immutable, signed, point-in-time snapshot**. PDF, CSV,
OSCAL, JSON, and the in-app view are **projections (faces)** of that
single snapshot, not independent documents.

Consequences:

- **Sign the snapshot once.** Every face inherits verifiability — there
  is no per-format signing and no way for two faces to disagree.
- **"Data as of" and the coverage caveat are snapshot properties**,
  identical across every face. The CISO's PDF and the auditor's CSV are
  guaranteed to describe the same fleet at the same instant.
- **Never regenerate — re-render.** Asking for the OSCAL of an existing
  report renders a new face over the frozen snapshot; it never
  re-samples the fleet.

### P2 — Format follows *audience × cardinality*

|                | Summary (low cardinality)            | Bulk evidence (high cardinality)                  |
| -------------- | ------------------------------------ | ------------------------------------------------- |
| **Human**      | **PDF** — narrative, bounded, signed | **In-app drill** (query, don't paginate) + **CSV** |
| **Machine**    | **JSON rollup** (dashboards, API)    | **OSCAL bundle / NDJSON** — async, streamed       |

The **human × bulk** cell is the 1,000-page PDF. **That cell stays
empty.** Humans who need bulk evidence either drill interactively or
sample in a spreadsheet; machines ingest OSCAL. A PDF that tries to be
complete evidence is using the wrong tool.

### P3 — The PDF is bounded by construction

A report PDF's page count MUST be `O(controls + exceptions + sampled
findings)`, never `O(hosts × rules)`. Full evidence is **referenced by
hash** and shipped as the attached OSCAL/CSV face:

> Complete evidence: `openwatch-fleet-2026-05.oscal.json` —
> SHA256 `abc1234…` — 50,000 observations.

The auditor samples the PDF; the attached bundle is complete and
independently verifiable. Sampling rule: top-N failing findings per
control inline, the remainder "by reference."

### P4 — Reports are *derived*, never *collected*

No report introduces new data collection. Each report kind is an
aggregation + render over tables that already exist (§9). This makes
report kinds cheap to add and impossible to drift from the scan results
they summarize.

### P5 — Fleet-scale generation is asynchronous

A fleet OSCAL/PDF over 100+ hosts cannot be produced inside an HTTP
request. Generation is **queued** (existing PG `SKIP LOCKED` job queue),
executed in a worker, and the caller is **notified when ready**
(in-app notification bell + optional scheduled email). The synchronous
path is retained only for the small, bounded executive JSON.

### P6 — Integrity is first-class

Every snapshot is **content-addressed and Ed25519-signed**, verifiable
offline. A report discloses its own coverage gaps (stale/unreachable
hosts) — *staleness honesty is what earns auditor trust*, and it is the
single most important non-obvious feature in the prototype.

---

## 2. The four personas (what each would *love* to see)

### Operator — sysadmin / security engineer

Does **not** want a "report" — wants a **worklist**.

- Failing rules ranked by **blast radius** ("CIS-3.5.1.1 fails on 18 of
  20 hosts").
- **Projected lift**: "run the Enable-host-firewall remediation group →
  CIS +7, STIG +6 across 18 hosts."
- **What changed since last period** — regressions first.
- Lives **in-app, interactive**; exports **CSV** into ticketing.
- Rarely opens a PDF.

Primary face: **in-app drill + CSV**.

### Leadership — CISO

Wants **one number, the trend, and "are we getting better or worse."**

- Fleet average compliance + **trend delta** (the delta matters more
  than the absolute).
- Top 3–5 risks framed as **business risk**, not rule IDs.
- Coverage honesty + 2–3 recommended actions.
- 1–2 pages, forwardable to a board.

Primary face: **signed PDF**, scheduled to inbox. (The prototype's
Executive Summary is the reference design.)

### Auditor

Wants **evidence of control satisfaction at a point in time** —
complete, verifiable, navigable — **and samples rather than reading
everything.**

- **OSCAL SAR** (machine-complete) + a navigable evidence path:
  control → all hosts' status → one host's evidence.
- PDF attestation = cover + **methodology** + **coverage** (which hosts,
  when) + framework rollup + **sampled** findings + **signature**. An
  index into the complete bundle, not the bundle.
- **CSV** is their real bulk tool (pivot 50k rows in seconds).
- Cares about chain-of-custody and the scan method.

Primary faces: **OSCAL SAR + CSV + bounded PDF attestation**.

### Compliance / GRC officer

Wants **gaps and a plan toward authorization.**

- Framework posture mapped to an authorization boundary.
- **Exception register**: waiver, justification, approver, expiry.
- **POA&M**: each finding → milestone → target date, tracked over time.

Primary faces: **OSCAL POA&M + Exception Register (PDF/CSV) + framework
rollup**. OpenWatch can serve this persona unusually well because
exceptions and remediation transactions are already first-class.

---

## 3. Report kinds catalog

Mapped from the prototype's six templates onto existing data sources.
Each kind is a `(snapshot builder, faces[])` pair.

| Kind                     | Audience        | Faces                       | Derived from                                                            |
| ------------------------ | --------------- | --------------------------- | ---------------------------------------------------------------------- |
| **Executive Summary**    | Leadership/CISO | PDF, JSON                   | `fleetrollup` + `posture_snapshots` (trend) + `host_liveness` (coverage) |
| **Framework Attestation**| Auditor/GRC     | OSCAL SAR, CSV, PDF         | `scan_results` + `scan_evidence` (per-scan OSCAL aggregated), `exceptions` |
| **Remediation Activity** | Operations      | CSV, JSON, PDF              | remediation `transactions` (committed / rolled_back over a period)     |
| **Exception Register**   | Compliance/GRC  | PDF, CSV                    | `internal/exception` (waiver, justification, approver, expiry)         |
| **Host Evidence Pack**   | Per-host audit  | PDF (per host), OSCAL, CSV  | `scan_results` + intelligence snapshot + scan history for one host     |
| **Drift & Trend**        | Management      | PDF, CSV                    | `transactions` (state changes) + `posture_snapshots` (history)         |
| **POA&M** (Phase D)      | GRC             | OSCAL POA&M                 | open findings + remediation milestones + exception expiries            |

---

## 4. Data model

### 4.1 The snapshot

```
report_snapshots
  id              uuid pk
  kind            text         -- executive | attestation | remediation | exception | host_evidence | drift | poam
  scope           jsonb        -- {groups:[], framework:"cis"|null, period:{from,to}|null, host_ids:[]|null}
  data_as_of      timestamptz  -- the sample instant (frozen)
  coverage        jsonb        -- {hosts_total, hosts_fresh, hosts_stale, hosts_unreachable, stale_host_ids:[]}
  content_sha256  text         -- content address of the canonical snapshot bytes
  signature       bytea        -- Ed25519 over content_sha256 (nullable until signing lands)
  signing_key_id  text
  generated_by    text         -- principal id or "system"/"scheduler"
  created_at      timestamptz
```

The **canonical snapshot** is a deterministic, sorted JSON document
holding every datum any face needs (rollups, per-(host,rule) outcomes
referenced by evidence hash, exceptions in scope, trend series). It is
content-addressed and signed once. Faces are pure functions of it.

> Migration note: the current `reports` table (migration 0028) is the
> executive-JSON MVP. `report_snapshots` generalizes it; the executive
> kind migrates onto it as the first kind, preserving the existing wire
> contract as the JSON face.

### 4.2 Faces

A face is rendered on demand and cached by `(snapshot_id, face)`:

```
report_faces
  snapshot_id  uuid fk -> report_snapshots
  face         text     -- pdf | csv | oscal_sar | oscal_poam | json | ndjson
  media_type   text
  size_bytes   bigint
  blob_sha256  text     -- content-addressed; large faces stored in the blob store, streamed
  status       text     -- pending | ready | failed   (async render)
  created_at   timestamptz
  primary key (snapshot_id, face)
```

Small faces (JSON, exec PDF) may render synchronously. Large faces
(fleet OSCAL, full CSV) are queued and flip `pending → ready`, at which
point the notification bell fires.

### 4.3 Signing

Ed25519 over `content_sha256`. The key is the same class of release
signing OpenWatch already operates; verification is offline
(`SHA256SUMS.asc`-style, or an in-product "Verify signature" action as
in the prototype). The reserved `audit_events.signature` work
(activity-readability Phase 5, AU-9) and report signing should share one
signing service.

> **Open item:** align OSCAL version. `internal/scanresult` emits OSCAL
> **1.0.6**; the prototype mock shows **1.1.2**. Pick one (recommend the
> newest NIST stable) and use it across per-scan and fleet OSCAL.

---

## 5. Format-by-format scale strategy

- **PDF** — bounded by P3. Page budget + sampling rule. Deterministic
  size regardless of fleet count. Rendered from the snapshot's rollup +
  a sampled findings slice + a hash pointer to the bundle.
- **CSV** — the bulk workhorse. One row per `(host, rule)`:
  `host, ip, group, os, rule_id, title, status, severity,
  framework_refs, evidence_sha256, scan_at, exception_id`.
  100×500 = 50k rows is trivial for CSV and instantly pivotable. **Apply
  the existing CSV formula-injection guard** (`csvSafe`, CWE-1236, shared
  with the audit export) and the truncation-disclosure header.
- **OSCAL** — evidence is **already content-addressed**, so observations
  reference evidence **by hash** (no duplication). Two viable shapes:
  (a) one fleet SAR with hash-referenced evidence; (b) per-host/group
  **shards with an assembly index** via OSCAL back-matter resources.
  Generated async; streamed as a zip bundle or NDJSON. Reuses the
  per-scan reconstruction (`scanresult.ReconstructScan`).
- **JSON rollup** — small; the summary numbers for dashboards/API.
- **In-app** — virtualized, query-driven drill
  (fleet → framework → control → host → rule → evidence). Never
  materialize the whole tree.

A direct answer to the framing question: **every-host-every-rule OSCAL
rendered to PDF is 1,000+ pages — which is exactly why OSCAL is never
rendered to PDF.** OSCAL is a machine format for a GRC tool; the human
PDF is a separate, bounded face over the same snapshot. The prototype's
instinct to keep them as two different viewers is correct.

---

## 6. In-app view vs export

- **In-app** is the *query/drill* surface and the *preview*. The
  executive face renders in-app exactly as the PDF will (the prototype
  does this). For bulk kinds, in-app is the interactive evidence
  explorer — not a paginated render of the export.
- **Export** is the *frozen artifact*: PDF for humans, OSCAL/CSV/JSON for
  machines and spreadsheet sampling. Every export carries the snapshot's
  signature and "data as of."
- The Library lists **snapshots**; each row offers its available faces
  (the prototype's "PDF", "OSCAL · PDF", "JSON" format column).

---

## 7. Generation & delivery pipeline (friction-free)

1. **Template pre-scopes** the report by persona (prototype Templates
   tab).
2. **Scope picker**: groups / framework lens / period / (optional)
   explicit host set.
3. **Build snapshot** → content-address → sign. Small kinds inline;
   fleet kinds **enqueue** (`internal/queue`).
4. Worker renders the requested faces; flips `report_faces.status` to
   `ready`.
5. **Notify when ready** — the in-app **notification bell** (currently a
   P1 stub) gains its first real producer; optional **email delivery**
   via the existing notification-channel dispatch.
6. **Scheduled reports** (prototype Scheduled tab): a scheduler tick
   enqueues a snapshot on a cadence and delivers faces to recipients.

This is the symbiosis worth calling out: **reports give the
notification bell a reason to exist, and the bell makes async reports
feel instant.** Build them aware of each other.

---

## 8. Phasing

### Phase A — Executive report, real for humans
- Signed, **bounded PDF** face for the executive kind.
- Auto-generated **coverage caveat** (stale/unreachable disclosure from
  `host_liveness`).
- **Scope picker**: group / framework lens / period (built on
  `fleetrollup` + `posture_snapshots`).
- Migrate `reports` → `report_snapshots` + `report_faces`; keep the
  executive JSON wire contract as the JSON face.
- Establishes snapshot-with-faces + the signing service.
- **Specs:** `api-reports` v2, `frontend-reports` (Library detail + PDF
  viewer + scope picker), new `system-report-snapshot`.

### Phase B — The scale-correct bulk path
- **Framework Attestation**: fleet **OSCAL SAR** (aggregate per-scan
  OSCAL) + **CSV** evidence extract.
- **Async** generation via the job queue; `report_faces` status flips.
- Sampling rule for the PDF attestation; hash pointer to the bundle.
- Solves the 1,000-page problem properly; serves auditor/GRC.
- **Specs:** extend `api-reports` (async + export endpoints + content
  negotiation), `system-report-faces`.

### Phase C — Delivery spine
- **Scheduled** reports + **email delivery** (notification-channel
  dispatch) + the **notification bell** "ready" signal.
- Add **Exception Register** + **Remediation Activity** kinds (data
  already exists).
- **Specs:** `system-report-schedule`, `frontend-reports` Scheduled tab.

### Phase D — GRC depth
- **POA&M** (OSCAL) — open findings → milestones → target dates,
  tracked over time.
- **Host Evidence Pack** + **Drift & Trend** kinds.

---

## 9. What we build on (existing capabilities)

| Need                         | Exists as                                  |
| ---------------------------- | ------------------------------------------ |
| Per-(host,rule) outcomes     | `host_rule_state`                          |
| Durable per-scan evidence    | `scan_results` + `scan_evidence` (content-addressed) |
| Per-scan OSCAL               | `scanresult.ReconstructScan` (OSCAL 1.0.6) |
| Live fleet aggregations      | `internal/fleetrollup` (score, liveness, top-failing rules/hosts, recent changes) |
| Trend history               | `internal/posture` → `posture_snapshots` (daily per host) |
| Drift (state changes)        | `transactions`                             |
| Exceptions/waivers           | `internal/exception`                       |
| Remediation history          | remediation `transactions`                 |
| Coverage / staleness         | `host_liveness`                            |
| Async execution              | `internal/queue` (PG `SKIP LOCKED`)        |
| Email delivery               | `internal/notification` dispatch           |
| Ready signal                 | in-app notification bell (P1 stub — first real producer) |
| Signing                      | release signing class; shared with AU-9 audit signing |

---

## 10. Open decisions

1. **OSCAL version** — align per-scan (1.0.6) and the prototype (1.1.2)
   on one version.
2. **Fleet OSCAL shape** — single SAR with hash-referenced evidence vs.
   per-host/group shards + assembly index. Recommend shards + index for
   100+ hosts (bounded memory, resumable).
3. **Retention** — reports are immutable + signed; define a retention
   window (prototype says "retained 1 year") and whether snapshots are
   purgeable. Relate to the audit retention sweep (AU-11).
4. **Signing key custody** — where the report signing key lives and how
   "Verify signature" works in-product and offline.
5. **Snapshot storage budget** — a fleet snapshot is ~50k rows of
   canonical JSON; store compressed in the blob store, not inline JSONB.
