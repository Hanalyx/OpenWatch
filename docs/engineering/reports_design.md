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
- **C1 — Exception Register kind.** *(SHIPPED 2026-06-22, PR #657.)* A
  point-in-time Compliance/GRC read-model of compliance waivers
  (`compliance_exceptions`): a frozen `ExceptionContent` {summary,
  exceptions[]} (counts by state + active/expiring-soon + the register
  rows, requester/reviewer resolved to usernames), a CSV register face, a
  bounded PDF summary face, and a kind-aware in-app `ExceptionBody`.
  Migration 0044 admits `kind='exception'`. Spec: `api-reports` v1.12.0
  (C-17 / AC-23), `frontend-reports` v1.9.0 (C-12 / AC-13).
- **C2 — Remediation Activity kind.** *(SHIPPED 2026-06-22, PR #658.)* A
  read-model of remediation requests over a look-back window
  (`remediation_requests` filtered on `requested_at`): a frozen
  `RemediationContent` {period_from, period_to, summary, activities[]}
  (exact counts by outcome + the activity rows, requester/reviewer resolved
  to usernames), a CSV activity-log face, a bounded PDF summary face, and a
  kind-aware in-app `RemediationBody`. The generate request gains
  `period_days` (1..365, default 30); the UI shows a Last 7/30/90 days
  selector for the kind. Migration 0045 admits `kind='remediation'`. Spec:
  `api-reports` v1.13.0 (C-18 / AC-24), `frontend-reports` v1.10.0
  (C-13 / AC-14).
- **C3 — Scheduled dispatcher.** *(REMAINING.)* **Scheduled** reports +
  **email delivery** (notification-channel dispatch); activates the
  Scheduled tab. Spec: `system-report-schedule`, `frontend-reports`
  Scheduled tab.

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

---

## 11. Phase A — resolved decisions & implementation plan

> **STATUS: Phase A shipped (2026-06-21, PRs #631–#637).** The executive
> report is now scoped (group/framework, A1), coverage-honest (A2),
> content-addressed on the `report_snapshots` + `report_faces` model
> (A3a), with a bounded pure-Go PDF face + export endpoint (A3b) and a
> frontend Download control (A3b-2), Ed25519-signed with offline
> verification (A4a) and a frontend Signed badge + Verify action (A4b).
> Two adjustments to the plan below, made during implementation and noted
> here: (a) the **coverage caveat shipped before the snapshot/faces
> migration** — the migration had no user value until a second face
> existed, so A2 delivered coverage and the structural migration moved to
> **A3a**; (b) A3 and A4 were each split backend/frontend (A3b/A3b-2,
> A4a/A4b) to isolate the fpdf dependency (A3b) and the cookie-auth blob
> download / client-side Web-Crypto verification (frontend slices). The
> §10 signing-key decision resolved as a config-path key
> (`[reports].signing_key_file`) with an ephemeral per-boot dev key.
> **Remaining: Phases B–D** (OSCAL/CSV faces, async + scheduling, the
> other report kinds) — a separate initiative.

Phase A makes the **executive** report real for humans without taking on
the bulk/OSCAL machinery. The §10 decisions are resolved for Phase A as
follows so that *none of them blocks the start*:

| # | Decision | Phase A resolution |
| - | -------- | ------------------ |
| 1 | OSCAL version | **N/A in Phase A** (no OSCAL face). Resolve in Phase B; recommend bumping the per-scan emitter 1.0.6 → the prototype's 1.1.2 there. |
| 2 | Fleet OSCAL shape | **Deferred to Phase B.** |
| 3 | Retention | **Keep indefinitely for now** (matches host soft-delete today); add an operator-configurable window in a later phase. Not blocking. |
| 4 | Signing-key custody | **De-risked:** `report_snapshots.signature` is nullable; **signing is the last Phase A slice (A4)** and is the only step gated on the operator provisioning a key. A1–A3 ship unsigned, then A4 turns signing on. So the open operator decision does not block starting. |
| 5 | Snapshot storage | **Inline JSONB is fine in Phase A** — the executive snapshot is a small rollup, not 50k rows. The compressed blob-store path is introduced in Phase B with the first bulk kind. |

### Slices (each one reviewable PR: spec + migration/code + tests)

**A1 — Scope the executive report.** *(api-reports v1.1.0, additive)*
- `POST /api/v1/reports:generate` accepts an optional scope:
  `{ group_id?, framework? }`. (Period applies to the trend, which
  arrives in A3 — not to the point-in-time snapshot.)
- Framework lens is already supported — `fleetrollup.WithFramework`.
  **Add `fleetrollup.WithGroup(groupID)`** to filter the rollup to a
  group's host membership (groups: migration 0027, `internal/group`).
- Store the resolved `scope` + a derived `scope_label`
  (e.g. "Production · CIS") on the report.
- Frontend: a scope picker (group + framework) on the generate action,
  matching the prototype's Templates builder.
- **Value:** scoped executive reports ("Production / CIS posture"),
  no new architecture yet.

**A2 — Snapshot/faces model + coverage caveat.** *(api-reports v2.0.0;
new `system-report-snapshot`)*
- Migration: `report_snapshots` + `report_faces` (§4). Migrate the
  executive kind onto it; **keep the existing executive JSON as the
  `json` face** so the v1 wire contract (C-01) is preserved unchanged.
- Compute the `coverage` block from `host_liveness`
  (`hosts_total / fresh / stale / unreachable` + `stale_host_ids`) and
  surface the **auto-generated coverage caveat** (P6) in-app.
- **Value:** the trust-critical staleness disclosure; the data model
  every later face/kind reuses.

**A3 — PDF face + in-app viewer parity.** *(api-reports v2.1.0)*
- Bounded server-side executive **PDF** renderer (P3): posture snapshot
  + 30-day trend (from `posture_snapshots`) + KPI strip + coverage
  caveat + framework rollup + top risks + recommended actions — the
  prototype's Executive document.
- Export endpoint: `GET /api/v1/reports/{id}/export?format=pdf|json`
  (content-addressed `report_faces`, streamed as an attachment).
- In-app viewer renders the same document the PDF will (preview ==
  export).
- **Decision for A3:** PDF engine. Prefer a **pure-Go PDF library**
  (airgap-friendly, no headless-browser dependency) over HTML→PDF.
  Confirm the lib choice at A3 start.

**A4 — Signing.** *(extends `system-report-snapshot`)*
- Ed25519 signing service over `content_sha256`; populate
  `report_snapshots.signature` + `signing_key_id`.
- "Verify signature" action in the viewer + offline verification.
- **Gated on:** the signing-key custody decision (§10.4) — recommend a
  dedicated report key provisioned like the release key (mounted secret,
  never in DB; ephemeral dev key when unset). Shares the signing service
  with the reserved `audit_events.signature` work (AU-9).

### Spec footprint
- New: `specs/system/report-snapshot.spec.yaml` (snapshot/faces/signing
  service), registered in `specter.yaml`.
- Bump: `specs/api/reports.spec.yaml` v1.0.0 → v1.1.0 (A1) → v2.x (A2/A3).
- Update: `specs/frontend/reports.spec.yaml` (scope picker, coverage
  caveat, PDF viewer; Templates tab becomes the persona launcher).

### Recommended order
A1 → A2 → A3 → A4. A1 ships visible value immediately and is fully
additive; A2 lays the architecture; A3 delivers the CISO's signed-looking
document; A4 turns on cryptographic signing once the key is provisioned.

---

## 12. Phase B — resolved decisions & implementation plan

Phase B builds the **Framework Attestation** kind: the scale-correct bulk
path (fleet **OSCAL SAR** + **CSV** evidence extract, generated **async**)
for auditors/GRC. Grounded in an infrastructure audit (2026-06-21): the
per-scan OSCAL emitter, the content-addressed evidence store, the
audit-CSV pattern (`csvSafe` + truncation header), the generic job queue,
and the SSE event bus all exist; the gaps are a fleet framework catalog,
a fleet SAR assembler, the async report job, and a "report.ready" event.

### Resolved decisions (the §10 items Phase B touches)

| # | Decision | Phase B resolution |
| - | -------- | ------------------ |
| 1 | OSCAL version | **Stay on 1.0.6.** The per-scan emitter delegates OSCAL marshaling to the Kensa library (`kensapkg.ExportOSCALScan`), which emits **1.0.6 assessment-results**; the version is Kensa-controlled. The fleet SAR must match the per-scan output, so align *down* to 1.0.6 rather than force a Kensa change to chase the prototype's aspirational 1.1.2. Revisit only if a GRC consumer requires 1.1.x (a coordinated Kensa + OpenWatch bump). |
| 2 | Fleet OSCAL shape | **Single `assessment-results` document; evidence REFERENCED by content hash (not inlined); STREAMED to the blob store.** A fleet SAR that inlined 100+ hosts × ~500 rules × up-to-256 KiB evidence is the 1000-page problem in OSCAL form. Instead the SAR carries one observation + finding per `(host, rule)` with the evidence `sha256` as a back-matter resource reference; the bytes stay in `scan_evidence`. Streaming the SAR to the blob bounds memory without the complexity of per-host shards + an assembly index (deferred unless a single SAR proves unwieldy). |
| 3 | Retention | **Keep indefinitely (unchanged).** A retention sweep (AU-11, relate to the host soft-delete sweep) is a later phase. |
| 5 | Snapshot storage | **Bulk-kind content goes to a content-addressed blob, not inline JSONB.** The attestation snapshot is the ~50k-row per-`(host, rule)` result set, too large for the reports row. Reuse the `scan_evidence` content-addressing pattern (or `report_faces.content` bytea, already present) and compress. The executive kind stays inline (small). |

(§10.4 signing-key custody was resolved in A4a: `[reports].signing_key_file`.)

### Slices (each a reviewable PR: spec + migration/code + tests)

**B0 — Fleet framework catalog.** `GET /api/v1/reports/frameworks`
(host:read) returns the distinct `framework_refs` keys present across the
in-scope fleet (`SELECT DISTINCT jsonb_object_keys(framework_refs) FROM
host_rule_state` [scoped]). Small, and it ALSO closes the **A1 deferred
gap**: the frontend framework-lens picker (deferred in A1 for lack of a
catalog) can now populate. Spec: `api-reports`.

**B1 — Attestation kind + CSV face.** A new `attestation` report kind
whose snapshot is `{scope, framework, per-(host,rule) outcomes}`, queried
via `host_rule_state` → `scan_runs` (`last_scan_id`) → `scan_results`. The
CSV face (reusing `csvSafe` + the truncation-disclosure header) streams one
row per `(host, rule)`: host, ip, group, os, rule_id, title, status,
severity, framework_refs, evidence_sha256, scan_at, exception_id. The
snapshot content is blob-stored (compressed). Spec: `api-reports`
(kind=attestation), new `system-report-attestation`.

**B2 — Fleet OSCAL SAR face.** *(SHIPPED 2026-06-21, PR #643.)* Assemble a
single OSCAL 1.0.6 `assessment-results` from the attestation snapshot
(`internal/report/oscal.go`): one result whose findings + observations
carry one entry per `(host, rule)`, reviewed-controls aggregated as
framework-prefixed control-id tokens (digit-leading native ids stay valid
OSCAL tokens), the finding state "satisfied" only on a pass, the host as a
deterministic-v5 inventory-item subject, narrowed by the snapshot's
framework lens. Evidence is REFERENCED by `sha256` in back-matter (an rlink
SHA-256 hash), never inlined as base64 — the bytes stay in `scan_evidence`.
Since Kensa's `ExportOSCALScan` is per-scan and *inlines* evidence, the
fleet assembler is a light hash-referencing custom builder (not Kensa's
exporter), with its own minimal OSCAL structs mirroring the per-scan shape.
Every uuid is a deterministic v5 from the snapshot id, so the document is
byte-deterministic and cached in `report_faces` (face `oscal_sar`, status
`ready`) like the other faces; the assembly is bounded by the same row cap
as the CSV (a metadata prop discloses truncation). `format=oscal_sar` is
attestation-only (executive is `ErrInvalidFace`). Spec: `api-reports`
v1.8.0 (C-14 / AC-20). True streaming to a separate blob store is deferred
(the in-memory + row-cap + `report_faces.content` pattern matches the CSV
face).

**B3b — Bounded attestation PDF face.** *(SHIPPED 2026-06-21, PR #644.)*
The `pdf` face is now KIND-DISPATCHED (`internal/report/export.go`): an
executive report renders the executive summary PDF, an attestation report
renders a bounded one-page cover (`renderAttestationPDF` in `pdf.go`) —
methodology note, aggregate attestation coverage + framework rollup
(compliance %, checks evaluated, pass/fail/skipped/error), a SAMPLED
top-failing list, and a footer carrying the snapshot content hash + signing
status as the pointer to the bulk faces. The rollup is O(1) in fleet size
(aggregate `count(*) FILTER` over the frozen scans + a top-N grouped query,
framework-lensed), so the PDF stays bounded. Cached in `report_faces` (face
`pdf`) like the others. Spec: `api-reports` v1.9.0 (C-15 / AC-21; C-10
updated: pdf kind-dispatched, not executive-only).

**B3a — Async generation + report.ready.** *(SHIPPED 2026-06-21, PR #646.)*
Generating an attestation marks its bulk faces (`csv`, `oscal_sar`, `pdf`)
`pending` in `report_faces` and enqueues a `report.render` job
(`internal/report/job.go`), returning immediately (the executive summary
stays synchronous). A `RenderProcessor` registered on the in-process worker
(`worker.WithReportProcessor`) claims the job, renders each face via
`Export` (flipping `pending → ready`; a render error marks the face
`failed` and fails the job for retry), and publishes
`EventKindReportReady` on the event bus — **the in-app notification bell's
first producer**. Async is an optimization, not a correctness gate: `Export`
stays the lazy fallback so a download before the job runs still renders
inline. Spec: `api-reports` v1.10.0 (C-16 / AC-22) + the new eventbus kind.

**B3c — Notification bell (frontend).** *(SHIPPED 2026-06-21, PR #647 —
conservative MVP.)* The stubbed TopBar bell is now a real consumer of
`report.ready`: `useLiveEvents` subscribes to the topic and bumps a
session-scoped unread counter in a small Zustand store
(`useNotificationStore`); the bell renders that count as a badge and, on
click, opens `/reports` and clears it. MVP scope is deliberately small and
honest — the counter is session-scoped (a refresh resets it), there is no
dropdown feed of individual notifications, and `report.ready` is the only
event type. A durable per-user feed (a dropdown list, multiple event types,
cross-session persistence) is the deferred follow-on and is NOT faked. Spec:
`frontend-live-events` v1.3.0 (C-08 / AC-10) + new `frontend-notifications`
v1.0.0.

### Recommended order
B0 → B1 → B2 → B3b → B3a → B3c. B0 unblocks attestation scoping + the
deferred A1 framework picker; B1/B2/B3b build the three bulk/cover faces
(CSV, OSCAL SAR, PDF); B3a makes generation async and emits the "ready"
signal; B3c surfaces it in the notification bell (the product-sensitive
slice, sequenced last).
