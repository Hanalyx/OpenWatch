# Slice C — Host Intelligence

> **Slice**: C (after Slice A = admin surface, Slice B = compliance trunk)
> **Status**: Planning (draft)
> **Sequencing**: Starts after Slice B (B.1 through B.4) ships
> **Estimated effort**: 6-8 weeks
> **Owner**: TBD

---

## Why this slice exists

OpenWatch's stated mission ("The Eye") is comprehensive visibility into security and compliance posture across infrastructure. Slice A made hosts addressable; Slice B makes their compliance state observable and queryable over time. **Neither tells you what's actually on those hosts.**

Concretely, after Slice B is complete OpenWatch can answer:
- "What's host Y's compliance score, and what rules are failing?"
- "What was that score 3 months ago, and which rules?"

It cannot answer:
- "Which hosts have package `openssl < 3.0.13` installed?" (vulnerability correlation)
- "What services are listening on the production fleet?" (asset management)
- "Did anyone create a local user on host Y last month?" (drift at the OS layer)
- "How much memory does host Y have, and what's its CPU utilization trend?" (capacity)

These questions are foundational to the compliance frameworks OpenWatch targets:

- **ISO 27001 A.8** — Asset management (authoritative inventory beyond hostname+IP)
- **FedRAMP CM-8** — System component inventory (current configuration baseline)
- **CMMC CA.L2-3.12.4** — Continuous monitoring of inventory and configuration
- **NIST SP 800-53 CM-8** — Information system component inventory

Slice C builds the host intelligence layer that closes this gap.

---

## Locked design decisions

### 1. OpenWatch-owned, NOT a Kensa extension

Per the Kensa/OpenWatch boundary doc § 5.2, Kensa is a pure compliance measurement engine — runs YAML rule checks, returns evidence, does nothing else. Host inventory and telemetry collection are OpenWatch responsibilities. Slice C builds its own SSH probe runner; it does not extend the Kensa Go module.

### 2. Separate scheduled probe (NOT piggybacking on Kensa scans)

Intel collection has its own cadence policy, decoupled from compliance scans. A failed compliance scan should not prevent an intel refresh. A package inventory refresh does not need to happen as often as a service-port probe. The Slice B `scheduler` package gains a second source of jobs: `intel_probe` job type alongside `scan` job type.

### 3. Storage model: write-on-change for state facts, snapshots for metrics

- **State facts** (packages, services, users, network config, hardware spec) — write-on-change to a `host_facts` table, mirroring the Slice B `transactions` pattern. Supports "what packages were on host Y three months ago" via point-in-time queries; storage stays bounded.
- **Continuous metrics** (CPU%, memory%, disk I/O, network throughput) — periodic snapshots to a `host_metrics` table. Write-on-change is the wrong model for time-series data (every sample differs slightly). Default cadence: every 5 minutes when the host is reachable.

This split was decided after recognizing that write-on-change loses information for continuous values. See § "Trade-off note" below.

### 4. Reuse Slice B's infrastructure

Slice C reuses the Slice B trunk without modification:

- `internal/scheduler` dispatches intel-probe jobs the same way it dispatches scan jobs (separate job_type, same queue, same SKIP LOCKED dispatch loop, same HMAC payload integrity).
- `internal/credential` resolves SSH credentials in-memory; Slice C SSH probes never write a key to disk.
- `internal/ssh` host-key verification policy applies to intel probes the same way it applies to scans.
- `internal/audit` emits typed events for intel collection (`intel.probe.started`, `intel.probe.completed`, `intel.probe.failed`, `intel.fact.changed`).
- `internal/policy` gains an `intel_schedule` policy entry alongside `schedules` (compliance schedule).

### 5. No agent on the target host

Intel collection runs over SSH using standard system utilities (`rpm`, `dpkg`, `systemctl`, `ss`, `ip`, `nft`, `getent`, `/proc`, `/sys`). No OpenWatch agent is installed on the target. This matches Kensa's approach and keeps the deployment story unchanged.

### 6. Privacy-first collector design

Each collector has an explicit allowlist of what it reads. Collectors do NOT read:

- Shell history (`.bash_history`, `.zsh_history`)
- Process command lines (`/proc/<pid>/cmdline`) — would surface env vars containing secrets
- Arbitrary file contents — only the specific config files each collector needs
- `/var/log/*` content — log forwarding is out of scope for Slice C

The collector code is small enough to review against this charter, and a source-inspection AC verifies no disallowed `ssh.Run` patterns appear.

---

## Data model

### `host_facts` — state facts (write-on-change)

```sql
CREATE TABLE host_facts (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    fact_type     TEXT NOT NULL,    -- 'package', 'service', 'user', 'network_interface', 'firewall_rule', 'hardware'
    fact_key      TEXT NOT NULL,    -- type-specific natural key (e.g., package name, service unit, username, interface name)
    fact_value    JSONB NOT NULL,   -- structured value (type-specific schema)
    change_kind   TEXT NOT NULL,    -- 'first_seen' | 'value_changed' | 'removed'
    observed_at   TIMESTAMPTZ NOT NULL,
    probe_id      UUID NOT NULL REFERENCES intel_probes(id),
    UNIQUE (host_id, fact_type, fact_key, observed_at)
);

CREATE INDEX idx_host_facts_by_host_type ON host_facts(host_id, fact_type, observed_at DESC);
CREATE INDEX idx_host_facts_by_key ON host_facts(fact_type, fact_key);  -- supports fleet-wide "who has package X"
```

Write-on-change semantics mirror Slice B's `transactions`. To reconstruct facts at time T: `SELECT DISTINCT ON (fact_key) ... WHERE host_id = Y AND fact_type = 'package' AND observed_at <= T ORDER BY fact_key, observed_at DESC` and filter out rows where `change_kind = 'removed'`.

### `host_fact_state` — current snapshot (for cheap "what's on this host right now")

```sql
CREATE TABLE host_fact_state (
    host_id        UUID NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    fact_type      TEXT NOT NULL,
    fact_key       TEXT NOT NULL,
    fact_value     JSONB NOT NULL,
    first_seen_at  TIMESTAMPTZ NOT NULL,
    last_seen_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, fact_type, fact_key)
);
```

Mirrors `host_rule_state` from Slice B — current state per natural key. UPSERTed every probe; rows deleted when a fact disappears (and a `host_facts` row with `change_kind='removed'` is appended).

### `host_metrics` — continuous metrics (snapshots)

```sql
CREATE TABLE host_metrics (
    host_id      UUID NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    observed_at  TIMESTAMPTZ NOT NULL,
    cpu_pct      REAL,
    mem_used_mb  BIGINT,
    mem_total_mb BIGINT,
    disk_used_gb BIGINT,
    disk_total_gb BIGINT,
    load_1m      REAL,
    load_5m      REAL,
    load_15m     REAL,
    PRIMARY KEY (host_id, observed_at)
);

-- Time-partitioned by month for retention manageability
CREATE INDEX idx_host_metrics_by_time ON host_metrics(observed_at DESC);
```

Retention policy (TBD in spec): 90 days of 5-minute samples, then downsampled to hourly for 1 year, then dropped. Configurable per the `intel_schedule` policy.

### `intel_probes` — probe runs (per Slice B's `scans` analog)

```sql
CREATE TABLE intel_probes (
    id              UUID PRIMARY KEY DEFAULT uuidv7(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    probe_types     TEXT[] NOT NULL,  -- which collectors ran in this probe
    status          TEXT NOT NULL,    -- queued | running | completed | failed
    initiator_type  TEXT NOT NULL,    -- 'scheduler' | 'manual' | 'api'
    initiator_id    TEXT,
    policy_version  TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    facts_changed   INT,              -- count of host_facts rows written
    error_code      TEXT,
    correlation_id  TEXT NOT NULL
);
```

Per-probe audit trail; same shape as Slice B's `scans` table.

---

## Sub-slices (waves)

| Wave | Components | Why this order |
|---|---|---|
| **C.1 (probe trunk)** | Probe runner + persistence + collector interface | Builds the foundation: a single end-to-end probe writes one host's package list. Demonstrates the whole pipeline before adding collectors. |
| **C.2 (core state collectors)** | Packages, services, users, hardware | The high-value state facts. After this, "which hosts have package X" queries work fleet-wide. |
| **C.3 (network + metrics)** | Network interfaces / routes / firewall rules + metrics sampler | Network state facts and continuous-metrics path. Different storage shape, different cadence — drawn together because they share the "probe runs ≠ scan runs" pattern. |
| **C.4 (visibility surface)** | Read API, fleet rollup queries, vulnerability-correlation joins | UI / dashboard consumption. Requires C.1-C.3 to populate the data. |

Each wave is spec-first: drafts land before code, same SDD discipline as Slice B.

---

## What we keep / change / drop from the Python implementation

The Python backend has `app/services/system_info/` and tables `host_packages`, `host_services`, `host_users`, `host_network`, `host_audit_events`, `host_metrics`. Worth a focused audit before drafting specs, but the broad shape:

| Decision | Reason |
|---|---|
| **Keep**: collection over SSH using stock OS utilities | Matches Kensa; no agent on target |
| **Keep**: per-fact-type collector packages | Maps cleanly to Go sub-packages |
| **Change**: separate probe runs, not piggybacking on scans | Decouples cadence; failure independence |
| **Change**: write-on-change for state facts | Python uses append-every-probe (storage bloat); Q1 already proved write-on-change works at 99.7% reduction for compliance — applies here too |
| **Change**: explicit collector charter (allowlist of files/commands read) | Python collected what was convenient; Go is privacy-first by design |
| **Change**: per-fact-type cadence in policy | Python had a single global cadence; packages don't need to refresh as often as listening ports |
| **Drop**: `host_audit_events` ingestion | Forwarding host auditd logs is a much larger scope (centralized log management, retention, correlation) — defer to a later slice if demand emerges |
| **Drop**: free-form metrics collection (anything goes into host_metrics) | Go side ships a fixed schema (cpu, mem, disk, load) for v1; extensible later via additive migrations |

A focused per-collector audit will land as a separate doc (`app/docs/python_system_info_audit.md`) before drafting C.2 specs.

---

## Spec inventory (planned)

Specs to draft, in writing order:

### Trunk (C.1)
- `system-intel-probe-runner` — SSH probe orchestration, audit emission, error handling
- `system-host-facts-writer` — Write-on-change persistence for state facts (mirrors `system-transaction-log-writer`)
- `system-host-metrics-writer` — Snapshot persistence for continuous metrics

### Collectors (C.2)
- `system-intel-collector-packages`
- `system-intel-collector-services`
- `system-intel-collector-users`
- `system-intel-collector-hardware`

### Collectors (C.3)
- `system-intel-collector-network`
- `system-intel-metrics-sampler`

### API surface (C.4)
- `api-host-intel` — per-host intel views
- `api-fleet-intel` — fleet rollups
- `api-intel-search` — "which hosts have ..." queries

### Cross-cutting
- Amendment to `system-scheduler` — adds intel-probe job type alongside scan jobs
- Amendment to `system-policy` — adds `intel_schedule` policy entry

Estimate: ~14 new specs, ~150 ACs total. Comparable to Slice A's spec footprint.

---

## OpenAPI surface preview

New endpoints, all under `/api/v1/`:

```
GET    /hosts/{id}/intel/summary             # what we know about this host
GET    /hosts/{id}/intel/packages            # current package inventory
GET    /hosts/{id}/intel/packages/history    # write-on-change timeline
GET    /hosts/{id}/intel/services
GET    /hosts/{id}/intel/users
GET    /hosts/{id}/intel/network
GET    /hosts/{id}/intel/hardware
GET    /hosts/{id}/intel/metrics             # ?range=24h|7d|30d
GET    /hosts/{id}/intel/probes              # list of probe runs

POST   /hosts/{id}/intel:refresh             # manual probe trigger
POST   /hosts/{id}/intel/packages:query      # ?as_of=<timestamp> for point-in-time

GET    /fleet/intel/packages                 # ?name=openssl&version_lt=3.0.13
GET    /fleet/intel/services                 # ?listening_port=22
GET    /fleet/intel/users                    # ?username=admin
GET    /fleet/intel/summary                  # rolled-up stats

GET    /intel/probes/{id}                    # probe details
```

Plus extensions to existing `Host` resource: `last_intel_probe_at`, `intel_freshness` (label: fresh / stale / unknown), `intel_facts_count`.

---

## Privacy and security

### Collector charter

Each collector is restricted by source-inspection AC to a fixed set of remote operations. The packages collector, for example, may only run `rpm -qa` or `dpkg -l` (platform-dependent) — and parses the structured output. It may NOT cat arbitrary files, list directories, or run discovery shell pipelines. The reviewed allowlist is in the spec.

### What we do NOT collect

- Shell history files
- Process command lines (`ps`, `/proc/<pid>/cmdline`) — leaks env-var secrets
- File contents beyond named config files
- `/var/log/*` content (no log forwarding)
- Network traffic samples
- Credential material on the host (no `cat /etc/shadow`, no SSH private keys)

### Audit emission

Every probe emits:
- `intel.probe.started` (at probe start, with `correlation_id`, `host_id`, `probe_types`)
- `intel.fact.changed` (per state-fact change — kind: first_seen / value_changed / removed)
- `intel.probe.completed` or `intel.probe.failed`

Every successful manual `POST /hosts/{id}/intel:refresh` is audited with the caller's identity. RBAC: intel read requires `INTEL_READ`; manual refresh requires `INTEL_WRITE`. Codegen'd permission constants land in `app/auth/permissions.yaml`.

### Supply chain

Intel runs through the existing `internal/credential` resolver — no new credential surfaces, no new env vars for sensitive material. The collector code is part of the Go binary and ships with the same FIPS/sgosec/govulncheck gates as the rest of the codebase.

---

## Performance budget

Per-host probe wall-clock budget (under default policy, all collectors enabled):

| Collector | Network round-trips | Wall-clock budget |
|---|---|---|
| Packages | 1 (`rpm -qa` or `dpkg -l`) | 5 s |
| Services | 2 (`systemctl list-units --type=service`, `ss -tlnp`) | 3 s |
| Users | 2 (`getent passwd`, `lastlog`) | 2 s |
| Hardware | 3-4 (`/proc/cpuinfo`, `/proc/meminfo`, `df -B1`, `lsblk -J`) | 2 s |
| Network | 3 (`ip -j addr`, `ip -j route`, `nft -j list ruleset`) | 3 s |
| Metrics sampler | 2 (`/proc/loadavg`, `/proc/stat`, `/proc/meminfo`) | 1 s |
| **Total per probe** | ~13 | **≤ 16 s wall-clock** |

Per-host fleet impact at default cadence:
- State facts every 1 h, metrics every 5 min → ~12 metric samples/h + 1 state probe/h = ~80 RPC round-trips per host per day
- For 1000 hosts: 80k round-trips/day = ~1/sec sustained. Trivial.

CI / unit test budget: fact-writer and metrics-writer have a `≤ 2s for 100 facts` target, mirroring B.1c AC-10.

---

## Out of scope (explicit deferrals)

- **Host auditd log forwarding** — defer to a later slice if demand emerges
- **Process-level monitoring** (per-process CPU/memory) — privacy-sensitive, large data volume
- **Network traffic analysis** — out of scope; ride a dedicated NetFlow product if needed
- **Configuration management** (push state to hosts) — OpenWatch is read-only re: hosts; remediation lives in Slice D or later
- **Container/pod awareness on the host** — Kubernetes inventory is a separate concern (k8s API integration, not SSH)
- **Vulnerability scanning** — host intel surfaces the package inventory; correlating with CVE databases is a downstream integration (handled by `/fleet/intel/packages?name=…&version_lt=…` queries against an external CVE source)

---

## Open questions

These need answers before C.1 trunk specs land:

1. **Probe runner concurrency** — does the intel probe respect Slice B's per-host concurrency guard (sync.Map of in-flight host IDs)? Almost certainly yes — same SSH host, same one-thing-at-a-time discipline. Need explicit constraint.
2. **Probe cadence policy shape** — single global cadence, per-fact-type, or per-host? My lean: per-fact-type globally + per-host override (mirrors `schedules` policy structure).
3. **Retention defaults** — 90-day rolling for `host_facts`, downsample metrics from 5-min to 1-hour after 7 days, drop after 1 year. Confirm or override.
4. **Backoff after collection failure** — does the executor backoff state from Slice B apply? Or does intel get its own backoff (so a flaky compliance scan doesn't block intel refresh and vice versa)? My lean: separate backoff state per probe type.
5. **Idempotency for manual `POST /hosts/{id}/intel:refresh`** — debounce so a hammered refresh button doesn't trigger 50 probes. My lean: rate-limit at 1 per 30 s per host.

---

## Slice C entry criteria (from Slice B)

Slice C cannot start until:

- Slice B B.1 (scheduler + executor + transaction log writer) is merged to main and proven on at least one production-shaped deployment
- Slice B B.2 (liveness + drift) ships so we know the patterns
- Slice B B.3 (event bus + alert router) ships — Slice C will publish `intel.fact.changed` events to the bus
- Slice B B.4 (fleet rollup queries) ships — Slice C's `/fleet/intel/*` endpoints reuse the rollup query shape

This is roughly 10-12 weeks of Slice B work, then C starts.

---

## What "Slice C done" means concretely

- 14 new specs, all at 100% / 80% / 50% coverage per tier
- ~30 new ACs implemented across waves C.1-C.4
- Hosts table augmented with intel-freshness fields
- New OpenAPI endpoints under `/hosts/{id}/intel/*` and `/fleet/intel/*` — codegen'd, tested
- New policy type `intel_schedule` loaded by `internal/policy`
- 7+ collectors (packages, services, users, hardware, network, metrics) each backed by a spec
- Probe runner + writers exercised end-to-end against real Linux hosts in CI
- Audit emission for every probe + every fact change
- RBAC entries `INTEL_READ` and `INTEL_WRITE` codegen'd into `permissions.gen.go`
- Retention task scheduled via job queue
- Migration of any Python-era host intel data (one-time backfill — TBD whether worth doing or starting fresh)

---

## Cross-references

- Boundary doc § 5.2 (Slice B scope) — what we explicitly inherit, not duplicate: [docs/KENSA_OPENWATCH_BOUNDARY.md](../../docs/KENSA_OPENWATCH_BOUNDARY.md)
- Slice A plan — pattern this doc follows: [stage_2_slice_a.md](./stage_2_slice_a.md)
- Q1 write-on-change rationale — same pattern reused: `specs/system/transaction-log-writer.spec.yaml`
- Python `system_info/` package — reference implementation to audit, not copy: `backend/app/services/system_info/`

---

## Trade-off note: why two storage shapes

We chose write-on-change for state facts (packages, services, users, network, hardware) and snapshot-based storage for metrics (CPU/mem/disk/load) for one reason: **write-on-change loses information when values are continuous**.

A package either is or isn't installed; the value is mostly stable; on every probe at least 99% of facts are unchanged. Write-on-change is a 100× storage savings here with no loss of historical accuracy ("was openssl 3.0.13 installed on 2026-02-15?" answers correctly).

A CPU utilization reading at noon yesterday is a different value from noon today. Every sample matters. Write-on-change would write every sample anyway (none are equal) — that's just slower-and-more-complex append. So metrics get a straightforward time-series shape with downsampling for retention.

This split was articulated during Slice B B.1c planning and is the architectural reason Slice C ships two writers (`host_facts` and `host_metrics`) rather than one. Spec authors should resist the pull to unify them.
