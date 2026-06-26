# Kensa / OpenWatch responsibility boundary

> **Status:** Ratified 2026-05-25. Authoritative.
> **Supersedes:** [`KENSA_OPENWATCH_COORDINATION_2026-04-14.md`](./KENSA_OPENWATCH_COORDINATION_2026-04-14.md) §3.4 ("Event subscription for Heartbeat"). The rest of the 2026-04-14 memo remains accurate; only the event-subscription plan was overtaken by this decision.
> **Audience:** OpenWatch engineers, Kensa engineers, anyone scoping work that crosses the boundary.
> **One-line summary:** Kensa is the per-host measurement engine; OpenWatch is the fleet orchestration and monitoring platform.

---

## 1. Why this document exists

The April 14 coordination memo's §3.4 planned for OpenWatch to subscribe to a Kensa event stream for liveness pulses, drift signals, and fleet-monitoring events. That plan does not match what the Kensa API can actually support, for reasons that are structural rather than implementational:

- Kensa is one-shot: every entry point (`detect`, `check`, `remediate`, the library `Service`) runs, does work, exits. The `InMemoryEventBus` is per-process and dies with the process.
- Kensa is single-host: each invocation is told one host. There is no inventory it could iterate.
- Periodic, fleet-wide pulses inherently require a long-running process with an inventory and a scheduler.

Adding `HeartbeatPulse` emission to Kensa would require turning Kensa into a stateful long-running fleet daemon with a host registry and a scheduler. That is OpenWatch. The shape of the work, not its complexity, dictates which side owns it.

This document records the boundary that both teams ratified on 2026-05-25, so future scoping conversations have one authoritative reference instead of re-deriving it.

---

## 2. The boundary, stated cleanly

| | Kensa | OpenWatch |
|---|---|---|
| Scope per invocation | One host | The fleet |
| Lifetime | One-shot (run, exit) | Long-lived service |
| State | Stateless between invocations | Stateful (inventory, history, schedules) |
| Surface | Library API consumed by callers | HTTP API + scheduler + bus, consumed by humans, integrations, and CI |
| Identity | The "git" of the system | The "GitHub" |

OpenWatch invokes Kensa per measurement; Kensa returns a structured result. OpenWatch persists that result, decides when to measure next, monitors whether hosts respond at all, compares results across time to detect drift, aggregates across the fleet, and routes alerts.

---

## 3. Responsibility split

### 3.1 OpenWatch owns

Everything in this column is built in the OpenWatch repo. Kensa has zero runtime responsibility for any of it.

| Responsibility | Notes |
|---|---|
| **Scheduler** | Decides which hosts run which frameworks at which cadence. Replaces what Kensa would never have done. |
| **Host inventory** | Already shipped in OpenWatch Slice A (`internal/host/`). |
| **Credential store + resolver** | Already shipped in Slice A (`internal/credential/`). Kensa is handed credentials per invocation; OpenWatch never relies on Kensa to look them up. |
| **Liveness pulse loop** | Per-host periodic reachability probe. Calls Kensa's `Reachable()` primitive when available; until then, OpenWatch SSH-dials directly via its existing `internal/ssh` package. |
| **Drift detection** | Reads OpenWatch's transaction history, compares latest result to previous per (host, rule), emits drift signals. |
| **Fleet rollup** | Cross-host aggregation: posture by framework, posture by host, drift trend over time. Backed by Kensa's per-host signed records but composed in OpenWatch. |
| **Event bus** | Long-lived in-process pubsub. OpenWatch publishes its own monitoring events here; alert routing subscribes. |
| **Alert routing + channel dispatch** | Slack, email, webhook, future Jira. Includes dedup, rate limit, severity routing. |
| **Coalescing, back-pressure, drop counters** | The "always see at least one pulse per host per interval" guarantee is OpenWatch's responsibility, on OpenWatch's bus. |
| **`HeartbeatPulse` event emission** | OpenWatch publishes pulses on its own bus. See §4 for the type-definition decision. |
| **`DriftDetected` event emission** | Same as above. |
| **Subscription to Kensa transaction-progress events** | OpenWatch consumes Kensa's events for in-flight scan/remediation visibility. See §4 for the consumer-side contract. |

### 3.2 Kensa owns

Everything in this column lives in the Kensa repo. OpenWatch is a consumer.

| Responsibility | Notes |
|---|---|
| **Per-host compliance evaluation** | The `Plan` / `Execute` / single-rule check primitives. Existing surface. |
| **Per-host signed transaction record** | The SQLite-backed signed log Kensa writes per host. OpenWatch's Eye reads these via `LogQuery`. |
| **Transaction-progress events** | `TransactionStarted`, `PhaseCompleted`, `Committed`, `RolledBack`. Emitted during a Kensa transaction; OpenWatch subscribes for progress display. |
| **Deadman events** | `DeadmanTimerArmed`, `DeadmanTimerFired`. Transaction-scoped, engine-internal — same lifecycle bucket as the other transaction-progress events. Kensa emits, OpenWatch consumes. Wiring currently absent (see §6.2). |
| **`Reachable(ctx, host)` primitive** | Cheap single-host reachability probe reusing Kensa's existing SSH ControlMaster transport. Doesn't exist yet — planned mid-Slice B (see §6.3). |
| **The shared event envelope** | `api.Event` and `api.EventKind` type definitions stay in Kensa as one shared wire vocabulary. See §4. |

---

## 4. Event taxonomy — three buckets

Every event in the system falls into exactly one bucket. The bucket determines who emits it and how its constant is declared.

### Bucket A — Kensa-emitted, OpenWatch-consumed

| Event | Status |
|---|---|
| `TransactionStarted` | Emitted by Kensa engine, published to internal bus |
| `PhaseCompleted` | Emitted |
| `Committed` | Emitted |
| `RolledBack` | Emitted |
| `DeadmanTimerArmed` | **Wiring gap** — deadman subsystem arms for real but does not publish (see §6.2) |
| `DeadmanTimerFired` | **Wiring gap** — same |

Consumer-side contract: OpenWatch subscribes via `Kensa.Subscribe(EventFilter{...})`. `Kensa.Subscribe` is currently stubbed (returns `ErrNotYetImplemented`); the underlying `pkg/kensa.Service.Subscribe` works. See §6.4.

### Bucket B — OpenWatch-owned (emitted by OpenWatch on its own bus)

| Event | Status |
|---|---|
| `HeartbeatPulse` | OpenWatch publishes per pulse-loop iteration |
| `DriftDetected` | OpenWatch publishes when a (host, rule) state transitions |

These never originate in Kensa. The Kensa code that today declares them as `EventKind` constants is dead vocabulary and will be removed (see §6.1).

`EventFilter.HeartbeatInterval` and `EventFilter.FleetIDs` follow the same path — they are filter fields for an OpenWatch-owned subscription model, not Kensa's. They move out of Kensa's `api/` package along with the event constants.

### Bucket C — The shared envelope

Kensa retains `api.Event` (the struct shape) and `api.EventKind` (the type, with its currently-emitted constants from Bucket A only). OpenWatch declares its Bucket B constants against the same `api.EventKind` type — one wire vocabulary, zero dead constants in Kensa.

```go
// In Kensa (api/events.go):
type EventKind string
const (
    TransactionStarted EventKind = "transaction.started"
    PhaseCompleted     EventKind = "transaction.phase_completed"
    Committed          EventKind = "transaction.committed"
    RolledBack         EventKind = "transaction.rolled_back"
    DeadmanTimerArmed  EventKind = "deadman.armed"
    DeadmanTimerFired  EventKind = "deadman.fired"
)

// In OpenWatch (e.g. internal/events/kinds.go):
import "github.com/Hanalyx/kensa/api"

const (
    HeartbeatPulse api.EventKind = "openwatch.heartbeat.pulse"
    DriftDetected  api.EventKind = "openwatch.drift.detected"
)
```

Both sides emit `api.Event` values; subscribers downstream of either bus see one type. No duplication of envelope definitions; no Kensa-side constants for events Kensa never produces.

---

## 5. What this means for OpenWatch planning

### 5.1 Slice A (shipped at `v0.2.0-rc.3`)

Unaffected. The auth + user + host + credential admin surface stands. Host inventory, credential resolver, SSH dial layer all match the boundary as ratified.

### 5.2 Slice B (next, not yet scoped to specs)

Slice B is meaningfully larger than the "just call Kensa to run a scan" framing the April 14 memo implied. The Slice B specs should cover:

1. **Scheduler** — when to run which framework against which host.
2. **Kensa executor wrapper** — invokes Kensa per scheduled run, persists the structured result.
3. **Transaction log writer** — OpenWatch's persistent record. Reads Kensa's signed records on each run; the log is OpenWatch's primary read surface for Eye / posture queries.
4. **Liveness loop** — periodic per-host reachability probe. Interim implementation SSH-dials directly via `internal/ssh`; switches to `Kensa.Reachable()` when that primitive lands.
5. **Drift detector** — compares latest transaction to previous per (host, rule); emits `DriftDetected` to OpenWatch's bus.
6. **Fleet rollup queries** — aggregate per-host state into fleet-level views (posture by framework, posture by host, drift trend).
7. **OpenWatch event bus** — in-process pubsub. Publishes Bucket B events; downstream subscribers attach.
8. **Alert router** — subscribes to the bus; routes by severity + tag + channel config.

Realistic estimate: 10–12 weeks. The work is genuinely larger than Slice A; the boundary ratification is what makes the scoping possible.

### 5.3 Slices beyond B

`Subscribe` to Kensa transaction-progress events (Bucket A) lands when OpenWatch needs in-flight scan/remediation visibility. That's likely Slice C (proactive remediation workflow) or whenever a UI surface needs "show me what's happening on host X right now." Slice B does not require it because the scheduler invokes Kensa synchronously and persists the final result; in-flight visibility is a nice-to-have on top.

---

## 6. Open Kensa-side action items

These are planned against this boundary doc. None block OpenWatch Slice A; one (6.3) is needed mid-Slice B.

### 6.1 Remove `HeartbeatPulse` and `DriftDetected` constants from Kensa's `api/`

- **Action:** Move the two constants (plus `EventFilter.HeartbeatInterval` and `EventFilter.FleetIDs`) out of Kensa's frozen `api/` package. OpenWatch redeclares them as `api.EventKind`-typed constants in its own package.
- **Owner:** Kensa team, with founder sign-off (Kensa `api/` is semver-frozen — this is a one-way door before v1.0.0; would require a v2 major bump if missed).
- **Timing:** Before Kensa v1.0.0 (M7 in progress). Time-sensitive — should not drift.
- **Done by this boundary doc:** No, separately tracked.

### 6.2 Wire deadman subsystem to publish to event bus

- **Action:** `DeadmanTimerArmed` / `DeadmanTimerFired` are declared and the deadman subsystem fires for real (`internal/engine/deadman`, `internal/agent/deadman`), but the events are never published to the bus. Add the publish call inside the existing deadman fire path.
- **Owner:** Kensa team.
- **Timing:** Whenever Kensa is doing engine work near deadman. Not OpenWatch-blocking.

### 6.3 Build `Reachable(ctx, host)` primitive

- **Action:** Add a cheap single-host reachability probe that reuses Kensa's ControlMaster SSH transport. Return shape MUST distinguish "host down" (the expected `Reached: false` answer) from "probe couldn't run" (a config / transport error). Recommended shape:
  ```go
  type Reachability struct {
      Reached bool
      Latency time.Duration
  }
  // err is reserved for probe-execution failures, NOT host-down conditions.
  func (s *Service) Reachable(ctx context.Context, host Host) (Reachability, error)
  ```
- **Owner:** Kensa team.
- **Timing:** Mid-Slice B. OpenWatch's interim liveness loop SSH-dials directly until this lands; the switch-over is mechanical when it does.

### 6.4 Wire `Kensa.Subscribe` to `Service.Subscribe`

- **Action:** `Kensa.Subscribe` is stubbed (returns `ErrNotYetImplemented`); only `pkg/kensa.Service.Subscribe` reaches the bus. The top-level wrapper needs to delegate.
- **Owner:** Kensa team.
- **Timing:** Before OpenWatch's first consumer of Bucket A events lands. Probably Slice C.

### 6.5 Doc fixes (landed 2026-05-25, recorded for traceability)

- `api/events.go` godoc: corrected the false "every event type the engine emits" claim and clarified `EventSubscriber` is for transaction progress, not heartbeat/drift.
- `KENSA_API_DOC.md` §8: rewritten to the three-bucket model with the open-item-2 resolution recorded inline.

---

## 7. What this document does NOT change

- The Kensa `Plan` / `Execute` / `LogQuery` / `EnvelopeVerifier` contract. Unaffected.
- The April 14 memo §1 (vision split), §2 (top-level identity mapping), §3.1–§3.3 (other duplication resolutions), §3.5–§5 (per-API discussions other than §3.4) remain authoritative.
- OpenWatch's Eye and Control Plane wiring against Kensa's `LogQuery` / `Planner` / `Executor`. Unaffected.
- Anything about who signs what (Kensa signs per-transaction; OpenWatch signs aggregates). Unaffected.

---

## 8. FAQ

**Q: If `HeartbeatPulse` is OpenWatch-emitted, why does it use Kensa's `api.EventKind` type at all?**

So the wire envelope stays one type across the whole platform. A downstream consumer subscribing to either bus sees `api.Event` values without conditional decoding. The decision is to share the envelope, not the constants — Kensa declares what Kensa emits; OpenWatch declares what OpenWatch emits; the carrier type is one.

**Q: Why doesn't Kensa expose pulses by gaining a daemon mode?**

Three reasons, in order of weight:
1. **It's the wrong product shape.** Kensa is "git." A daemon with an inventory and a scheduler is "GitHub." Putting both in one tool means losing the property that any caller (CLI, OpenWatch, third-party automation) can use Kensa as a stateless library.
2. **The boundary disappears.** If Kensa owns an inventory, OpenWatch and Kensa are competing for the same data model, and every future "where does X live?" question gets harder.
3. **Cost vs benefit.** A pulse loop is ~200 lines of Go. The benefit of moving it to Kensa is zero (no other Kensa caller needs it). The cost is permanent — Kensa carries an inventory + scheduler forever.

**Q: What happens if Kensa later wants to publish a HeartbeatPulse for some new reason?**

It can — Kensa would declare a Kensa-emitted constant (e.g. `KensaInternalHeartbeat` for a self-health pulse Kensa emits). The Bucket B decision is specifically about the existing `HeartbeatPulse` constant whose semantics are fleet-level monitoring. Kensa-internal heartbeats are a different concept and would get a different constant.

**Q: We're an outside team writing a Kensa consumer. Which boundary do we follow?**

This one. The 2026-04-14 memo's §3.4 is obsolete on heartbeat/drift. The other sections still apply.

**Q: How is this kept in sync if Kensa or OpenWatch evolves?**

Each side cites this document in its own internal docs (Kensa's `KENSA_API_DOC.md` §8; OpenWatch's Slice B specs and any future scope docs). Changes to the boundary require coordinated edits to this file plus the citing docs; the file is versioned (date in the Status line at top). If a future change overtakes a section, that section gets struck through and a new doc supersedes it (same pattern as this doc superseding the April 14 memo's §3.4).

---

## 9. Reference

- April 14 memo (still authoritative outside §3.4): [`KENSA_OPENWATCH_COORDINATION_2026-04-14.md`](./KENSA_OPENWATCH_COORDINATION_2026-04-14.md)
- OpenWatch quarterly plans: [`OPENWATCH_Q2_PLAN.md`](./OPENWATCH_Q2_PLAN.md), [`OPENWATCH_Q1_Q3_PLAN.md`](./OPENWATCH_Q1_Q3_PLAN.md)
- OpenWatch vision: [`OPENWATCH_VISION.md`](./OPENWATCH_VISION.md)
- Stage 2 Slice A plan (shipped): [`engineering/stage_2_slice_a.md`](./engineering/stage_2_slice_a.md)
