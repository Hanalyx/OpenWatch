# Correlation ID Propagation — Design Specification

**Status:** Foundation, locked 2026-04-30
**Owner:** Backend platform
**Spec:** `specs/system/correlation.spec.yaml` (to be authored at Specter migration)
**Source-of-truth code:** `internal/correlation/` package; helpers in `internal/queue/`, `internal/audit/`, `internal/log/`

---

## 1. Why this exists

When a user reports "my 10am scan failed," support must reconstruct the request from logs. Without a correlation ID, that means joining facts by hand: which host, what time window, which worker process — chained across a half-dozen log files. With a correlation ID, support greps for one string and reads the entire story top-to-bottom.

The hard part isn't generating the ID. It's keeping it alive across asynchronous boundaries:

- An HTTP request enqueues a job and returns `202 Accepted`.
- The worker dequeues the job seconds later in a different goroutine (sometimes a different process).
- The worker spawns sub-jobs (a fleet scan fans out to per-host scans).
- A cron tick enqueues work with no originating request.
- A worker calls Kensa over SSH; Kensa's logs and the worker's logs are separate streams.
- A webhook fires to an external system.

Every one of those boundaries is a place where the correlation ID can drop on the floor. Each drop creates a forensic gap that can't be back-filled. **The contract has to be locked once, codified in helpers, and enforced by CI** — because retrofitting propagation across 30 handlers and 12 job types is a multi-week refactor that will be skipped under deadline pressure.

This document defines that contract.

---

## 2. The one-line contract

> **Every audit event, every log line, and every job in OpenWatch carries a correlation ID. The ID enters the system at exactly four origin points and is propagated by exactly four helpers. Code that bypasses the helpers is rejected by CI.**

Origin points:

1. HTTP request (middleware extracts or generates)
2. Cron tick (scheduler generates)
3. System startup (boot generates one shared ID)
4. Test harness (test injects)

Propagation helpers:

1. `correlation.HTTPMiddleware` — entry from HTTP
2. `queue.Enqueue(ctx, payload)` — extract from context, write to job row
3. `queue.Dequeue() (*Job, ctx)` — read from job row, restore onto context
4. `audit.Emit(ctx, event)` and the slog handler — extract from context for storage and logs

Anything else that needs the ID reads it from `context.Context` via `correlation.From(ctx)`. There is no global, no thread-local, no other path.

---

## 3. ID format

### 3.1 Shape

```
<type-prefix>-<16 hex chars>
```

Examples:

```
req-018f3c2a8b7d4e9a    # HTTP request
cron-018f3c2a8b7d4eaa   # cron tick
boot-018f3c2a8b7d4eb0   # process boot
test-deadbeef00000001   # test harness
```

Total length: 20–21 characters. Greppable, distinctive, fits in a log column without truncation.

### 3.2 Generation

The 16 hex chars are 8 bytes: a 48-bit unix-millisecond timestamp followed by a 16-bit per-millisecond monotonic counter.

**Why a counter, not random bits in the trailing 16 bits?**

The original design proposed "48 bits of timestamp + 16 bits of randomness, which is plenty at request rates <10K/sec." That math is correct for steady-state traffic (birthday-paradox collision probability is negligible at those rates), but it **fails under bursty workloads** — tight loops, batch operations, parallel tests. The Day 4 acceptance test for `correlation.spec.yaml` AC-2 ("10000 sequential Generate calls return distinct IDs") found duplicate IDs within milliseconds: the same 16 random bits get drawn twice when you generate ~256 IDs in a single ms, by the birthday paradox.

The monotonic counter eliminates this entirely:

- **Within the same millisecond** the counter increments by 1 per `Generate` call.
- **When the millisecond advances** the counter is re-seeded with `crypto/rand.Read(2 bytes)` so consecutive IDs don't reveal request rate via predictable values.

Trade-off: the counter wraps (back to 0) after 65,536 IDs in a single millisecond — ~65 M IDs/sec. Far beyond any realistic OpenWatch rate; if observed in production, alert and re-design (16-bit counter wasn't sized for that scenario).

**Properties this gives us:**

- **Time-ordered.** Two correlation IDs generated in sequence sort lexicographically in time order (timestamp dominates, counter tiebreaks within ms). `grep req- /var/log/openwatch.log | sort` produces a chronological view.
- **Unique under bursty load.** No collisions until ≥65,536 IDs/ms, which is operationally impossible at our scale.
- **Greppable.** No special characters, no quoting issues.
- **Boundary-distinct.** The prefix tells you at a glance whether this came from an API call, a cron, or a boot.

```go
// internal/correlation/correlation.go

var (
    monoMu      sync.Mutex
    monoLastMs  uint64
    monoCounter uint16
)

func Generate(prefix Prefix) string {
    nowMs := uint64(time.Now().UnixMilli())
    c := nextCounter(nowMs)

    var u [8]byte
    u[0] = byte(nowMs >> 40); u[1] = byte(nowMs >> 32)
    u[2] = byte(nowMs >> 24); u[3] = byte(nowMs >> 16)
    u[4] = byte(nowMs >> 8);  u[5] = byte(nowMs)
    u[6] = byte(c >> 8);      u[7] = byte(c)
    return string(prefix) + "-" + hex.EncodeToString(u[:])
}

func nextCounter(nowMs uint64) uint16 {
    monoMu.Lock()
    defer monoMu.Unlock()
    if nowMs != monoLastMs {
        monoLastMs = nowMs
        var r [2]byte
        if _, err := rand.Read(r[:]); err != nil {
            panic("correlation: rand.Read failed: " + err.Error())
        }
        monoCounter = uint16(r[0])<<8 | uint16(r[1])
    } else {
        monoCounter++
    }
    return monoCounter
}

type Prefix string

const (
    PrefixRequest Prefix = "req"
    PrefixCron    Prefix = "cron"
    PrefixBoot    Prefix = "boot"
    PrefixTest    Prefix = "test"
)
```

### 3.3 Sanitization of client-provided IDs

A client may supply `X-Correlation-Id` to pre-correlate their side of the call. We trust the value only after sanitizing:

| Check | Rule | On failure |
|-------|------|-----------|
| Charset | `^[A-Za-z0-9_-]+$` | Generate fresh; log warning |
| Length | 1–64 chars | Generate fresh; log warning |
| Reserved prefix | If client sends `boot-` or `cron-`, reject and regenerate. Those prefixes are reserved for internal origins. | Generate fresh; log warning |

Sanitization happens in the HTTP middleware, before the value touches `context.Context`. **A correlation_id that reaches a handler is always trusted.**

```go
// internal/correlation/sanitize.go
var validIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var reservedPrefixes = []string{"boot-", "cron-", "test-"}

func SanitizeOrGenerate(client string) (id string, regenerated bool) {
    if client == "" {
        return Generate(PrefixRequest), false
    }
    if !validIDPattern.MatchString(client) {
        return Generate(PrefixRequest), true
    }
    for _, rp := range reservedPrefixes {
        if strings.HasPrefix(client, rp) {
            return Generate(PrefixRequest), true
        }
    }
    return client, false
}
```

### 3.4 Why not W3C `traceparent`?

The OpenTelemetry-standard `traceparent` header carries a 32-char trace ID + 16-char span ID + flags. It would integrate cleanly with future OTel exporters. We chose `X-Correlation-Id` because:

1. **Single-string simplicity.** A correlation ID maps 1:1 to "user intent." Span hierarchies are an observability concern, not an audit/forensic concern.
2. **Forensic-readable.** `req-018f3c2a8b7d4e9a` is human-recognizable in logs; `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01` is not.
3. **Future-compatible.** The propagation discipline transfers: when we adopt OTel, the same boundary helpers populate `traceparent` alongside `correlation_id`. No discipline rewrite.

Locked decision (roadmap 2026-04-27): `X-Correlation-Id` is the canonical header.

---

## 4. The four primary boundaries

### 4.1 HTTP request entry

```
Client                                              OpenWatch
  │  POST /api/v1/scans                                 │
  │  X-Correlation-Id: my-id-123  (optional)            │
  ├─────────────────────────────────────────────────────▶
  │                                                     │
  │                                  HTTPMiddleware:    │
  │                                    1. Sanitize or generate
  │                                    2. correlation.Set(ctx, id)
  │                                    3. ResponseHeader: X-Correlation-Id
  │                                    4. Log "request received" with id
  │                                                     │
  │                                            chi.Mux  │
  │                                                  ▼  │
  │                                            handler(w, r)
  │                                                     │
  │  202 Accepted                                       │
  │  X-Correlation-Id: my-id-123                        │
  │◀────────────────────────────────────────────────────┤
```

The middleware:

```go
// internal/correlation/http.go
func HTTPMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        client := r.Header.Get("X-Correlation-Id")
        id, regenerated := SanitizeOrGenerate(client)
        if regenerated {
            slog.WarnContext(r.Context(), "rejected client correlation id; regenerated",
                slog.String("rejected_value_preview", truncate(client, 16)),
                slog.String("correlation_id", id),
            )
        }
        ctx := correlation.Set(r.Context(), id)
        w.Header().Set("X-Correlation-Id", id)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

This middleware runs **before** every other middleware in the chain (auth, RBAC, idempotency, audit). The audit middleware needs `correlation_id` to be on context already; auth needs it for failed-login audit events; idempotency checks key reuse and may need to log under the original request's correlation_id.

> **Router quirk (chi v5):** chi's default `NotFound` and `MethodNotAllowed` handlers do **not** run the `r.Use(...)` middleware chain. Unmatched paths and unsupported methods will return responses **without** `X-Correlation-Id`, breaking the forensic guarantee. The server bootstrap MUST register explicit handlers for both:
>
> ```go
> r.Use(correlation.HTTPMiddleware)
>
> r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
>     http.Error(w, "404 page not found", http.StatusNotFound)
> })
> r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
>     http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
> })
> ```
>
> Discovered Day 4 of Stage 0 during live `curl` verification of `http-server.spec.yaml` AC-9. If you swap routers in a future iteration (gorilla/mux, httprouter, etc.), re-verify that unmatched routes traverse middleware — same class of bug recurs across router libraries.

### 4.2 HTTP → job queue

When a handler enqueues a job:

```go
// internal/queue/enqueue.go
func Enqueue(ctx context.Context, jobType string, payload []byte) (jobID uuid.UUID, err error) {
    correlationID, ok := correlation.From(ctx)
    if !ok {
        // This is a programming error: every code path that reaches Enqueue
        // must have come through an origin (HTTP, cron, boot, test).
        return uuid.Nil, fmt.Errorf("queue.Enqueue: no correlation_id on context")
    }
    return enqueueRow(ctx, jobType, payload, correlationID)
}
```

The `job_queue` table has:

```sql
ALTER TABLE job_queue ADD COLUMN correlation_id TEXT NOT NULL;
CREATE INDEX idx_job_queue_correlation ON job_queue(correlation_id);
```

The index supports forensic queries: "show every job spawned by `req-018f3c2a8b7d4e9a`."

**No public path to insert a job exists outside `internal/queue/`.** The CI lint rule (Section 7) rejects any other code that constructs an `INSERT INTO job_queue` statement.

### 4.3 Job → worker dequeue

The worker:

```go
// internal/queue/dequeue.go
func Dequeue(ctx context.Context) (*Job, context.Context, error) {
    job, err := dequeueRow(ctx)
    if err != nil || job == nil {
        return nil, ctx, err
    }
    workerCtx := correlation.Set(context.Background(), job.CorrelationID)
    workerCtx = applyDeadline(workerCtx, job.MaxRuntime)
    return job, workerCtx, nil
}
```

The worker uses the **returned `workerCtx`**, not the caller's `ctx`. This prevents accidentally bleeding the worker-loop's own correlation (if any) into the per-job context.

The worker entry point:

```go
// internal/worker/run.go
func (w *Worker) processOne(ctx context.Context) error {
    job, jobCtx, err := queue.Dequeue(ctx)
    if err != nil || job == nil {
        return err
    }
    handler := w.registry.Get(job.Type)
    return handler.Run(jobCtx, job)  // jobCtx carries the originating correlation_id
}
```

Anything `handler.Run` does — emit audit, log, enqueue child jobs, call external systems — uses `jobCtx`. The chain holds.

### 4.4 Worker → sub-job (cascading enqueue)

A handler that enqueues child jobs uses the same `queue.Enqueue`:

```go
// example: a fleet-scan handler spawns one job per host
func (h *FleetScanHandler) Run(ctx context.Context, parent *queue.Job) error {
    hosts := h.fetchHosts(ctx, parent.Payload.FleetID)
    for _, host := range hosts {
        _, err := queue.Enqueue(ctx, "scan.host", encodeHostScan(host))  // ctx carries parent's correlation_id
        if err != nil {
            return err
        }
    }
    return nil
}
```

The child jobs inherit the parent's correlation_id. A user clicking "scan fleet" produces:

```
req-018f3c2a8b7d4e9a   # the HTTP click
├── job-fleet-scan      # parent job (carries req-018f3c2a8b7d4e9a)
│   ├── job-scan-host-1   # child (carries req-018f3c2a8b7d4e9a)
│   ├── job-scan-host-2   # child (carries req-018f3c2a8b7d4e9a)
│   └── job-scan-host-N   # child (carries req-018f3c2a8b7d4e9a)
```

Grep for `req-018f3c2a8b7d4e9a` and the entire fleet operation reconstructs.

> **Why not a per-job ID instead?** Because the support question is "what happened with the user's 10am click?" — not "what happened with this one host scan?" The job ID answers the second; correlation_id answers the first. The job hierarchy is captured by `job.parent_id` (a separate column), not by mangling the correlation ID.

---

## 5. The four secondary boundaries

### 5.1 Cron tick → job

The cron scheduler has no originating HTTP request. It generates a fresh correlation_id at tick time:

```go
// internal/cron/tick.go
func (s *Scheduler) tick(jobID string) {
    ctx := correlation.Set(context.Background(), correlation.Generate(correlation.PrefixCron))
    slog.InfoContext(ctx, "cron tick", slog.String("cron_job", jobID))
    s.handlers[jobID].Run(ctx)
}
```

Each tick gets a distinct ID. If a tick enqueues 50 jobs, all 50 share the cron tick's ID. If the same cron job fires again at the next interval, it gets a different ID — different intent, different forensic story.

### 5.2 Worker → external system (Kensa, OIDC, webhook)

**HTTP-based outbound calls** (OIDC discovery, webhook dispatch, plugin calls) forward as headers:

```go
// internal/httpclient/client.go (wraps net/http.Client)
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
    if id, ok := correlation.From(ctx); ok {
        req.Header.Set("X-Correlation-Id", id)
    }
    return c.inner.Do(req.WithContext(ctx))
}
```

OpenWatch's own outbound HTTP always uses this wrapper; raw `http.Client.Do` is forbidden by lint (Section 7).

**Kensa SSH invocations** pass via env var:

```go
// internal/kensa/invoke.go
func (k *Invoker) Run(ctx context.Context, host string, args []string) (*Result, error) {
    id, _ := correlation.From(ctx)
    cmd := fmt.Sprintf("KENSA_CORRELATION_ID=%s kensa scan %s", shellEscape(id), strings.Join(args, " "))
    slog.InfoContext(ctx, "invoking kensa", slog.String("host", host), slog.String("kensa_cmd_summary", summary(args)))
    // ... ssh exec ...
}
```

Kensa's coordination ask: include `KENSA_CORRELATION_ID` in its JSON output (so Kensa-side audit/logs reference it). Until Kensa supports this, we log on the OpenWatch side at invocation and completion. Kensa-side logs remain unlinked, which is a known forensic gap to close in Phase 2.

### 5.3 Worker → audit

Already specified in `audit_event_taxonomy.md` (the audit envelope has `correlation_id`). The emit helper extracts from context:

```go
// internal/audit/emit.go
func Emit(ctx context.Context, e Event) {
    id, _ := correlation.From(ctx)
    e.CorrelationID = id  // fall back to "" if missing; the writer logs a warning
    audit.queue <- e
}
```

If a worker's `ctx` somehow has no correlation_id (a bug), the audit event still writes with `correlation_id = ""` — and the audit writer increments a counter that the operator can alert on. **Audit always succeeds; correlation propagation bugs surface as monitoring signal, not lost events.**

### 5.4 Anywhere → log line (slog)

A custom slog.Handler reads correlation_id from context and adds it as a top-level attribute on every log line:

```go
// internal/log/handler.go
type CorrelationHandler struct {
    inner slog.Handler
}

func (h *CorrelationHandler) Handle(ctx context.Context, r slog.Record) error {
    if id, ok := correlation.From(ctx); ok {
        r.AddAttrs(slog.String("correlation_id", id))
    }
    return h.inner.Handle(ctx, r)
}
```

This is wrapped around the stdlib JSON handler. The result: every `slog.InfoContext(ctx, ...)` call automatically carries correlation_id. Developers don't think about it.

Logs without context (rare — used in `slog.Info` not `slog.InfoContext`) have no correlation_id. The CI lint forbids non-Context slog calls outside of `func init()` and `func main()`.

---

## 6. Boot correlation

A single correlation_id is generated at process startup:

```go
// cmd/openwatch/main.go
func main() {
    bootID := correlation.Generate(correlation.PrefixBoot)
    bootCtx := correlation.Set(context.Background(), bootID)

    slog.InfoContext(bootCtx, "openwatch starting", slog.String("version", buildVersion))
    license.Load(bootCtx)
    policy.LoadAll(bootCtx)
    audit.EmitSync(bootCtx, audit.Event{Action: "system.startup"})
    server.Run(bootCtx)
}
```

All startup-phase events share `boot-018f3c2a8b7d4eb0`. Forensically: "what happened at the last restart?" → grep for the boot ID.

This works because every loader (`license`, `policy`, audit, etc.) accepts `ctx context.Context`. The discipline is uniform.

---

## 7. CI enforcement

The contract is meaningless unless the build catches violations. Three layers:

### 7.1 Forbidigo lint: no raw job_queue inserts

```yaml
# .golangci.yml
linters:
  enable:
    - forbidigo
linters-settings:
  forbidigo:
    forbid:
      - p: '^pgxpool\.Pool\.Exec.*INSERT INTO job_queue'
        msg: "Use queue.Enqueue(ctx, ...) — raw inserts skip correlation propagation"
      - p: '^http\.DefaultClient'
        msg: "Use internal/httpclient — wrapped to forward X-Correlation-Id"
      - p: '^slog\.(Info|Warn|Error|Debug)\b'
        msg: "Use slog.{Info,Warn,Error,Debug}Context — bare loggers skip correlation_id"
    exclude-godoc-examples: true
```

The `slog.Info` ban has a few legitimate exceptions (very-early startup logs before the boot context exists). These are tagged with `//nolint:forbidigo` and reviewed in PR.

### 7.2 Behavioral spec: every audit event has a non-empty correlation_id

`specs/system/correlation.spec.yaml` (post-Specter migration):

```yaml
spec_id: system/correlation
status: active
acceptance_criteria:
  - id: AC-1
    description: HTTP middleware sets a non-empty correlation_id on every request context
  - id: AC-2
    description: Sanitizer rejects malformed client-provided IDs (charset, length, reserved prefix)
  - id: AC-3
    description: queue.Enqueue requires correlation_id on context; returns error if missing
  - id: AC-4
    description: queue.Dequeue restores correlation_id onto fresh context (not caller context)
  - id: AC-5
    description: Cron ticks generate fresh correlation_id with cron- prefix
  - id: AC-6
    description: Boot generates one correlation_id shared by all startup events
  - id: AC-7
    description: Outbound HTTP via internal/httpclient forwards X-Correlation-Id
  - id: AC-8
    description: slog handler adds correlation_id to every Context-aware log call
  - id: AC-9
    description: Every audit event in test fixtures has a non-empty correlation_id
```

Each AC has one or more enforcing tests (Go `testing` package, `// AC-N` docstring).

### 7.3 End-to-end propagation test

One integration test exercises the full chain:

```go
// internal/correlation/propagation_test.go
func TestEndToEndPropagation(t *testing.T) {
    // 1. Send HTTP request with explicit X-Correlation-Id
    resp := postJSON(t, "/api/v1/diagnostics:enqueue-test-job", `{"message":"hi"}`,
        "X-Correlation-Id", "test-end2end-001")

    // 2. Response header echoes the same ID
    require.Equal(t, "test-end2end-001", resp.Header.Get("X-Correlation-Id"))

    // 3. Audit event for the API call carries the ID
    apiAudit := waitForAuditEvent(t, "diagnostics.enqueue", 2*time.Second)
    require.Equal(t, "test-end2end-001", apiAudit.CorrelationID)

    // 4. Worker picks up the job
    waitForJobStatus(t, apiAudit.ResourceID, "completed", 5*time.Second)

    // 5. Audit event written by the worker carries the same ID
    workerAudit := waitForAuditEvent(t, "diagnostics.test_job_completed", 5*time.Second)
    require.Equal(t, "test-end2end-001", workerAudit.CorrelationID)
}
```

This test runs in CI on every commit. If propagation breaks anywhere on the chain, the test fails. It is the single most important regression net for this contract.

---

## 8. Anti-patterns

| Anti-pattern | What's wrong | What to do instead |
|--------------|--------------|---------------------|
| `correlation.From(context.Background())` | `Background()` has no correlation_id. The `_, ok := correlation.From(...)` returns `ok=false`. | Pass through the real ctx. If you genuinely have no ctx (rare), treat that as a programming error. |
| Storing correlation_id in a struct field for "convenience" | The struct outlives the context. Stale correlation_ids start appearing in unrelated logs. | Always read from `ctx` at point of use. Pay the O(1) lookup cost. |
| Pulling correlation_id into a string and concatenating into log messages | Not searchable as a structured field; can't filter by it. | `slog.InfoContext(ctx, "...")` — the handler adds it as a structured attribute. |
| Calling `slog.Info` without context | The slog handler can't extract correlation_id; the log line has none. | Always use `slog.InfoContext`. Lint enforces this. |
| Using `http.DefaultClient` for outbound calls | Bypasses the wrapper that forwards `X-Correlation-Id`. Downstream systems see no correlation. | Use `internal/httpclient`. Lint enforces this. |
| Generating a new correlation_id inside a handler "to be safe" | Breaks the chain. The HTTP middleware already set one; overwriting it loses the link to the original request. | Read the existing one. If missing, that's a bug in the middleware, not a reason to generate. |
| Treating correlation_id as a security identifier | It is **not** authenticated, **not** unique-per-user, **not** tamper-proof. A client can replay any correlation_id they like (after sanitization). | Never use correlation_id for auth, rate limiting, or session tracking. It is forensic only. |
| Using correlation_id as a database join key | Multiple top-level requests over time can produce the same audit/job rows from the same user; correlation is *per request*, not *per user*. | Join on user_id, host_id, scan_id — domain keys. |

---

## 9. Failure modes

| Scenario | Behavior |
|----------|----------|
| Client sends a malicious header (e.g., 10MB string, control chars) | Sanitizer rejects; new ID generated; warning log emitted with truncated preview of the rejected value. |
| Two clients send the same correlation_id | Allowed. Logs and audit interleave under the same ID. Forensically, this looks like one logical operation by two callers — usually that's exactly what the clients intended (e.g., a workflow tool replaying). |
| Worker crashes before completing a job; job re-dispatches to another worker | New worker reads the same correlation_id from the job row. The chain holds. |
| Worker dequeues a job whose row has `correlation_id = ''` (legacy data, bug) | `queue.Dequeue` generates a fresh `req-` ID with a warning log; emits a `system.health.degraded` audit event. |
| `correlation.From(ctx)` returns `ok=false` deep in a handler | Should not happen if HTTPMiddleware ran. If it does, the audit emit fallback writes `correlation_id=""` and the writer counter increments. Operator alert fires when counter > 0. |
| Process killed mid-request | The originating request log shows the started entry; no completion entry. Same correlation_id appears in any audit events that did flush. Recovery is on the operator (look at the start log + system shutdown event). |
| Clock skew makes correlation_ids out of order | UUIDv7 is millisecond-precision. Skew >1ms produces out-of-order IDs but uniqueness is preserved (the random suffix dominates collision risk). Forensic queries that rely on lexicographic time order may see misordered events; queries that filter by correlation_id are unaffected. |
| Test injects `test-foo` and runs concurrently with another test injecting `test-foo` | Tests must use unique IDs. The `test-` prefix is reserved for tests but uniqueness is the test's responsibility; collision produces test-noise, not production bugs. |

---

## 10. Stage 0 vs Stage 2 split

### Stage 0 ships (Day 4 + Day 5):

- `internal/correlation/` — generate, sanitize, set, from, prefix constants
- `correlation.HTTPMiddleware` wired into the chi router
- `internal/log/CorrelationHandler` wrapping slog.JSONHandler
- `internal/audit/Emit` integration (already in audit foundation)
- Boot correlation (Day 1 main.go scaffold updated to set boot-)
- `internal/httpclient/Client` wrapper (forwards header)
- Forbidigo lint config in `.golangci.yml`

### Stage 0 ships (Day 8, alongside policy framework):

- `internal/queue/Enqueue` and `Dequeue` helpers with correlation propagation
- `job_queue.correlation_id` column (folded into the existing job_queue migration from Day 3)
- `internal/cron/Scheduler.tick` with cron- generation
- End-to-end propagation test

### Stage 2 ships (when real jobs land):

- Job handlers using `Enqueue` for sub-jobs
- Kensa invoker passing `KENSA_CORRELATION_ID`
- OIDC/SAML/webhook outbound calls using `internal/httpclient`
- Per-job-type correlation forensic tests

The Stage 0 work is small (~600 LOC + lint config + migrations) but locks the contract before any consumer exists. Stage 2 consumers cannot accidentally bypass it because the helpers are already the only path.

---

## 11. Performance

The propagation machinery is hot-path; targets:

| Operation | Target | Notes |
|-----------|--------|-------|
| `correlation.Generate()` | < 200ns | One `rand.Read(8)` + hex encode + concat |
| `correlation.Set(ctx, id)` | < 50ns | Single `context.WithValue` |
| `correlation.From(ctx)` | < 30ns | Chain walk on context (typical depth ~5) |
| `HTTPMiddleware` overhead | < 1µs | Generate + sanitize + set + header write |
| `slog handler` overhead | < 100ns | One context lookup + one attr add |
| End-to-end (HTTP entry to log line) | < 2µs added | Negligible vs DB and HTTP serialization |

`crypto/rand` is the long pole; we read 8 bytes (~150ns on a typical Linux). Pre-fetching from a buffered random source is an option if benchmarks show contention, but at our request rates it's unnecessary.

---

## 12. Open questions

1. **OTel adoption.** When (not if) we adopt OpenTelemetry, do we wrap the correlation middleware to emit both `X-Correlation-Id` and `traceparent`? Or use OTel's native trace context as the correlation source? Defer until OTel is on the roadmap; the propagation discipline transfers either way.
2. **Per-tenant prefixing.** Multi-tenant deployments may want `tenant-acme-req-...` for per-tenant log filtering. Current design is single-tenant; defer to multi-tenant epic.
3. **Correlation ID in metrics labels.** Prometheus high-cardinality labels are dangerous. Correlation IDs must NOT become metric labels — they would explode the cardinality. Logs and audit only.
4. **Frontend propagation.** The TypeScript frontend should generate a correlation_id at the start of a user action (e.g., "click scan button") and pass it through every API call for that action. That makes the frontend a first-class origin point. Defer to frontend integration epic; design transfers cleanly.
5. **Long-running operations.** A scan can run for tens of minutes. The correlation_id stays the same end-to-end, but the operator's view of "what's happening now?" needs additional handles. Job ID + parent_id covers the operator view; correlation_id covers the forensic view. No new design needed.

---

## Cross-references

- HTTP design: `docs/engineering/api_design_principles.md` §9.4 (correlation_id in error envelope), §11 (`X-Correlation-Id` header).
- Audit foundation: `docs/engineering/audit_event_taxonomy.md` §3 (envelope), §6 (writer paths).
- Policies: `docs/engineering/policies_as_data.md` §8 (audit integration; `policy.applied` carries correlation_id).
- Roadmap: 2026-04-27 entry on `X-Correlation-Id` propagation; 2026-04-30 entries on this design.
- Stage 0: Day 4 (HTTP middleware), Day 5 (audit uses it), Day 8 (queue helpers + lint + e2e test).
