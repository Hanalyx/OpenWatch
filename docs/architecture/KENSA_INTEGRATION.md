# OpenWatch and Kensa integration

This document describes how the current OpenWatch (single Go binary, PostgreSQL,
systemd) integrates the Kensa compliance engine. It covers the integration
package, the responsibility boundary, the data path, and what is and is not yet
wired in the code.

For the full, ratified responsibility split between the two products, read
[`docs/KENSA_OPENWATCH_BOUNDARY.md`](../KENSA_OPENWATCH_BOUNDARY.md) — that is the
authoritative boundary reference, and this document does not restate it in full.
For the behavioral contract enforced by tests, read
[`specs/system/kensa-executor.spec.yaml`](../../specs/system/kensa-executor.spec.yaml)
(version 2.0.0, status `approved`).

## What Kensa is

Kensa is a pure, single-host measurement engine maintained at
`github.com/Hanalyx/kensa`. It connects to a host over SSH, evaluates native
YAML rules, and returns a structured result with evidence. It is stateless
between invocations and single-host per invocation. It does not store results
long-term, manage exceptions, schedule scans, or provide a UI.

OpenWatch is the long-lived fleet platform around that engine: it owns the host
inventory, the credential store, scheduling, persistence (the transaction log),
drift detection, fleet rollups, alerting, and the API plus embedded UI.

Kensa is integrated as a Go module dependency, not a separate process or
container. OpenSCAP, `oscap`, XCCDF, and OVAL are not used and never have been in
the Go rebuild; Kensa runs its own SSH-based checks against native YAML rules.

## Version pin

OpenWatch pins the Kensa module in `go.mod`:

| Item | Value | Source |
|------|-------|--------|
| Module | `github.com/Hanalyx/kensa` | `go.mod` |
| Version | `v0.2.1` | `go.mod`, `internal/kensa/types.go` (`KensaModuleVersion`) |

The linked Kensa version is also exposed at runtime. `GET /api/v1/health`
returns a `kensa` field populated by `version.Kensa()` in
`internal/version/version.go`, which reads the version from the binary's build
info rather than a hand-edited constant, so it always reflects the Kensa module
actually linked in.

Note: the package comment in `internal/kensa/doc.go` still reads `v0.1.1`. That
comment is stale; `go.mod` and `internal/kensa/types.go` are the authoritative
sources and both record `v0.2.1`.

## Integration package

All Kensa integration lives in one package, `internal/kensa/`. Per its package
doc, this is the only package in OpenWatch that imports
`github.com/Hanalyx/kensa`.

| File | Purpose |
|------|---------|
| `internal/kensa/doc.go` | Package contract and architectural decisions |
| `internal/kensa/types.go` | `Result`, `RuleOutcome`, sentinel errors, failure-reason enum, evidence cap |
| `internal/kensa/executor.go` | `Executor`: concurrency guard, credential bridge, audit emission |
| `internal/kensa/import.go` | Blank import that keeps the module pinned in `go.mod` |
| `internal/kensa/backoff.go` | Retry backoff helpers |

The executor is constructed once at process start and held for the process
lifetime. `internal/worker/credential_bridge.go` adapts OpenWatch's credential
service to the executor's `CredentialBridge` interface.

### Security properties enforced by the executor

These are stated in `internal/kensa/doc.go` and `types.go` and verified by the
spec's acceptance criteria:

- SSH private keys are parsed in memory via `crypto/ssh.ParsePrivateKey` and
  passed to Kensa through an in-memory transport. The key bytes never touch
  `/tmp` or any disk path (spec AC-02). Kensa's `HostConfig.KeyPath` is never
  populated by this wrapper.
- Decrypted credential plaintext is zeroed via a deferred `Wipe()` on every code
  path — success, error, and context cancellation (spec AC-07).
- A per-host concurrency guard (a `sync.Map` of in-flight host IDs) prevents two
  concurrent scans against the same host; the second caller gets `ErrHostBusy`
  immediately, without opening an SSH session (spec AC-03). Different hosts run
  in parallel.
- Per-rule evidence is capped at 10 MiB (`MaxEvidenceBytes`); a larger blob
  fails the whole scan with `ErrEvidenceOversize` (spec AC-14).
- No engine-abstraction interface is defined; Kensa is invoked directly. There
  is no `ScanEngine interface` seam (spec AC-12).

### Framework-agnostic scans (v2.0.0 change)

As of the executor spec v2.0.0, a scan covers the full rule corpus applicable to
the host's detected OS capabilities. There is no per-scan framework parameter;
`Result` has no `FrameworkID` field. Per-rule framework metadata lives on each
`RuleOutcome.FrameworkRefs` (for example `"cis_rhel9_v2": "5.1.12"`). This is a
breaking change from the earlier per-framework scan model.

## Result shape

`Executor.Run` returns a `*kensa.Result` on success (see
`internal/kensa/types.go`):

| Field | Type | Notes |
|-------|------|-------|
| `HostID` | `uuid.UUID` | Target host |
| `Outcomes` | `[]RuleOutcome` | One entry per evaluated rule |
| `StartedAt` / `CompletedAt` | `time.Time` | Scan window |
| `PolicyVersion` | `string` | Snapshotted from the job payload |

Each `RuleOutcome` carries `RuleID`, `Status` (`pass`, `fail`, `skipped`,
`error`), `Severity`, raw `Evidence` bytes (capped at `MaxEvidenceBytes`),
`FrameworkRefs`, and `SkipReason` (set when skipped).

## Failure classification

Failures are returned as sentinel errors and mapped to a closed
`detail.reason` enum on the `scan.failed` audit event (spec AC-06):

| Sentinel error | `FailureReason` |
|----------------|-----------------|
| `ErrHostKeyUnknown` | `host_key_unknown` |
| `ErrCredentialDecryption` | `credential_decryption_failed` |
| `ErrEvidenceOversize` | `evidence_oversize` |
| `ErrKensaInternal` | `kensa_error` |
| `ErrHostBusy` | `host_busy` |
| (timeout) | `timeout` |
| `ErrNoCredential` | host has no credential registered |

## Data path

The intended scan path, per the boundary doc (§5.2) and the worker wiring:

1. The scheduler enqueues a scan job onto the PostgreSQL-native job queue
   (`SKIP LOCKED`), with a JSONB body carrying the host ID, a policy version,
   and an HMAC (`internal/worker/payload.go`).
2. The worker (`openwatch worker`) dequeues the job and resolves the host's
   credential through the credential bridge.
3. The executor opens an in-memory SSH session and runs the Kensa scan against
   the host.
4. The result is handed to the transaction-log writer
   (`internal/transactionlog/writer.go`), which persists meaningful state
   changes and emits audit events.
5. Audit events (`scan.started`, `scan.completed`, `scan.failed`) are emitted
   through `audit.Emit`.

Persistence is not the executor's responsibility; the transaction-log writer
owns it. Steps 1, 2, 4, and 5 are wired in `cmd/openwatch/worker.go`.

## What is not yet wired

The live Kensa scan call is not yet wired into production. In
`internal/kensa/executor.go`, `NewExecutor` binds `scanFunc` to
`unwiredScanFunc`, which returns an error reading "scan path not yet wired
(production wiring pending)". The worker constructs the executor with
`kensa.NewExecutor(...)` (`cmd/openwatch/worker.go`) but does not yet call
`WithScanFunc` to inject a closure backed by the real Kensa client. Until that
binding lands (tracked as spec AC-18), a dequeued scan job fails with
`ReasonKensaError` rather than performing a real scan.

`internal/kensa/import.go` is a blank import (`_ "github.com/Hanalyx/kensa/api"`)
that keeps the module pinned in `go.mod` while no Kensa symbol is called
directly; it is removed once the executor invokes real Kensa calls.

These items are roadmap, not present behavior:

- Live `ScanFunc` wiring in the worker (spec AC-18).
- A Kensa `Reachable(ctx, host)` reachability primitive for the liveness loop;
  until it exists, OpenWatch dials hosts directly via `internal/ssh`
  (boundary doc §6.3).
- Subscription to Kensa transaction-progress events for in-flight scan
  visibility; `Kensa.Subscribe` is stubbed on the Kensa side
  (boundary doc §6.4).
- Remediation and rollback execution through Kensa.

Do not document these as working features until the corresponding code lands.

## Operating the integration

Kensa runs inside the OpenWatch binary, so there is no separate Kensa service to
start, scan, or restart. You operate the worker that drives it.

Check the linked Kensa version:

```
curl -sk https://localhost:8443/api/v1/health
```

The response includes a `kensa` field with the embedded engine version.

The worker process runs the scan jobs:

```
systemctl status openwatch.service
journalctl -u openwatch.service -f
```

Inspect queued and in-flight scan jobs in PostgreSQL (use the DSN from
`/etc/openwatch/secrets.env`):

```
psql "$OPENWATCH_DATABASE_DSN" -c \
  "select id, status, created_at from job_queue order by created_at desc limit 10;"
```

For install, configuration, TLS, and database setup, follow the canonical
[`docs/guides/INSTALLATION.md`](../guides/INSTALLATION.md); this
document does not duplicate those procedures. For role and permission details
that gate the scan and compliance endpoints, see
[`docs/engineering/rbac_registry.md`](../engineering/rbac_registry.md).

## References

| Topic | Source |
|-------|--------|
| Responsibility boundary | `docs/KENSA_OPENWATCH_BOUNDARY.md` |
| Executor behavioral spec | `specs/system/kensa-executor.spec.yaml` (v2.0.0, approved) |
| Integration package | `internal/kensa/` |
| Worker wiring | `cmd/openwatch/worker.go`, `internal/worker/` |
| Transaction-log writer | `internal/transactionlog/writer.go` |
| Health endpoint and Kensa version | `api/openapi.yaml` (`GET /api/v1/health`), `internal/version/version.go` |
| Install and configuration | `docs/guides/INSTALLATION.md` |
| Roles and permissions | `docs/engineering/rbac_registry.md` |
