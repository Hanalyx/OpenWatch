# Kensa ask: public construction path for scan with a caller-supplied TransportFactory

> **RESOLVED — kensa v0.3.2 (2026-06-12) shipped BOTH shapes:**
> `pkg/kensa.NewScanner()` (stateless, concurrency-safe shared; Remediate
> errors by design) and `DefaultWithTransportFactory(ctx, storePath, tf,
> engineOpts...)` (nil factory rejected; for Phase 7 remediation).
> OpenWatch binds the scan-only composition:
> `api.New(Config{Scanner: kensa.NewScanner(), TransportFactory: ours})` —
> see `internal/kensa/scanfunc.go` (newScanService). Retained for the
> record of the gap analysis.

**From:** OpenWatch scan-foundation sprint · 2026-06-12
**Blocks (was):** the production ScanFunc binding (the last step of OpenWatch Phase 0)

## The gap

OpenWatch must scan with its **own** `api.TransportFactory` — credentials are
decrypted in memory only, so kensa's bundled `ssh.Factory{}` (KeyPath on disk /
ssh-agent) is unusable. The adapter is built and tested on our side
(`api.Transport` over our SSH stack). What's missing is any **public way to
construct a Kensa that uses it**:

- `pkg/kensa.Default` / `DefaultWithEngineOptions` hardcode
  `TransportFactory: ssh.Factory{}` (pkg/kensa/kensa.go:169); engine options
  cannot override it.
- `api.New(Config)` is public, but the `Config.Scanner` value
  (`api.ScannerBackend`) is only implemented by `internal/scan` — not
  importable.
- `RunOption` has no transport override (only `WithNonBlocking`).

Notably, the scan path needs only TWO config fields: `Kensa.Scan` guards on
`Scanner == nil || TransportFactory == nil` and never touches Engine, Store,
Log, or Verifier (api/kensa.go:248). So a scan-only consumer needs far less
than `Default` builds.

## The ask — either shape works for us (pick what fits kensa best)

**(a) Smallest surface — export the scanner constructor:**

```go
// pkg/kensa
// NewScanner returns the standard check-engine ScannerBackend, for
// embedders that supply their own TransportFactory via api.New.
func NewScanner() api.ScannerBackend
```

OpenWatch then composes: `api.New(api.Config{Scanner: kensa.NewScanner(),
TransportFactory: ours})` — no store/signer/engine constructed for scan-only
use.

**(b) Default variant — factory injection:**

```go
// pkg/kensa
func DefaultWithTransportFactory(ctx context.Context, storePath string,
    tf api.TransportFactory, engineOpts ...engine.Option) (*Service, error)
```

Same wiring as Default, transport swapped. (Matches the
DefaultWithEngineOptions precedent; OpenWatch would pass an ephemeral
storePath since PostgreSQL is its system of record.)

If (a): note whether the scanner is stateless/concurrency-safe across hosts
(our worker scans hosts concurrently; one shared ScannerBackend vs
one-per-scan).

## Context for the changelog

This is the third and final piece of the OpenWatch scan integration, after
the v0.3.0 ComplianceStatus verdict surface and the v0.3.1 LoadRules export —
with it, the full chain is public: `LoadRules → api.New(Scanner, our
TransportFactory) → Scan → Outcomes`.
