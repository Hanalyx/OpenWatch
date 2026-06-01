// Package scheduler is the recurring driver for OS Intelligence
// collection — the cron-like loop that turns the one-shot
// collector.Service.RunCycle into a continuous per-host cadence.
//
// Spec: app/specs/system/intelligence-scheduler.spec.yaml (status: approved).
//
// Architectural notes:
//
//   - Tick rate vs per-host interval. The Run loop ticks on a short
//     cadence (effectiveInterval, default 30s, clamped to [5s, 5min]).
//     The PER-HOST cadence is the much-longer IntelligenceConfig.IntervalSec
//     (default 1h, clamped to [5min, 24h]) — the tick rate just sets
//     how quickly a freshly-due host gets noticed.
//
//   - Single-query dispatch. listIntelTargets returns due hosts in
//     one SQL query — no per-host follow-up reads. The partial index
//     on host_intelligence_state(next_intelligence_at) makes the read
//     cheap regardless of fleet size. Spec C-02 + AC-07.
//
//   - Per-host advisory lock. dispatchHost wraps RunCycle in a
//     pg_advisory_xact_lock keyed by hashtext(host_id). Two scheduler
//     processes racing on the same host serialize at the DB level —
//     one runs, the other no-ops. Same pattern as the scan worker.
//     Spec C-03 + AC-12.
//
//   - Bounded worker pool. At most IntelligenceConfig.RateLimit
//     RunCycles in flight per scheduler instance (default 10, cap 200).
//     Spec C-07 + AC-13.
//
//   - Independent intel + scan backoff. Failed RunCycle UPSERTs
//     host_backoff_state with probe_type='intel' — the (host_id,
//     probe_type=scan) row is untouched. A flaky Intelligence probe
//     can't starve the scan dispatcher. Spec C-05 + AC-11.
//
//   - Maintenance respect. hosts.maintenance_mode = true excludes
//     the host from listIntelTargets, same convention as
//     system-liveness-loop v1.3.0.
//
//   - HTTP-free. The scheduler package MUST NOT import internal/server
//     or net/http. Spec C-08 + AC-15 source-inspect to guarantee.
//
// Lifecycle:
//
//	svc := scheduler.NewService(pool, collectorSvc).
//	         WithCredentialService(credSvc).
//	         WithRateLimit(cfg.RateLimit)
//	go svc.Run(ctx)
//	// ...later...
//	svc.Stop()  // graceful drain; blocks until in-flight cycles finish
package scheduler
