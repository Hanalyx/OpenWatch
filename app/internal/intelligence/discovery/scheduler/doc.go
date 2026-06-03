// Package scheduler is the recurring driver for OS discovery — the
// loop that finds hosts whose hosts.os_discovered_at column is stale
// (NULL or older than the policy interval) and enqueues
// host.discovery jobs through internal/queue so the worker pool
// picks them up and runs discovery.Service.Discover on them.
//
// Spec: app/specs/system/discovery-scheduler.spec.yaml (status: approved).
//
// Architectural notes:
//
//   - Tick rate vs per-host interval. The Run loop ticks on a short
//     cadence (effectiveInterval, default 60s, clamped to [10s, 5min]).
//     The PER-HOST cadence is the much-longer DiscoveryConfig.IntervalSec
//     (default 24h, clamped to [1h, 7d]) — the tick rate just sets
//     how quickly a freshly-due host gets noticed.
//
//   - Single-query dispatch. listDiscoveryTargets returns due hosts in
//     one SQL query — no per-host follow-up reads. The condition is
//     hosts.os_discovered_at IS NULL OR hosts.os_discovered_at + interval
//     <= now(). NULL means "never discovered" and goes first.
//
//   - Per-tick rate limit. At most DiscoveryConfig.RateLimit hosts are
//     enqueued per tick (default 25, clamped [1, 500]). Bounds the
//     thundering-herd shape when a fresh fleet hits NULL all at once.
//     Dropped hosts re-surface on the next tick because nothing about
//     their state changed.
//
//   - Stateless. Unlike the OS Intelligence scheduler this package does
//     NOT maintain backoff state. Discovery failures (SSH timeout,
//     sudo prompt absent, unreachable host) leave hosts.os_discovered_at
//     NULL; the next tick re-enqueues. The job_queue's own retry +
//     dead-letter contract absorbs flapping hosts without the scheduler
//     needing to track per-host failure counts.
//
//   - Maintenance respect. hosts.maintenance_mode = true excludes
//     the host from listDiscoveryTargets. DiscoveryConfig.MaintenanceGlobal
//     short-circuits the whole tick before any DB read happens.
//
//   - Enqueue-only. The scheduler does not import internal/intelligence/discovery
//     for its SSH side; it depends only on the public job-kind constant
//     and payload type. All real discovery work runs in the worker.
//
//   - HTTP-free. The scheduler package MUST NOT import internal/server
//     or net/http. Spec C-07 + AC-11 source-inspect to guarantee.
//
// Lifecycle:
//
//	svc := scheduler.NewService(pool).
//	         WithConfigLoader(cfgStore.LoadDiscovery)
//	go svc.Run(ctx)
//	// ...later...
//	svc.Stop()  // graceful drain; blocks until in-flight enqueue calls finish
package scheduler
