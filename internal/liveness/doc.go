// Package liveness implements OpenWatch's periodic host reachability
// probe loop.
//
// Spec: specs/system/liveness-loop.spec.yaml (status: approved)
//
// Architectural choices:
//
//   - Credential-free probe. The loop opens a plain TCP connection to
//     port 22 and reads up to 256 bytes of banner. No SSH handshake,
//     no key authentication, no credential decryption. Spec C-07 +
//     AC-14 source-inspect to guarantee this property.
//
//   - TCP-banner over ICMP. ICMP pings are commonly firewalled but
//     port 22 is the actual signal that matters — a host that responds
//     to ICMP but blocks SSH is "alive" but not "reachable for the
//     scheduler's purposes". Spec C-01.
//
//   - Hysteresis on state transition. A single transient failure does
//     NOT flip a previously-reachable host to "unreachable" — the loop
//     waits for N consecutive failures (default 2). Avoids alert noise
//     from one-off network blips. Spec C-08.
//
//   - Per-host jitter. Probe scheduling adds ±20% per-host jitter so
//     a fleet of 1000 hosts doesn't all probe at exactly t=0. Jitter is
//     deterministic from (hostID, interval) — same inputs always
//     produce the same jittered output. Spec C-04.
//
//   - Per-host concurrency guard. A second probe of the same host
//     while the first is in flight returns ErrProbeInFlight. Different
//     hosts probe in parallel. Spec C-05, mirrors the kensa-executor
//     pattern.
//
//   - Audit on state transitions only. host.connectivity.checked
//     emits on first-seen + every state flip; steady-state probes
//     don't audit. Spec C-06. This keeps the audit volume bounded
//     for stable fleets.
//
// Future: when Kensa.Reachable() lands (boundary doc §6.3), the
// probeFunc seam swaps the in-process net.DialTimeout call for a
// Kensa-side probe that shares the SSH ControlMaster with active
// scans. Behavior visible to callers is unchanged.
package liveness
