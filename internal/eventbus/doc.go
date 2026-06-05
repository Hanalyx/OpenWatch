// Package eventbus implements OpenWatch's in-process typed pub/sub.
//
// Spec: specs/system/event-bus.spec.yaml (status: approved)
//
// Architectural choices:
//
//   - In-process via Go channels. Bus events never cross the process
//     boundary; if/when cross-process delivery is needed, a separate
//     bridge sits next to the bus, not inside it. Spec C-01 / AC-12.
//
//   - Typed Event interface + closed EventKind enum. Subscribers
//     filter by EventKind at registration; no wildcard subscribe.
//     Spec C-02 / C-05.
//
//   - Per-subscriber goroutine. Each subscriber has its own delivery
//     channel and its own goroutine reading from it. A slow subscriber
//     does NOT block other subscribers — backpressure is absorbed by
//     channel buffering (default 1024) and overflow drops increment
//     DroppedCount. Spec C-03 / C-08.
//
//   - Bus.Shutdown drains then closes. Publishers that arrive after
//     Shutdown silently no-op. Spec C-07.
//
// The bus carries Bucket B events per the Kensa/OpenWatch boundary
// doc § 4: OpenWatch-emitted events (HeartbeatPulse from B.2a liveness,
// DriftDetected from B.2b drift). Kensa-emitted events (Bucket A) are
// out of scope; if a future feature consumes those, a separate bridge
// translates Kensa → OpenWatch bus events.
//
// Distinction from internal/audit: the audit log is the persistent
// forensic record; the bus is in-memory dispatch to runtime consumers.
// Some events produce both — a drift detection emits
// compliance.drift.detected to the audit log AND publishes
// DriftDetected to the bus so the alert router (B.3b) can run.
package eventbus
