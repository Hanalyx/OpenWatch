// Package alertrouter is the bridge between OpenWatch's in-process
// event bus (internal/eventbus) and external notification channels
// (Slack, email, webhook, PagerDuty).
//
// Spec: specs/system/alert-router.spec.yaml (status: approved)
//
// Architectural choices:
//
//   - Subscribes to EventKindHeartbeatPulse + EventKindDriftDetected on
//     the bus at Start. A single dispatch goroutine reads from the
//     subscription channels and translates each event to a typed Alert
//     before fan-out. Spec C-08 / AC-11.
//
//   - Closed enums for AlertType and Severity. Each AlertType has a
//     default Severity that the router applies before channel routing.
//     Spec C-01 / C-02.
//
//   - In-memory dedup gate keyed by (alert_type, host_id, rule_id) with
//     configurable TTL (default 60 min, range 60s..24h). Dedup state
//     does NOT survive process restart — for v1, single-instance
//     dedup is correct; multi-instance deploys can slot a Postgres
//     store behind the same interface. Spec C-03 / C-04.
//
//   - Channel registration with tag-filter routing. Each channel
//     declares a Tags map of required key/value pairs; an empty Tags
//     map is a wildcard (channel receives every alert). Alert.Tags
//     always carries at minimum severity + alert_type + host_id.
//     Spec C-05 / C-06.
//
//   - Per-channel goroutine for Channel.Send. A Send returning an error
//     increments that channel's FailureCount but does NOT halt delivery
//     to other channels for the same alert. The router never panics on
//     a channel-side error. Spec C-07 / AC-10.
//
//   - Router.Stop unsubscribes from the bus AND waits up to 10s for
//     in-flight Channel.Send calls to complete (drain timeout). After
//     Stop, new events arriving on the bus subscription are ignored.
//     Spec C-08 / AC-12.
//
// Distinction from internal/audit: the audit log is the persistent
// forensic record of who/what/when; the alert router is real-time
// delivery to notification surfaces. Most alert-worthy events emit
// to both — e.g., a major drift writes compliance.drift.detected to
// the audit log AND fires through the alert router to Slack.
//
// Concrete Channel implementations (Slack, email, webhook) live in
// subpackages so the core router has no external SDK dependencies.
// This PR ships the interface + a fake (for tests) + stdout (for
// dev/test scenarios). Spec C-09 / AC-13.
package alertrouter
