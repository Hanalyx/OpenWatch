// Package collector implements OS Intelligence — the recurring,
// write-on-change counterpart to OS Discovery.
//
// Spec: app/specs/system/os-intelligence.spec.yaml (status: approved).
//
// Architectural notes:
//
//   - Credential-aware boundary. Like internal/intelligence/discovery
//     and unlike internal/liveness, collector IS credential-aware: it
//     imports internal/credential and golang.org/x/crypto/ssh, opens
//     real SSH sessions, and runs commands that may need sudo. Future
//     readers should not move credential-free probes here.
//
//   - One SSH session per cycle. The probe batch (account, security,
//     system) runs in one session. Multi-dial is forbidden. Spec C-01
//     / AC-09 enforce.
//
//   - Pure parsers. Each parser takes a single command's raw bytes and
//     returns a typed struct. No SSH, no DB, no HTTP. Parser tests are
//     fixture-based.
//
//   - Write-on-change. host_intelligence_state holds the LAST snapshot
//     (UPSERT, no history). host_intelligence_events appends one row
//     per detected change. Same discipline as Slice B's
//     transactions + host_rule_state (99.7% write reduction).
//
//   - Closed taxonomy. taxonomy.go enumerates ~25 event codes spanning
//     account, security, system. The migration CHECK and the
//     audit/events.yaml entries mirror this exactly. Adding a new code
//     requires touching all three.
//
//   - Eventbus + audit on every change. Per-event publish to
//     EventKindIntelligenceEvent AND emit a per-code audit event. The
//     alert router subscribes to the bus; auditors trail the audit log.
//
// What this package does NOT do:
//
//   - The recurring scheduler / cron loop — lands in PR 1.3.
//   - REST endpoints — lands in PR 1.3.
//   - Severity-threshold → alert-router promotion — separate
//     system-alert-router amendment.
package collector
