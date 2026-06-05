// Package alerts owns the lifecycle service for persisted alerts —
// acknowledge / silence / resolve / dismiss transitions plus the
// auto-resolve hook that closes host_unreachable when host_recovered
// arrives.
//
// Spec: app/specs/system/alerts.spec.yaml (status: approved).
//
// Architectural notes:
//
//   - SSOT split with system-alert-router. The router persists every
//     routed alert into the alerts table with initial state='active'.
//     This package mutates state. Spec system-alert-router C-11 says
//     "transitions are owned by system-alerts"; this is the realization.
//
//   - Closed state machine. Allowed transitions enumerated in C-02.
//     Invalid transitions return ErrInvalidTransition with both the
//     prior + requested state in the message so handlers can render a
//     useful error to operators.
//
//   - Row-level locking. Every transition runs inside BEGIN; SELECT
//     ... FOR UPDATE; UPDATE; COMMIT. Concurrent attempts on the same
//     alert serialize — the second sees the post-transition state.
//     Spec C-01.
//
//   - Audit per transition. AlertAcknowledged / AlertSilenced /
//     AlertResolved / AlertDismissed plus AlertUnsilencedAuto for the
//     sweeper. The codes exist in app/audit/events.yaml (3 are new in
//     PR 3; alert.acknowledged + alert.resolved already shipped).
//     Spec C-05.
//
//   - Auto-resolve hook. A bus subscription registered at Service
//     construction listens for new host_recovered / drift_improvement
//     alerts and resolves matching open alerts for the same host.
//     Spec C-08 / AC-11.
//
//   - HTTP-free. The package MUST NOT import internal/server or
//     net/http. The HTTP surface lives in api-alerts (PR 3 handlers).
//     Spec C-09 + AC-15.
package alerts
