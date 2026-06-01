// Package activity merges alerts + transactions + intelligence_events
// + audit_events into a single time-ordered feed, with per-source
// RBAC and seek-cursor pagination.
//
// Spec: app/specs/system/activity.spec.yaml (status: approved).
//
// Architectural notes:
//
//   - One UNION query. Service.List runs exactly one SQL statement —
//     a UNION ALL across the up-to-four sources, with severity /
//     time-range / source / host filters pushed down to each leg.
//     Spec C-01 + AC-11.
//
//   - Per-source RBAC. The caller's permission set determines which
//     legs of the UNION are populated. Without alert:read the alerts
//     leg returns zero rows; without host:read transactions and
//     intelligence return zero; without audit:read audit returns zero.
//     The "hidden by RBAC" count is reported alongside the items so
//     the UI can render "47 items; 200 hidden by your role".
//     Spec C-02 + AC-03 / AC-04.
//
//   - Cursor on occurred_at DESC. Same pattern as audit + intelligence
//     APIs. Empty cursor on the response means terminal page.
//
//   - HTTP-free. The package MUST NOT import internal/server or
//     net/http. The HTTP surface lives in api-activity (the
//     internal/server handler delegates here). Spec C-07 + AC-12.
package activity
