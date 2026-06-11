// Package fleetrollup answers "how is my fleet doing right now?" via
// read-only aggregations over the Slice B persistence layer
// (host_rule_state, transactions, host_liveness).
//
// Spec: specs/system/fleet-rollup.spec.yaml (status: approved)
//
// Architectural choices:
//
//   - Read-only. No INSERT/UPDATE/DELETE. Source-inspection enforces
//     (AC-11). Mutation belongs to the producers (B.1c writer for
//     transactions + host_rule_state, B.2a liveness for host_liveness).
//
//   - Typed results. Every method returns a concrete struct. No
//     map[string]any leaks across the API. JSON encoding happens at
//     the HTTP layer, not here. Spec C-08.
//
//   - Parameterized SQL only. No fmt.Sprintf-into-SQL, no string
//     concatenation of values into SQL fragments. Source-inspection
//     enforces (AC-12). Bounds (LIMIT) and column lists are static
//     in the query string.
//
//   - Hard upper limit (1000) on every paginated query, regardless
//     of caller input. Protects callers from DoS-ing the dashboard
//     when a fleet grows unexpectedly. Spec C-03 / C-04.
//
//   - Context-aware. Every method respects ctx cancellation — a
//     canceled context returns context.Canceled, never blocks. Spec
//     C-07 / AC-09.
//
//   - Empty-fleet semantics. An empty host_rule_state, empty
//     host_liveness, empty transactions table → zero values, never
//     ErrNoRows. The dashboard renders "no data yet" instead of
//     swallowing an error. Spec C-05 / AC-02.
package fleetrollup
