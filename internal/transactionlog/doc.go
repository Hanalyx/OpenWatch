// Package transactionlog implements OpenWatch's compliance write-on-change
// persistence layer.
//
// Spec: specs/system/transaction-log-writer.spec.yaml (status: approved)
//
// Architectural choices:
//
//   - host_rule_state holds ONE row per (host, rule) — the CURRENT state.
//     UPSERTed every scan (last_checked_at moves forward, check_count++,
//     status may change).
//
//   - transactions is append-only and records ONLY state changes
//     (pass→fail, fail→pass, or first-seen). A scan that finds the
//     same state as last time writes zero transactions rows for that
//     rule. This is the 99.7% storage reduction from the Q1 design.
//
//   - One database transaction per writer.Apply call: BEGIN, then N
//     UPSERTs to host_rule_state + M INSERTs to transactions (where
//     M ≤ N is the count of state changes), COMMIT. Partial writes are
//     forbidden — spec C-01.
//
//   - Idempotent on scan_id: a second Apply with the same scan_id is a
//     no-op (UNIQUE(scan_id, rule_id) on transactions catches it).
//     Spec C-04.
//
//   - All DB access through sqlc-generated typed queries or
//     parameterized SQL via pgx; no raw string-concatenation SQL.
//     Spec C-09 / AC-13 source-inspection enforces this.
//
//   - Per-rule evidence is capped at 256 KB; oversized evidence is
//     rejected with a typed error before INSERT. Spec C-10 / AC-14.
//
//   - The Python-era baselines table is explicitly NOT used here —
//     the prior transactions row IS the baseline. Spec C-08 / AC-12
//     source-inspects to confirm no references to the Python-era
//     baseline table name exist anywhere in the Go codebase.
package transactionlog
