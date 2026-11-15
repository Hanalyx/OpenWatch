// Package drift implements OpenWatch's compliance drift detector.
//
// Spec: specs/system/drift-detector.spec.yaml (status: approved)
//
// Architectural choices:
//
//   - Pure consumer of the transaction log (B.1c). The detector reads
//     prior + current state from host_rule_state and the transactions
//     for this scan_id. It does not write to either table.
//
//   - No baselines table. The Python-era baselines table is explicitly
//     dropped — the prior host_rule_state aggregate IS the baseline.
//     Spec C-07 / AC-12 source-inspects to enforce this.
//
//   - Percentage-point math. A compliance score drop from 80% to 70%
//     is a 10pp delta — NOT a 12.5pp delta (which would be the
//     percent-of-percent miscalculation). Spec C-03.
//
//   - Classify is a pure function. Given (prior_score, current_score,
//     thresholds), it returns one of four Kind values
//     deterministically. No I/O, no side effects, trivially testable
//     without a database. Spec C-01.
//
//   - Audit on non-stable kinds only. Stable scans (delta below the
//     minor threshold) DO NOT emit compliance.drift.detected. Operators
//     see audit traffic only when something actually changed. Spec C-04.
//
//   - Fixed thresholds. The caller passes them, and cmd/openwatch passes
//     DefaultThresholds() (major=10pp, minor=5pp, improvement=5pp) for
//     both serve and worker. Operators cannot change them: there is no
//     setting. policy.AlertThresholds holds score bands, a different
//     quantity, and is never read here (spec C-05). ValidateThresholds
//     rejects any value outside (0, 100] or any configuration where
//     major < minor.
//
//   - Single read transaction. DetectForScan wraps the prior+current
//     score computations in one DB transaction so a concurrent writer
//     cannot produce a torn view. Spec C-06.
package drift
