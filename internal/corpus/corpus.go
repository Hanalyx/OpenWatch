// Package corpus defines which host_rule_state rows still count.
//
// host_rule_state holds one row per (host, rule) and is only ever UPSERTed,
// never pruned. When a rule leaves the scanned corpus its last verdict stays
// in the table forever. A rule that was failing when it left stays failing
// forever: no scan clears it, because it is never evaluated again, and no
// remediation fixes it, because the scan engine has no handler for a rule it
// no longer ships. Scoring against the raw table grades a host on rules it is
// no longer measured against.
//
// A host's CURRENT corpus is the set of host_rule_state rows whose
// last_scan_id is the id of that host's most recent completed scan_runs row.
//
// # The definition is a view, not a helper in this package
//
// That definition lives in exactly one place, the SQL view
// host_rule_state_current (migration 0060). There is deliberately no Go
// function here that builds the predicate. A helper pasting the same SQL into
// every caller leaves the twelfth read site free to skip it, and no guard can
// tell a missing call from a hand-rolled equivalent. With a view, the rule is
// mechanical: no current-score read may name the bare host_rule_state table.
// Registry below records the only reads allowed to, and guard_test enforces
// it against the whole tree.
//
// Rows outside the current corpus are never deleted. They record what a host
// used to be measured against, which an assessor may ask for. Only the reads
// are scoped, which is why internal/retention pins this table at StateNever.
package corpus

// AtScanSQL returns a SQL boolean fragment scoping host_rule_state to the
// corpus of ONE NAMED SCAN. qualifier is the caller's table alias, or the
// table name where the query does not alias it. placeholder is the caller's
// own bind marker for the scan id (for example "$2"), so placeholder
// numbering stays with the caller.
//
// This is the second legal way to scope a read, and it exists for a caller
// that already knows which scan it is analyzing. drift.DetectForScan is the
// one such reader: it takes the scan id as an argument and reports on that
// scan.
//
// # Why such a caller MUST NOT use the view
//
// The scan worker's order is writer.Apply, then scanResults.Persist, then
// scanruns.MarkCompleted. Inside that window host_rule_state already carries
// the NEW scan id on every rule the scan evaluated, while the latest
// COMPLETED run is still the PREVIOUS one. So the rows matching the view
// there are exactly the rules the new scan did NOT evaluate.
//
// A read using the view in that window does not get a slightly stale answer.
// It gets the retired set and nothing else, and reports it as the host's
// current state. Nothing in the shape of the code announces this, which is
// why the rule is written here: the next person wiring a post-scan hook will
// reach for the obvious helper and get an answer that looks plausible.
//
// Any read invoked between Apply and MarkCompleted MUST scope this way.
// Spec: system-current-corpus C-03, C-04.
func AtScanSQL(qualifier, placeholder string) string {
	return qualifier + ".last_scan_id = " + placeholder
}
