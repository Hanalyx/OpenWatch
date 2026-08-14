package corpus

// The exception registry: every function permitted to name the bare
// host_rule_state table in SQL.
//
// Completeness here is structural rather than remembered. A current-score
// read either uses the host_rule_state_current view, which needs no entry, or
// it is an exception a reviewer agreed to and wrote down. There is
// deliberately no state meaning "not looked at yet", because that is how the
// twelfth read site goes missing.
//
// guard_test walks every non-test Go source, parses it, and checks string
// literals naming the bare table against this list. It runs BOTH ways: a
// literal outside a registered function is reported, and so is an entry whose
// function no longer holds such a literal, so a stale exemption cannot
// outlive the code it excused.
//
// Spec: system-current-corpus C-05.

// State says WHY a function may read the bare table. The two values are not
// interchangeable and the distinction is the point: raw means the read needs
// every row regardless of corpus, scan_scoped means it is scoped, just to a
// named scan rather than to the latest completed one.
type State string

const (
	// StateRaw is a read that must see rows regardless of corpus
	// membership. Only the write path qualifies.
	StateRaw State = "raw"

	// StateScanScoped is a read scoped to one named scan, via AtScanSQL.
	StateScanScoped State = "scan_scoped"
)

// Entry is one permitted reader of the bare table.
type Entry struct {
	Package string
	// File is slash-separated and relative to the module root.
	File string
	// Function is "Name" for a plain function, "Type.Name" for a method.
	Function string
	State    State
	// Reason must be non-empty. An exemption without a stated reason is
	// indistinguishable from an oversight.
	Reason string
}

// Registry is the complete set of exceptions. Three entries, and a fourth
// should be hard to justify.
var Registry = []Entry{
	{
		Package:  "transactionlog",
		File:     "internal/transactionlog/writer.go",
		Function: "Writer.Apply",
		State:    StateRaw,
		Reason: "The WRITE path decides what the corpus IS, so it cannot be scoped by it. " +
			"Apply reads the prior row to choose change_kind, then UPSERTs; both statements " +
			"name the bare table and both must. A scoped prior-state read would find no row " +
			"for a rule outside the current corpus, call the result first_seen, and append a " +
			"false transactions row on every scan of every rule one run skipped.",
	},
	{
		Package:  "drift",
		File:     "internal/drift/service.go",
		Function: "Service.readCurrentCounts",
		State:    StateScanScoped,
		Reason: "Scoped by AtScanSQL to the scan DetectForScan was handed. It runs in the " +
			"window between writer.Apply and scanruns.MarkCompleted, where the view resolves " +
			"to the PREVIOUS run and would return exactly the rules this scan did not " +
			"evaluate. Naming the scan is exact and does not depend on wiring order.",
	},
	{
		Package:  "corpustest",
		File:     "internal/db/corpustest/corpustest.go",
		Function: "SeedRules",
		State:    StateRaw,
		Reason: "A WRITE, and the only one outside transactionlog. It is the C-14 seed helper, " +
			"which must be a package because test files are not importable, so the guard sees " +
			"it as production source. It INSERTs the rows whose last_scan_id decides corpus " +
			"membership, so it cannot read through the view that membership defines.",
	},
	{
		Package:  "drift",
		File:     "internal/drift/service.go",
		Function: "Service.reconstructPriorCounts",
		State:    StateScanScoped,
		Reason: "Same scan, same AtScanSQL scoping, for the denominator its first_seen count " +
			"is compared against. Counting a scan-scoped numerator against an all-time " +
			"denominator would report a prior baseline on a genuine first scan whenever the " +
			"host carried retired rows.",
	},
}
