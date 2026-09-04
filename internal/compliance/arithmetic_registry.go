package compliance

// The compliance-arithmetic registry: every site outside this package permitted
// to do arithmetic on a score field.
//
// Why a registry and not a rule. Recognizing that a division PRODUCES a
// compliance percentage needs data-flow analysis: `a / b` says nothing about
// what a and b mean. The enforceable half is syntactic, an arithmetic operator
// applied to something resolving to a score-field name, and that half over-
// reports. A count of failing rules divided by a page size is arithmetic on a
// score field and is not a compliance score.
//
// So the guard reports every such site and this list says which ones a reviewer
// agreed to and why. An unlisted site fails the build naming its file and line.
// The SQL path is an entry here, not an exception to the rule: internal/posture
// and internal/fleetrollup build the score expression from
// compliance.ScoreSQL, which is this package's own definition, and the
// conformance test proves the SQL and the Go answers agree.
//
// Spec: system-compliance-scoring C-14, AC-31.

// ArithmeticSite is one permitted compliance-arithmetic site.
type ArithmeticSite struct {
	// File is slash-separated and relative to the module root.
	File string
	// Symbol is the function or component the expression sits in.
	Symbol string
	// Expr is the operand the scanner reports, so an entry authorizes ONE
	// expression rather than the whole file. A file-shaped entry would let the
	// next formula added to a file with an existing exemption inherit it.
	Expr string
	// Reason must be non-empty. A permitted site nobody justified is
	// indistinguishable from one nobody noticed.
	Reason string
}

// ArithmeticRegistry is the complete set. It is deliberately short: the whole
// point of moving the formula into this package was that these sites should
// not exist, so a growing list is a signal rather than a convenience.
var ArithmeticRegistry = []ArithmeticSite{
	{
		File:   "frontend/src/pages/HostDetailPage.tsx",
		Symbol: "diff",
		Expr:   "first.score_pct",
		Reason: "The trend DELTA between two days: latest.score_pct minus first.score_pct. " +
			"Both operands are server-computed scores and the result is a difference, not a " +
			"score, so there is no second formula here. It is guarded on both days sharing a " +
			"formula_status, because subtracting a legacy score from a current one is a " +
			"change of measurement rather than a change in posture.",
	},
	{
		File:   "frontend/src/pages/HostsListPage.tsx",
		Symbol: "passPct",
		Expr:   "host.passed",
		Reason: "A stacked-bar WIDTH: passed over total, as a CSS percentage of the rule " +
			"population. Not a compliance score, and deliberately over total rather than " +
			"over verdicts, because the bar shows the whole outcome mix including skipped " +
			"and errored rules. The score beside it is the server's score_pct, taken as sent.",
	},
	{
		File:   "frontend/src/pages/HostsListPage.tsx",
		Symbol: "failPct",
		Expr:   "host.failed",
		Reason: "The other half of the same stacked bar. It is listed separately rather than " +
			"covered by the entry above, because an entry that authorized the FILE would let " +
			"the next expression added here inherit the exemption.",
	},
	{
		File:   "frontend/src/pages/host-detail/ComplianceTab.tsx",
		Symbol: "executed",
		Expr:   "summary.passing",
		Reason: "executed = passing + failing, the legend's own row count. A sum of two " +
			"counts is not a percentage, and the panel's score comes from the server's " +
			"score_pct.",
	},
}
