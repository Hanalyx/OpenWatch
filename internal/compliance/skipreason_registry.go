package compliance

// SkipReasonUse says what a reader does with a skip reason it has read.
type SkipReasonUse string

const (
	// UseDisplay shows the text to a person, directly or over the wire.
	UseDisplay SkipReasonUse = "display"
	// UsePersist carries the text between stores without interpreting it.
	UsePersist SkipReasonUse = "persist"
)

// SkipReasonReader records one authorized reader of a rule's skip reason.
//
// The identity is File plus Symbol, and it is the DETECTOR that decides
// both: skipreason_guard_test.go parses the tree, extracts the enclosing
// declaration for every mention, and reconciles the result against this
// list in both directions. A file-shaped identity would let a new reader
// slip into an already-listed file unnoticed, so there is no file-level
// entry here and no way to write one.
//
// FeedsScore must be false for every entry. A skip reason is free text a
// rule author wrote. Compliance scoring counts outcomes and never reads
// the prose behind one, so a reader that fed this text into a score would
// be making a verdict out of an explanation.
type SkipReasonReader struct {
	Package    string
	File       string
	Symbol     string
	Use        SkipReasonUse
	FeedsScore bool
	Reason     string
}

// SkipReasonRegistry is the closed set of authorized readers.
//
// Every entry below was produced by running the detector, not by hand.
// An earlier hand-written version of this list had all twelve of its
// symbols wrong, and the both-direction check is what proved it.
var SkipReasonRegistry = []SkipReasonReader{
	{
		Package: "internal/kensa", File: "internal/kensa/scanfunc.go", Symbol: "mapOutcomes",
		Use: UsePersist, FeedsScore: false,
		Reason: "The single point where a skip reason ENTERS OpenWatch. Kensa's " +
			"api.RuleOutcome has no skip field, so the executor's Detail text is " +
			"copied across only when the status is skipped. Nothing is parsed.",
	},
	{
		Package: "internal/kensa", File: "internal/kensa/types.go", Symbol: "RuleOutcome.SkipReason",
		Use: UsePersist, FeedsScore: false,
		Reason: "The field mapOutcomes writes. It is the in-memory carrier from the " +
			"scan engine boundary to the two durable stores.",
	},
	{
		Package: "internal/worker", File: "internal/worker/scan_worker.go", Symbol: "toScanResultResults",
		Use: UsePersist, FeedsScore: false,
		Reason: "Copies the reason into the durable per-scan store's value type. " +
			"A straight field assignment in a loop.",
	},
	{
		Package: "internal/worker", File: "internal/worker/scan_worker.go", Symbol: "toTransactionLogResults",
		Use: UsePersist, FeedsScore: false,
		Reason: "The mirror of toScanResultResults for the transaction log. Both " +
			"consume the same outcome slice, so both must carry the same text.",
	},
	{
		Package: "internal/scanresult", File: "internal/scanresult/types.go", Symbol: "Result.SkipReason",
		Use: UsePersist, FeedsScore: false,
		Reason: "The per-scan store's write-side field. Populated only when the " +
			"status is skipped.",
	},
	{
		Package: "internal/scanresult", File: "internal/scanresult/writer.go", Symbol: "Writer.Persist",
		Use: UsePersist, FeedsScore: false,
		Reason: "Writes the text to the per-scan result row, empty string becoming " +
			"NULL. The column is written and never read back by any scoring query.",
	},
	{
		Package: "internal/transactionlog", File: "internal/transactionlog/types.go", Symbol: "Result.SkipReason",
		Use: UsePersist, FeedsScore: false,
		Reason: "The transaction log's write-side field, the counterpart of the " +
			"per-scan store's Result.SkipReason.",
	},
	{
		Package: "internal/transactionlog", File: "internal/transactionlog/writer.go", Symbol: "Writer.Apply",
		Use: UsePersist, FeedsScore: false,
		Reason: "Inserts and upserts the text in the transaction log. The upsert " +
			"branch overwrites it from the excluded row so a rescan cannot leave a " +
			"stale explanation attached to a fresh outcome.",
	},
	{
		Package: "internal/scanresult", File: "internal/scanresult/reader.go", Symbol: "RuleResult.SkipReason",
		Use: UseDisplay, FeedsScore: false,
		Reason: "The read-side field for the rule list. COALESCEd to empty string " +
			"on read, so a caller cannot tell absent from blank. That is acceptable " +
			"here precisely because nothing computes from it.",
	},
	{
		Package: "internal/scanresult", File: "internal/scanresult/reader.go", Symbol: "RuleEvidenceDetail.SkipReason",
		Use: UseDisplay, FeedsScore: false,
		Reason: "The read-side field for the per-rule drill-down.",
	},
	{
		Package: "internal/scanresult", File: "internal/scanresult/reader.go", Symbol: "Reader.ScanResults",
		Use: UseDisplay, FeedsScore: false,
		Reason: "Selects the reason into RuleResult for the rule list. It is " +
			"returned, never counted.",
	},
	{
		Package: "internal/scanresult", File: "internal/scanresult/reader.go", Symbol: "Reader.RuleEvidence",
		Use: UseDisplay, FeedsScore: false,
		Reason: "Selects the reason into RuleEvidenceDetail for one rule's " +
			"drill-down.",
	},
	{
		Package: "internal/scanresult", File: "internal/scanresult/reader.go", Symbol: "Reader.ReconstructScan",
		Use: UseDisplay, FeedsScore: false,
		Reason: "Rebuilds the full rule set for the OSCAL export path. The mention " +
			"is in the SELECT list feeding RuleEvidenceDetail; the exporter's own " +
			"outcome type has no skip field, so the text reaches OSCAL as detail.",
	},
	{
		Package: "internal/server", File: "internal/server/scans_handlers.go", Symbol: "handlers.GetScanByID",
		Use: UseDisplay, FeedsScore: false,
		Reason: "Puts the reason on the wire for the rule list, as a pointer left " +
			"nil when the text is empty. The counts in the same response come from " +
			"outcome statuses and not from this field.",
	},
	{
		Package: "internal/server", File: "internal/server/scans_handlers.go", Symbol: "handlers.GetScanRuleEvidence",
		Use: UseDisplay, FeedsScore: false,
		Reason: "The drill-down counterpart of GetScanByID, with the same nil-when-" +
			"empty pointer treatment.",
	},
	{
		Package: "internal/server/api", File: "internal/server/api/server.gen.go", Symbol: "ScanRuleResult.SkipReason",
		Use: UseDisplay, FeedsScore: false,
		Reason: "GENERATED from api/openapi.yaml. The optional wire field on the " +
			"rule list item. Edit the spec, not this file.",
	},
	{
		Package: "internal/server/api", File: "internal/server/api/server.gen.go", Symbol: "ScanRuleEvidence.SkipReason",
		Use: UseDisplay, FeedsScore: false,
		Reason: "GENERATED from api/openapi.yaml. The optional wire field on the " +
			"evidence drill-down.",
	},
	{
		Package: "frontend/src/api", File: "frontend/src/api/schema.d.ts", Symbol: "framework_refs",
		Use: UseDisplay, FeedsScore: false,
		Reason: "GENERATED client types. The mention sits in a nested type literal " +
			"whose nearest named key is framework_refs, which is why the detector " +
			"reports that symbol rather than the enclosing schema name.",
	},
	{
		Package: "frontend/src/pages/scans", File: "frontend/src/pages/scans/ScanDetailPage.tsx", Symbol: "why",
		Use: UseDisplay, FeedsScore: false,
		Reason: "The only rendering reader. Falls back to the skip reason when a " +
			"rule has no catalog description, and puts the result in a text node.",
	},
}
