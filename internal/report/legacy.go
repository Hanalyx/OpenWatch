package report

import "encoding/json"

// The frozen pre-2026-09-03 content shapes.
//
// # Why these exist
//
// content is a JSONB column, and JSONB does not preserve bytes: it reorders
// keys by length then bytewise and rewrites the separators. So the content
// read back is NOT the content that was hashed and signed, and
// sha256(rep.Content) has never equaled content_sha256.
//
// The canonical face is therefore RECONSTRUCTED by marshaling the decoded
// content through the Go struct, which reproduces Go's field order and
// separators. That works exactly as long as the struct shape is frozen.
// Changing ExecutiveContent to carry score_pct and provenance changes the
// bytes it produces, so a legacy artifact re-marshaled through the CURRENT
// struct would gain "score_pct":null, lose its null compliance_pct, and
// reorder its fields. Its hash would move and its signature would stop
// verifying: exactly what AC-34 forbids.
//
// Decoding a legacy artifact through the shape it was written with is what
// keeps its bytes, its hash and its signature unchanged. These types are
// frozen. Nothing may be added to them, reordered in them, or removed from
// them, and the golden-bytes test is what enforces that.
type legacyExecutiveContent struct {
	CompliancePct   *int             `json:"compliance_pct"`
	HostCount       int              `json:"host_count"`
	PassingRules    int              `json:"passing_rules"`
	FailingRules    int              `json:"failing_rules"`
	CriticalIssues  int              `json:"critical_issues"`
	TopFailingRules []TopFailingRule `json:"top_failing_rules"`
	Coverage        Coverage         `json:"coverage"`
}

// legacyAttestationRollup is the frozen rollup shape. See
// legacyExecutiveContent.
type legacyAttestationRollup struct {
	CompliancePct *int             `json:"compliance_pct"`
	TotalChecks   int              `json:"total_checks"`
	Passing       int              `json:"passing"`
	Failing       int              `json:"failing"`
	Skipped       int              `json:"skipped"`
	Errored       int              `json:"errored"`
	TopFailing    []TopFailingRule `json:"top_failing"`
}

// legacyAttestationContent is the frozen attestation shape.
type legacyAttestationContent struct {
	Framework     string                  `json:"framework"`
	HostsTotal    int                     `json:"hosts_total"`
	HostsAttested int                     `json:"hosts_attested"`
	Attested      []AttestedHost          `json:"attested"`
	Rollup        legacyAttestationRollup `json:"rollup"`
}

// isLegacyArtifact reports whether stored content predates the formula
// change, which is true exactly when it carries no artifact_class.
//
// The absence is the identity. Nothing backfills an artifact_class onto a
// stored row, so an artifact without one was signed before the change and
// stays that way for as long as it exists. Reading the field is deliberately
// the ONLY test: guessing from which score field happens to be present would
// make a malformed artifact look like whichever generation it resembled.
func isLegacyArtifact(content []byte) bool {
	var probe struct {
		Provenance *struct {
			ArtifactClass string `json:"artifact_class"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(content, &probe); err != nil {
		return false
	}
	return probe.Provenance == nil || probe.Provenance.ArtifactClass == ""
}

// ErrAmbiguousScore reports an artifact carrying both score fields.
//
// A current artifact must expose ONE authoritative number. Carrying the
// pooled legacy percent beside the equal-host mean would publish two
// plausible scores over the same population and leave every reader to pick,
// which is the ambiguity the removal of passing_fraction was meant to end.
type ErrAmbiguousScore struct{ Kind string }

func (e ErrAmbiguousScore) Error() string {
	return "report: " + e.Kind + " artifact carries both compliance_pct and an artifact_class; " +
		"a current artifact must carry exactly one score"
}

// checkScoreFields rejects a current artifact that also carries the legacy
// field.
func checkScoreFields(kind string, content []byte) error {
	if isLegacyArtifact(content) {
		return nil
	}
	var probe struct {
		CompliancePct *int `json:"compliance_pct"`
	}
	if err := json.Unmarshal(content, &probe); err != nil {
		return nil
	}
	if probe.CompliancePct != nil {
		return ErrAmbiguousScore{Kind: kind}
	}
	return nil
}
