package report

import (
	"encoding/json"
	"strconv"

	"github.com/Hanalyx/openwatch/internal/compliance"
)

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

// ErrInvalidProvenance reports provenance that is present but unusable.
//
// A present-but-empty envelope is not a legacy artifact. Treating it as one
// let "provenance": {} and "provenance": null read as "signed before the
// formula changed", which is a claim about history that the bytes do not
// support. Absence means legacy; anything else present must be valid.
type ErrInvalidProvenance struct{ Reason string }

func (e ErrInvalidProvenance) Error() string {
	return "report: invalid provenance: " + e.Reason
}

// artifactGeneration says which contract a stored artifact was written under.
type artifactGeneration int

const (
	// generationLegacy is an artifact with NO provenance key at all.
	generationLegacy artifactGeneration = iota
	// generationCurrent is an artifact carrying a valid artifact_class.
	generationCurrent
)

// expectedClassFor is the artifact class each report kind MUST declare.
//
// C-16: executive and attestation compute a fleet score and are
// score-bearing; exception and remediation aggregate no scan set and are read
// models. Accepting either globally known value for every kind let an
// artifact deny the class its own kind requires, so an executive could
// declare read_model and drop the whole envelope while still parsing.
var expectedClassFor = map[Kind]compliance.ArtifactClass{
	KindExecutive:   compliance.ScoreBearing,
	KindAttestation: compliance.ScoreBearing,
	KindException:   compliance.ReadModel,
	KindRemediation: compliance.ReadModel,
}

// generationOf classifies stored content, rejecting the ambiguous middle.
//
// Only ACTUAL ABSENCE of the provenance key means legacy. A null provenance,
// an empty object, or an empty or unknown artifact_class are all
// present-but-invalid: something wrote a provenance field and failed to fill
// it, and reading that as "legacy" would silently accept a broken artifact as
// a historical one and render whatever score it happened to carry.
func generationOf(kind string, content []byte) (artifactGeneration, error) {
	// Raw key inspection, at the level this KIND stores provenance: the key's
	// presence is the question, and unmarshaling into a pointer cannot tell an
	// absent key from an explicit null. An attestation nests its envelope
	// under rollup, so looking only at the top level read every attestation as
	// legacy.
	host, err := scoreFieldHost(kind, content)
	if err != nil {
		return generationLegacy, err
	}
	raw, present := host["provenance"]
	if !present {
		return generationLegacy, nil
	}
	if string(raw) == "null" {
		return generationCurrent, ErrInvalidProvenance{
			"provenance is present and null; absence means legacy, and a null " +
				"envelope claims a history the bytes do not support"}
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return generationCurrent, ErrInvalidProvenance{"provenance is not an object"}
	}
	classRaw, hasClass := env["artifact_class"]
	if !hasClass {
		return generationCurrent, ErrInvalidProvenance{"provenance carries no artifact_class"}
	}
	var class string
	if err := json.Unmarshal(classRaw, &class); err != nil {
		return generationCurrent, ErrInvalidProvenance{"artifact_class is not a string"}
	}
	want, known := expectedClassFor[Kind(kind)]
	if !known {
		return generationCurrent, ErrInvalidProvenance{
			"kind " + strconv.Quote(kind) + " has no declared artifact class"}
	}
	if class != string(want) {
		return generationCurrent, ErrInvalidProvenance{
			"artifact_class " + strconv.Quote(class) + " contradicts kind " +
				strconv.Quote(kind) + ", which is " + string(want)}
	}
	return generationCurrent, nil
}

// isLegacyArtifact reports whether stored content predates the formula
// change, which is true exactly when it carries NO provenance key.
//
// The absence is the identity. Nothing backfills provenance onto a stored
// row, so an artifact without it was signed before the change and stays that
// way for as long as it exists. A present-but-invalid envelope is not legacy
// and is rejected by generationOf instead of being quietly accepted here.
func isLegacyArtifact(kind string, content []byte) bool {
	gen, err := generationOf(kind, content)
	return err == nil && gen == generationLegacy
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

// scoreFieldHost returns the object a kind's score fields live in.
//
// An executive artifact carries them at the top level; an attestation carries
// them under rollup. The previous check looked at the top level for both, so
// a hybrid attestation carrying rollup.compliance_pct beside a valid
// artifact_class was never detected.
func scoreFieldHost(kind string, content []byte) (map[string]json.RawMessage, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(content, &top); err != nil {
		return nil, ErrInvalidProvenance{"content is not a JSON object"}
	}
	if Kind(kind) != KindAttestation {
		return top, nil
	}
	raw, ok := top["rollup"]
	if !ok {
		return map[string]json.RawMessage{}, nil
	}
	var rollup map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rollup); err != nil {
		return nil, ErrInvalidProvenance{"attestation rollup is not an object"}
	}
	return rollup, nil
}

// checkScoreFields rejects a current artifact that also carries the legacy
// field, and any artifact whose provenance is present but unusable.
//
// It tests KEY PRESENCE, not the decoded value. Decoding into a pointer made
// "compliance_pct": null indistinguishable from an absent key, so a current
// artifact could carry the forbidden field as an explicit null and pass.
func checkScoreFields(kind string, content []byte) error {
	gen, err := generationOf(kind, content)
	if err != nil {
		return err
	}
	if gen == generationLegacy {
		return nil
	}
	host, err := scoreFieldHost(kind, content)
	if err != nil {
		return err
	}
	if _, present := host["compliance_pct"]; present {
		return ErrAmbiguousScore{Kind: kind}
	}
	return nil
}
