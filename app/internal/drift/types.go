package drift

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// DriftKind classifies a per-host score delta. Closed enum per spec
// AC-13. Maps 1:1 to compliance.drift.detected detail.drift_type values
// (where "stable" is not emitted — see spec C-04).
type DriftKind string

const (
	DriftStable         DriftKind = "stable"
	DriftMinorWorsening DriftKind = "minor_worsening"
	DriftMajorWorsening DriftKind = "major_worsening"
	DriftImprovement    DriftKind = "improvement"
)

// AllDriftKinds is the closed set, in registration order. Used by
// AC-13's reflection-style check.
var AllDriftKinds = []DriftKind{
	DriftStable,
	DriftMinorWorsening,
	DriftMajorWorsening,
	DriftImprovement,
}

// DriftTypeForAudit converts a DriftKind to the detail.drift_type
// string the compliance.drift.detected event uses ({major, minor,
// improvement}). Returns "" for DriftStable (which doesn't emit).
func DriftTypeForAudit(k DriftKind) string {
	switch k {
	case DriftMajorWorsening:
		return "major"
	case DriftMinorWorsening:
		return "minor"
	case DriftImprovement:
		return "improvement"
	}
	return ""
}

// Thresholds defines the percentage-point boundaries between drift
// kinds. All values are percentage points (pp), not percent-of-percent.
// Spec C-05 / AC-07: validated via ValidateThresholds.
type Thresholds struct {
	// MajorWorseningPP is the score-drop threshold (pp) for the major
	// classification. A drop ≥ this value is major worsening.
	MajorWorseningPP float64

	// MinorWorseningPP is the score-drop threshold (pp) for minor.
	// A drop ≥ this AND below major is minor worsening.
	MinorWorseningPP float64

	// ImprovementPP is the score-gain threshold (pp) for improvement.
	// A gain ≥ this value is classified as improvement.
	ImprovementPP float64
}

// DefaultThresholds returns the spec-defined defaults. Spec C-05.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MajorWorseningPP: 10,
		MinorWorseningPP: 5,
		ImprovementPP:    5,
	}
}

// ErrInvalidThresholds is returned by ValidateThresholds when any
// value falls outside (0, 100] or major < minor.
var ErrInvalidThresholds = errors.New("drift: invalid thresholds")

// ValidateThresholds checks that every value is in (0, 100] and that
// MajorWorseningPP >= MinorWorseningPP. Spec AC-07.
func ValidateThresholds(t Thresholds) error {
	for name, v := range map[string]float64{
		"MajorWorseningPP": t.MajorWorseningPP,
		"MinorWorseningPP": t.MinorWorseningPP,
		"ImprovementPP":    t.ImprovementPP,
	} {
		if v <= 0 || v > 100 {
			return fmt.Errorf("%w: %s = %v, want (0, 100]", ErrInvalidThresholds, name, v)
		}
	}
	if t.MajorWorseningPP < t.MinorWorseningPP {
		return fmt.Errorf("%w: MajorWorseningPP (%v) must be >= MinorWorseningPP (%v)",
			ErrInvalidThresholds, t.MajorWorseningPP, t.MinorWorseningPP)
	}
	return nil
}

// DriftReport is what DetectForScan returns. Carries the classified
// kind, the raw scores + delta, and per-severity transition counts so
// the alert router (B.3) can route by severity.
type DriftReport struct {
	HostID       uuid.UUID
	ScanID       uuid.UUID
	Kind         DriftKind
	PriorScore   float64
	CurrentScore float64
	ScoreDelta   float64 // current - prior; negative when worsening

	// HasPriorBaseline is false on the first-ever scan against this
	// host. Kind is forced to DriftStable in that case (no baseline to
	// drift from). Spec AC-08.
	HasPriorBaseline bool

	// Per-severity transition counts. Spec C-08 / AC-09.
	CriticalBecameFailing int
	HighBecameFailing     int
	MediumBecameFailing   int
	LowBecameFailing      int

	CriticalBecamePassing int
	HighBecamePassing     int
	MediumBecamePassing   int
	LowBecamePassing      int
}
