// Package policy is the Stage-0 policies-as-data framework. Signed YAML
// policy files load into an atomic.Pointer[State] cache; evaluators are
// per-type and emit policy.applied audit events on every call.
//
// Stage 0 ships the generic loader + one typed evaluator (alert_thresholds)
// as the demo. Other types (exceptions, approvals, schedules, remediation)
// land alongside their Stage-2 consumers.
//
// Spec: app/specs/system/policy.spec.yaml.
package policy

import (
	"errors"
	"time"
)

// Type is one of the five recognized policy types.
type Type string

const (
	TypeExceptions      Type = "exceptions"
	TypeApprovals       Type = "approvals"
	TypeSchedules       Type = "schedules"
	TypeAlertThresholds Type = "alert_thresholds"
	TypeRemediation     Type = "remediation"
)

// Outcome is the result of evaluating a policy. Allow / deny are
// universal; type-specific outcomes (e.g., "warning", "critical" for
// alert_thresholds) live alongside as Outcome strings.
type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeDeny  Outcome = "deny"
	OutcomeDefer Outcome = "defer"
)

// LoadOutcome is what the loader reports back to admin endpoints after
// attempting LoadFile.
type LoadOutcome string

const (
	LoadLoaded    LoadOutcome = "loaded"
	LoadUnchanged LoadOutcome = "unchanged"
	LoadInvalid   LoadOutcome = "invalid"
)

// Decision is what every Evaluate(...) returns. The fields are stable
// across versions; type-specific context goes into Detail.
type Decision struct {
	Outcome       Outcome
	PolicyType    Type
	PolicyVersion string
	Reason        string
	HumanMessage  string
	Detail        map[string]any
	AppliedAt     time.Time
}

// State is the in-memory cache of every active policy. Stored under an
// atomic.Pointer for lock-free reads on the hot path.
type State struct {
	// Versions maps each policy type to its currently-active version.
	Versions map[Type]string

	// Sources maps each type to the SHA-256 hex of the raw file bytes
	// that produced this state. Used for "is the disk file changed?"
	// comparisons in reload.
	Sources map[Type]string

	// SignedBy maps each type to the signer identity (from envelope
	// metadata). "default" for built-in policies.
	SignedBy map[Type]string

	// LoadedAt is when this state snapshot was installed.
	LoadedAt time.Time

	// AlertThresholds is the typed payload for the only Stage-0
	// evaluator. Other typed payloads land per their Stage-2 consumer.
	AlertThresholds AlertThresholds

	// Warnings captures non-fatal advisories from the last load
	// (e.g., "unsigned_dev_mode").
	Warnings []string
}

// AlertThresholds defines compliance-score severity bands. score in
// [0,100]; bands MUST cover the range without gaps.
type AlertThresholds struct {
	CriticalBelow int // score < CriticalBelow → critical
	HighBelow     int // score < HighBelow → high
	MediumBelow   int // score < MediumBelow → medium
	// Anything >= MediumBelow is "ok".
}

// AlertInput is what the alert_thresholds evaluator consumes.
type AlertInput struct {
	Score int // 0..100
}

// Envelope is the on-disk YAML shape (Stage-0 simplified; Section 4.1
// of policies_as_data.md describes the full envelope).
type Envelope struct {
	PolicyType Type   `yaml:"policy_type"`
	Version    string `yaml:"version"`
	Metadata   struct {
		Description string `yaml:"description"`
		SignedBy    string `yaml:"signed_by"`
		SignedAt    string `yaml:"signed_at"`
	} `yaml:"metadata"`
	Rules     map[string]any `yaml:"rules"`
	Signature struct {
		Algorithm string `yaml:"algorithm"`
		KeyID     string `yaml:"key_id"`
		Value     string `yaml:"value"`
	} `yaml:"signature"`
}

// LoaderError surfaces a structured failure from LoadFile. Errors is a
// flat list so the policy.invalid audit event can include all problems
// in one envelope.
type LoaderError struct {
	Type   Type
	Errors []string
}

func (e *LoaderError) Error() string {
	if len(e.Errors) == 0 {
		return "policy: invalid"
	}
	return "policy: " + e.Errors[0]
}

// ErrUnsignedInProduction is returned when a policy file lacks a
// signature and OPENWATCH_DEV_MODE is not set.
var ErrUnsignedInProduction = errors.New("policy: unsigned policy rejected (set OPENWATCH_DEV_MODE=true for dev)")
