package transactionlog

import (
	"errors"

	"github.com/google/uuid"
)

// MaxEvidenceBytes is the per-rule evidence cap enforced at writer.Apply
// time. Spec C-10: 256 KB. Oversized evidence is rejected before INSERT
// with a typed error AND nothing is persisted from that Apply batch
// (atomicity per C-01).
const MaxEvidenceBytes = 256 * 1024 // 256 KiB

// Status classifies a rule's outcome. Stored as TEXT with a CHECK
// constraint in both host_rule_state and transactions tables.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

// ChangeKind classifies why a transactions row was written.
// Stored as TEXT with a CHECK constraint on transactions.change_kind.
type ChangeKind string

const (
	// ChangeFirstSeen — no prior host_rule_state row existed; this is
	// the first time we've checked this (host, rule) pair.
	ChangeFirstSeen ChangeKind = "first_seen"

	// ChangeStateChanged — prior_status != current_status. The most
	// common change kind.
	ChangeStateChanged ChangeKind = "state_changed"

	// ChangeSeverityChanged — same status but the rule's severity
	// reclassification changed (e.g., a CIS rule moved from medium to
	// high). Rare but worth recording for audit traceability.
	ChangeSeverityChanged ChangeKind = "severity_changed"
)

// FailureReason classifies a writer.Apply failure for the
// writer.apply.failed audit event's detail.reason enum. Spec AC-15.
type FailureReason string

const (
	ReasonFKViolation       FailureReason = "fk_violation"
	ReasonDeadlock          FailureReason = "deadlock"
	ReasonEvidenceOversize  FailureReason = "evidence_oversize"
	ReasonSQLCError         FailureReason = "sqlc_error"
	ReasonUnknown           FailureReason = "unknown"
)

// Result is one rule's outcome from a Kensa scan, ready to be persisted
// by writer.Apply.
type Result struct {
	RuleID        string
	Status        Status
	Severity      string            // "critical" | "high" | "medium" | "low" | ""
	Evidence      []byte            // raw evidence JSON; size-capped at MaxEvidenceBytes
	FrameworkRefs map[string]string // e.g. {"cis_rhel9_v2": "5.1.12"}
	SkipReason    string            // populated when Status == StatusSkipped
}

// ApplyBatch is the bundle of (scan_id, host_id, results) that
// writer.Apply processes atomically. One ApplyBatch == one DB transaction.
type ApplyBatch struct {
	ScanID  uuid.UUID
	HostID  uuid.UUID
	Results []Result
}

// Sentinel errors. Tests use errors.Is for classification; the audit
// emission path maps each to a typed detail.reason on writer.apply.failed.
var (
	// ErrEvidenceOversize wraps a per-rule evidence blob exceeding
	// MaxEvidenceBytes. Spec AC-14. The error message includes the
	// offending rule_id so the audit can name it.
	ErrEvidenceOversize = errors.New("transactionlog: rule evidence exceeds 256 KB cap")

	// ErrInvalidStatus is returned when a Result.Status is not one of
	// the known Status values.
	ErrInvalidStatus = errors.New("transactionlog: invalid status")

	// ErrInvalidEvidence is returned when a Result.Evidence cannot be
	// parsed as a JSON object. Spec AC-08: evidence MUST conform to
	// the KensaEvidence shape (a JSON object, at minimum).
	// A future commit adds the full schema check against the
	// KensaEvidence OpenAPI schema once that schema lands.
	ErrInvalidEvidence = errors.New("transactionlog: evidence is not a JSON object")
)
