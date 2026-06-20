package kensa

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// KensaModuleVersion is the version pin recorded in the spec's context
// block. AC-10 source-inspects to verify this matches the corresponding
// entry in app/go.mod.
const KensaModuleVersion = "v0.5.2"

// Sentinel errors returned by Executor.Run. Tests use errors.Is for
// classification; the audit emission path maps each to a typed
// detail.reason on scan.failed (closed enum per AC-06).
var (
	// ErrHostBusy is returned by the SECOND Executor.Run call for the
	// same hostID while the first is still in flight. Spec AC-03.
	ErrHostBusy = errors.New("kensa: host scan in flight (concurrency guard)")

	// ErrNoCredential is returned when the host has no credential in
	// the credential store. Spec AC-09.
	ErrNoCredential = errors.New("kensa: host has no credential")

	// ErrCredentialDecryption wraps a failure in internal/credential
	// (corrupt ciphertext, wrong DEK). Spec AC-15.
	ErrCredentialDecryption = errors.New("kensa: credential decryption failed")

	// ErrHostKeyUnknown is returned when the SSH host-key policy is
	// require_known and the target's key is not in known_hosts. The
	// SSH dial fails BEFORE any authentication attempt. Spec AC-13.
	ErrHostKeyUnknown = errors.New("kensa: host key not in known_hosts")

	// ErrEvidenceOversize is returned when a Kensa rule result's
	// evidence blob exceeds the per-rule 10 MB cap. The scan transitions
	// to failed. Spec AC-14.
	ErrEvidenceOversize = errors.New("kensa: rule evidence exceeds 10 MB cap")

	// ErrKensaInternal wraps any Kensa-side failure not classified above
	// (framework unsupported, planner error, transaction abort).
	// Spec AC-06.
	ErrKensaInternal = errors.New("kensa: Kensa-side execution failure")
)

// FailureReason is the typed detail.reason enum on scan.failed audit
// events. Spec C-05 / AC-06 require a closed enum.
type FailureReason string

const (
	ReasonHostKeyUnknown             FailureReason = "host_key_unknown"
	ReasonCredentialDecryptionFailed FailureReason = "credential_decryption_failed" //nolint:gosec // typed reason enum value, not a credential
	ReasonEvidenceOversize           FailureReason = "evidence_oversize"
	ReasonKensaError                 FailureReason = "kensa_error"
	ReasonHostBusy                   FailureReason = "host_busy"
	ReasonTimeout                    FailureReason = "timeout"
)

// ResultStatus classifies each rule's outcome inside a Result.
type ResultStatus string

const (
	StatusPass    ResultStatus = "pass"
	StatusFail    ResultStatus = "fail"
	StatusSkipped ResultStatus = "skipped"
	StatusError   ResultStatus = "error"
)

// MaxEvidenceBytes is the per-rule evidence cap. Spec C-10 / AC-14.
// A target host returning a larger evidence blob causes the entire
// scan to transition to failed with ReasonEvidenceOversize.
const MaxEvidenceBytes = 10 * 1024 * 1024 // 10 MiB

// Result is what Executor.Run returns on success. It mirrors the
// Kensa-side ScanResult but flattens transactions into rule outcomes
// suitable for the transaction log writer (B.1c).
//
// v2.0.0 breaking change: FrameworkID is removed. A scan covers the
// full rule corpus applicable to the host; per-rule framework
// metadata lives on RuleOutcome.FrameworkRefs.
type Result struct {
	HostID        uuid.UUID
	Outcomes      []RuleOutcome
	StartedAt     time.Time
	CompletedAt   time.Time
	PolicyVersion string // snapshotted from the job payload
}

// RuleOutcome is one rule's outcome inside a Result.
type RuleOutcome struct {
	RuleID   string
	Status   ResultStatus
	Severity string
	Evidence []byte // raw evidence bytes; capped at MaxEvidenceBytes
	// FrameworkRefs maps framework_id -> control ids. Multi-valued
	// because one rule can satisfy several controls within the SAME
	// framework (e.g. ssh-disable-root-login -> three NIST 800-53
	// controls). Spec system-kensa-executor v2.1.0 C-14.
	FrameworkRefs map[string][]string // e.g. "nist_800_53_r5": ["AC-6(2)", "AC-17(2)"]
	SkipReason    string              // populated when Status == StatusSkipped
}
