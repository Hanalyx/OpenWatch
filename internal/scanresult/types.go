// Package scanresult persists and reads durable, point-in-time per-scan
// compliance results plus content-addressed evidence. It is the audit
// memory the write-on-change transaction log deliberately discards: where
// transactionlog keeps only the CURRENT state (host_rule_state) and the
// state CHANGES (transactions), this package keeps EVERY rule's verdict
// and evidence for EVERY scan, so a historical scan stays fully browsable
// and OSCAL-exportable for an audit window.
//
// The Writer is wired alongside transactionlog.Writer in the scan worker
// (never instead of it). The Reader backs the /api/v1/scans surface
// (scan:read). Evidence is deduped by content hash, so an unchanged
// passing rule across many scans stores its proof once.
//
// Spec: system-scan-results-store v1.0.0.
package scanresult

import (
	"errors"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/transactionlog"
)

// MaxEvidenceBytes is the per-rule evidence cap. It MUST equal
// transactionlog.MaxEvidenceBytes: the worker hands the SAME evidence
// bytes to both writers, so a blob one writer accepts and the other
// rejects would fail this writer forever on the transient-retry path
// (the scan keeps "succeeding" then failing to durably record). Aliasing
// the constant makes the two caps impossible to drift apart.
const MaxEvidenceBytes = transactionlog.MaxEvidenceBytes

// Status classifies a rule's outcome. Stored as TEXT with a CHECK
// constraint on scan_results.status. Mirrors transactionlog.Status.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

// Result is one rule's outcome from a Kensa scan, ready to be persisted
// by Writer.Persist. The shape mirrors transactionlog.Result so the
// worker can convert from the same kensa.RuleOutcome set, but the type
// identity is distinct to keep the package boundary explicit.
type Result struct {
	RuleID        string
	Status        Status
	Severity      string              // "critical" | "high" | "medium" | "low" | ""
	Evidence      []byte              // raw evidence JSON; size-capped at MaxEvidenceBytes
	FrameworkRefs map[string][]string // framework_id -> control ids
	SkipReason    string              // populated when Status == StatusSkipped
}

// PersistBatch is the (scan_id, host_id, results) bundle Writer.Persist
// records atomically. One PersistBatch == one DB transaction.
type PersistBatch struct {
	ScanID  uuid.UUID
	HostID  uuid.UUID
	Results []Result
}

// Sentinel errors. Tests classify with errors.Is.
var (
	// ErrEvidenceOversize wraps a per-rule evidence blob exceeding
	// MaxEvidenceBytes. Rejected before any INSERT (atomic batch).
	ErrEvidenceOversize = errors.New("scanresult: rule evidence exceeds 256 KB cap")

	// ErrInvalidStatus is returned when a Result.Status is not one of
	// the known Status values.
	ErrInvalidStatus = errors.New("scanresult: invalid status")
)
