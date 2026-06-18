// Package remediation implements the free (AGPLv3 core) half of Phase 7
// remediation governance: an operator's intent to fix a failing rule on a
// host, with a request -> approve | reject lifecycle and a read-only
// projected-lift estimate.
//
// FREE-PATH INVARIANT (load-bearing): nothing in this package contacts a host
// or mutates host_rule_state / transactions. Request, Approve, and Reject are
// pure state transitions over remediation_requests; ProjectLift only reads
// host_rule_state. The act of mutating a host (dry-run / execute / rollback)
// is the OpenWatch+ licensed track, gated by the remediation_execution license
// feature, and is NOT implemented here.
//
// Separation of duties: the requester cannot review their own request
// (enforced here, on top of the distinct remediation:request vs
// remediation:approve RBAC permissions).
//
// Spec: api-remediation v1.0.0. Plan: docs/engineering/remediation_core_plan.md.
package remediation

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is the remediation request lifecycle state. The free path uses
// pending_approval -> approved | rejected; the remaining states are driven by
// the OpenWatch+ licensed execution track.
type Status string

const (
	StatusPendingApproval Status = "pending_approval"
	StatusApproved        Status = "approved"
	StatusRejected        Status = "rejected"
	StatusDryRunComplete  Status = "dry_run_complete"
	StatusExecuting       Status = "executing"
	StatusExecuted        Status = "executed"
	StatusRolledBack      Status = "rolled_back"
	StatusFailed          Status = "failed"
)

// ProjectedLift is the estimated per-framework compliance-score delta
// (percentage points) if the rule flips to pass. A nil field means that
// framework's data was unavailable for the host (best-effort projection).
type ProjectedLift struct {
	CIS  *float64
	STIG *float64
	NIST *float64
}

// Request is one remediation_requests row.
type Request struct {
	ID     uuid.UUID
	HostID uuid.UUID
	// HostName is populated by the list query via a join; the single-row
	// lifecycle ops leave it empty (the UI re-fetches the list after a mutation).
	HostName       string
	RuleID         string
	Status         Status
	RequestedBy    uuid.UUID
	ReviewedBy     *uuid.UUID
	ReviewNote     string
	ScanRunID      *uuid.UUID
	Mechanism      string
	RebootRequired bool
	Transactional  bool
	Projected      ProjectedLift
	RequestedAt    time.Time
	ReviewedAt     *time.Time
}

// Step is one remediation_transactions row (the per-step Kensa journal).
// Written by the execute path; empty until a request is executed.
type Step struct {
	ID          uuid.UUID
	RuleID      string
	Mechanism   string
	PhaseResult *string
	DryRun      bool
	AppliedAt   *time.Time
}

// ExecTxn is a neutral, kensa-free view of one Kensa remediation transaction
// outcome. The worker maps kensa.RemediationTxn into this shape before calling
// RecordExecution, so internal/remediation never imports internal/kensa (which
// would create an import cycle: kensa -> credential -> ... and the worker
// already depends on both).
type ExecTxn struct {
	// TxnID is the Kensa transaction id (the rollback handle). Stored as
	// remediation_transactions.kensa_txn_id.
	TxnID uuid.UUID
	// Status is the per-transaction outcome: committed | rolled_back |
	// partially_applied | errored. Mapped to the phase_result CHECK enum
	// (committed | rolled_back | skipped) for the journal row.
	Status string
	// Evidence is the signed evidence envelope (or a summary), stored in the
	// remediation_transactions.evidence JSONB column.
	Evidence []byte
	// Err is the transaction error string, empty on success.
	Err string
}

// TxnCommitted reports whether s is the terminal "rule now passes" status.
// Kensa runs Validate before Commit, so a committed transaction means the
// rule's check passed on the host.
func (t ExecTxn) Committed() bool { return t.Status == "committed" }

var (
	// ErrNotFound is returned when a remediation request id does not exist.
	ErrNotFound = errors.New("remediation: not found")
	// ErrDuplicateOpen is returned when an open request already exists for the
	// same host+rule (partial-unique violation).
	ErrDuplicateOpen = errors.New("remediation: an open remediation request already exists for this host and rule")
	// ErrWrongState is returned when a transition does not apply to the current
	// status (e.g. approving an already-rejected request).
	ErrWrongState = errors.New("remediation: action not valid for the current state")
	// ErrSelfReview is returned when the reviewer is the requester:
	// separation of duties forbids approving your own request.
	ErrSelfReview = errors.New("remediation: requester cannot review their own request")
	// ErrInvalidInput is returned for an empty rule_id.
	ErrInvalidInput = errors.New("remediation: invalid input")
)
