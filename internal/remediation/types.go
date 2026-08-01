// Package remediation implements the free (Apache 2.0 core) half of Phase 7
// remediation governance: an operator's intent to fix a failing rule on a
// host, with a request -> approve | reject lifecycle and a read-only
// projected-lift estimate.
//
// FREE-PATH INVARIANT (load-bearing): nothing in this package contacts a host
// or mutates host_rule_state / transactions. Request, Approve, and Reject are
// pure state transitions over remediation_requests; ProjectLift only reads
// host_rule_state. The act of mutating a host (dry-run / execute / rollback)
// is the OpenWatch Enterprise licensed track, gated by the remediation_execution license
// feature, and is NOT implemented here.
//
// Separation of duties: the requester cannot review their own request
// (enforced here, on top of the distinct remediation:request vs
// remediation:approve RBAC permissions).
//
// Spec: api-remediation v1.0.0. Plan: docs/engineering/remediation_core_plan.md.
package remediation

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is the remediation request lifecycle state. The free path uses
// pending_approval -> approved | rejected; the remaining states are driven by
// the OpenWatch Enterprise licensed execution track.
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

	// The terminal outcomes below distinguish states that need DIFFERENT
	// operator actions. Before they existed, "failed" meant any of five
	// things and carried the message "No host change was committed", which
	// was false for one of them. See api-remediation C-09.

	// StatusStaged: the persist layer was written but the runtime did NOT
	// converge, so the change takes effect at the next reboot. THE HOST IS
	// MUTATED. Produced by Kensa when a mechanism cannot change live kernel
	// state under the host's current configuration, today audit_rule_set on
	// a host with an immutable audit config (`auditctl -s` = `enabled 2`).
	// A staged rule must NOT be flipped to pass in host_rule_state (a
	// re-scan correctly still reports it failing), and rollback must remain
	// reachable.
	StatusStaged Status = "staged"

	// StatusReverted: Kensa's validation failed after apply and the engine
	// auto-restored the captured pre-state. THE HOST IS UNTOUCHED. This is
	// the atomic model working as designed, so it is deliberately not
	// presented as the same kind of failure as an errored run.
	StatusReverted Status = "reverted"

	// StatusNotApplied: the engine refused to act without mutating the host,
	// e.g. Kensa v0.8.0's duplicate-audit-action guard declining to write a
	// second drop-in for an action another rules.d file already audits. THE
	// HOST IS UNTOUCHED and is arguably already compliant. Carries the
	// refusal detail so an operator can tell it from a defect.
	StatusNotApplied Status = "not_applied"

	// StatusPartiallyApplied: non-capturable steps succeeded before a later
	// failure, so they are stranded and rollback cannot reverse them. HOST
	// STATE IS UNKNOWN and needs inspection.
	StatusPartiallyApplied Status = "partially_applied"
)

// HostMutated reports whether reaching this terminal status means the host was
// changed. It is the predicate that decides whether an operator has cleanup to
// consider, and it is why "reverted" must not render like "failed".
func (s Status) HostMutated() bool {
	switch s {
	case StatusExecuted, StatusStaged, StatusPartiallyApplied:
		return true
	default:
		return false
	}
}

// RollbackEligible reports whether a request in this status can be rolled back.
// Staged is included deliberately: Kensa captured pre-state and `kensa rollback`
// reverses a staged drop-in byte-perfect, so refusing here would strand a real
// host change with no route back. See api-remediation AC-09.
func (s Status) RollbackEligible() bool {
	return s == StatusExecuted || s == StatusStaged
}

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
	// Phases is the per-phase Kensa journal for this rule's transaction.
	// A "step" in this API has always meant one RULE; the Capture, Apply,
	// Validate and Commit phases an operator wants to see are one level
	// below it, and this is where they live.
	Phases []Phase
	// PreState is the captured pre-change state, verbatim from Kensa. Held
	// as raw JSON because its shape is the handler's, not ours.
	PreState json.RawMessage
}

// Phase is one Capture/Apply/Validate/Commit phase within a rule's
// transaction.
type Phase struct {
	Index      int    `json:"index"`
	Mechanism  string `json:"mechanism"`
	Detail     string `json:"detail,omitempty"`
	Success    bool   `json:"success"`
	Capturable bool   `json:"capturable"`
	Staged     bool   `json:"staged"`
	Stranded   bool   `json:"stranded"`
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
	// Status is the raw per-transaction Kensa outcome: committed |
	// rolled_back | partially_applied | errored | staged. Passed through
	// verbatim from api.TransactionStatus and mapped by OutcomeOf.
	Status string
	// Refused is true when the engine declined to act WITHOUT mutating the
	// host (Kensa reported Success=false with a detail rather than an error),
	// e.g. the v0.8.0 duplicate-audit-action guard. Kensa has no distinct
	// TransactionStatus for this, so it is carried alongside.
	Refused bool
	// Evidence is the signed evidence envelope (or a summary), stored in the
	// remediation_transactions.evidence JSONB column.
	Evidence []byte
	// Steps is the per-phase journal, serialised, stored in
	// remediation_transactions.steps. Empty for a transaction that never ran.
	Steps []byte
	// PreState is the captured pre-change state, serialised, stored in
	// remediation_transactions.pre_state. That column has existed since
	// migration 0037 and was never written until this carried it.
	PreState []byte
	// Mechanism is the first step's mechanism, stored in
	// remediation_transactions.mechanism, another column that existed and was
	// never populated.
	Mechanism string
	// Err is the transaction error string, empty on success.
	Err string
	// HostUnchanged mirrors api.TransactionResult.HostUnchanged: true if and
	// only if Kensa can PROVE the host is in its pre-transaction state.
	//
	// Carried into the journal for evidence, but deliberately NOT used to
	// decide severity. It is a bool, so false is ambiguous: it means either
	// "Kensa proved the host was mutated" or "nobody populated this field".
	// An errored transaction synthesised for an unreachable host arrives with
	// it unset, and escalating on that would send an operator to inspect a
	// host nothing ever touched. Alarm fatigue is its own failure mode, and
	// building severity on an ambiguous signal is the same mistake as
	// pattern-matching step prose. If Kensa ever gives this three states, or a
	// positive "host was mutated" assertion, revisit.
	HostUnchanged bool
}

// TxnCommitted reports whether s is the terminal "rule now passes" status.
// Kensa runs Validate before Commit, so a committed transaction means the
// rule's check passed on the host.
func (t ExecTxn) Committed() bool { return t.Status == "committed" }

// Staged reports whether the transaction wrote a reboot-deferred change. The
// host IS mutated but the runtime has not converged.
func (t ExecTxn) Staged() bool { return t.Status == "staged" }

// Kensa transaction statuses, named so the mapping below reads against the
// upstream vocabulary rather than bare strings. Mirrors api.TransactionStatus;
// duplicated as untyped strings because ExecTxn deliberately does not import
// the kensa package (it would create an import cycle through credential).
const (
	kensaCommitted        = "committed"
	kensaRolledBack       = "rolled_back"
	kensaPartiallyApplied = "partially_applied"
	kensaErrored          = "errored"
	kensaRecovered        = "recovered"
	kensaStaged           = "staged"
	kensaRollbackFailed   = "rollback_failed"
)

// OutcomeOf maps one Kensa transaction to the request status it implies, and
// reports whether the status was recognised.
//
// The bool is the point of this function. api-remediation AC-11 requires that
// an unrecognised Kensa status is never silently absorbed: the previous code
// collapsed everything unknown through a `default:` branch, which is exactly
// how Kensa v0.8.0's `staged` came to be reported as "failed, no host change
// was committed" on a host that had just been modified. A false return means
// the caller MUST log the offending value and fail closed.
func OutcomeOf(t ExecTxn) (Status, bool) {
	// A refusal is not a Kensa status; check it before the status switch.
	// The engine declined without touching the host.
	if t.Refused {
		return StatusNotApplied, true
	}
	switch t.Status {
	case kensaCommitted:
		return StatusExecuted, true
	case kensaStaged:
		return StatusStaged, true
	case kensaRolledBack, kensaRecovered:
		// Kensa restored pre-state itself. The host is untouched, so this is
		// NOT the same event as an errored run and must not read like one.
		return StatusReverted, true
	case kensaPartiallyApplied:
		return StatusPartiallyApplied, true
	case kensaRollbackFailed:
		// The engine applied, then tried to reverse, and could NOT verify the
		// restoration. Kensa: "the host is in an unconfirmed state." That is
		// the most severe outcome it reports, more so than partially_applied,
		// because an undo was attempted and its success is unknown. It maps to
		// the outcome that tells an operator to go look, never to a plain
		// failure, which would read as "nothing to do here".
		return StatusPartiallyApplied, true
	case kensaErrored:
		return StatusFailed, true
	default:
		// Fail closed: unknown means unknown, never a success-shaped outcome.
		return StatusFailed, false
	}
}

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
