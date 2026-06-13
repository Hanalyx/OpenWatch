// Package exception implements compliance exception governance:
// operator-approved rule waivers with a request -> approve/reject ->
// revoke/expire lifecycle.
//
// DB-backed (scan plan decision 2026-06-13): an exception is
// approval-workflow data with a lifecycle, queries, and an audit
// trail, not a signed static policy file.
//
// OVERLAY MODEL: an exception NEVER mutates host_rule_state. A failing
// rule with an active exception stays 'fail' in the raw scan results
// (Kensa's verdict is authoritative); the exception is a governance
// annotation the lens/UI reads to mark a failure as accepted risk.
//
// Separation of duties: the requester cannot approve their own request
// (enforced here, on top of the distinct exception:request vs
// exception:approve RBAC permissions).
//
// Spec: api-compliance-exceptions v1.0.0.
package exception

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is the exception lifecycle state.
type Status string

const (
	StatusRequested Status = "requested"
	StatusApproved  Status = "approved"
	StatusRejected  Status = "rejected"
	StatusRevoked   Status = "revoked"
	StatusExpired   Status = "expired"
)

// Exception is one compliance_exceptions row.
type Exception struct {
	ID     uuid.UUID
	HostID uuid.UUID
	// HostName is populated by the list queries (ListForHost,
	// ListFleet) via a join; the single-row lifecycle ops leave it
	// empty (the UI re-fetches the list after a mutation).
	HostName    string
	RuleID      string
	Reason      string
	Status      Status
	RequestedBy uuid.UUID
	ReviewedBy  *uuid.UUID
	ReviewNote  string
	ExpiresAt   *time.Time
	RequestedAt time.Time
	ReviewedAt  *time.Time
}

// Active reports whether the exception is currently suppressing: an
// approved row that has not passed its expiry.
func (e Exception) Active(now time.Time) bool {
	if e.Status != StatusApproved {
		return false
	}
	return e.ExpiresAt == nil || e.ExpiresAt.After(now)
}

var (
	// ErrNotFound is returned when an exception id does not exist.
	ErrNotFound = errors.New("exception: not found")
	// ErrDuplicateOpen is returned when a requested/approved exception
	// already exists for the same host+rule (partial-unique violation).
	ErrDuplicateOpen = errors.New("exception: an open exception already exists for this host and rule")
	// ErrWrongState is returned when a transition does not apply to the
	// current status (e.g. approving a rejected exception).
	ErrWrongState = errors.New("exception: action not valid for the current state")
	// ErrSelfReview is returned when the reviewer is the requester:
	// separation of duties forbids approving your own request.
	ErrSelfReview = errors.New("exception: requester cannot review their own request")
	// ErrInvalidInput is returned for empty rule_id/reason etc.
	ErrInvalidInput = errors.New("exception: invalid input")
)
