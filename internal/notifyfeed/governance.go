package notifyfeed

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// GovernanceProjector turns governance + remediation lifecycle events into
// RBAC-scoped in-app notifications — the bell's "action queue" (Slice 3). Unlike
// the alert Channel and the regression Projector (which fan to every active
// user), governance items reach only the users who can act on them: an
// exception pending approval reaches approvers, a decision reaches the
// requester, a failed remediation reaches the operators who can re-run it.
//
// It implements the Notifier interface the exception service and the
// GovernanceNotifier the remediation worker hold, so neither producer imports
// this package. Spec: system-notifications (Slice 3).
type GovernanceProjector struct {
	store *Store
}

// NewGovernanceProjector returns a governance projector over the feed store.
func NewGovernanceProjector(store *Store) *GovernanceProjector {
	return &GovernanceProjector{store: store}
}

// exceptionQueueLink is where the exception queue lives in the UI
// (frontend/src/components/settings/ExceptionQueue.tsx, mounted on the policies
// settings page). Approvers act on the queue here.
const exceptionQueueLink = "/settings/policies"

// ExceptionRequested records an "exception pending approval" notification for
// every user whose role can approve it (exception:approve → security_admin,
// admin). Grouped per exception so a re-surfaced request collapses onto one
// row. Best-effort: an error is returned for the caller to log, never to fail
// the request.
func (g *GovernanceProjector) ExceptionRequested(ctx context.Context, exceptionID, hostID uuid.UUID, ruleID string) error {
	host := g.store.hostName(ctx, hostID)
	h := hostID
	n := Notification{
		Kind:     "exception_pending",
		Severity: "high",
		Title:    fmt.Sprintf("Exception awaiting approval: %s on %s", ruleID, host),
		Body:     "A compliance exception request needs review and approval or rejection.",
		HostID:   &h,
		Link:     exceptionQueueLink,
		GroupKey: "exception_pending:" + exceptionID.String(),
	}
	if err := g.store.RecordForRoles(ctx, roleStrings(auth.RolesWithPermission(auth.ExceptionApprove)), n); err != nil {
		return fmt.Errorf("notifyfeed: exception requested: %w", err)
	}
	return nil
}

// ExceptionDecided records the outcome notification for the requester (only),
// closing the loop for the person who asked. Grouped per exception.
func (g *GovernanceProjector) ExceptionDecided(ctx context.Context, exceptionID, requestedBy uuid.UUID, ruleID string, approved bool) error {
	if requestedBy == uuid.Nil {
		return nil
	}
	verb, kind := "rejected", "exception_rejected"
	if approved {
		verb, kind = "approved", "exception_approved"
	}
	// Requester-facing: the rule id identifies the request; no host lookup.
	n := Notification{
		UserID:   requestedBy,
		Kind:     kind,
		Severity: "medium",
		Title:    fmt.Sprintf("Exception %s: %s", verb, ruleID),
		Body:     fmt.Sprintf("Your compliance exception request for %s was %s.", ruleID, verb),
		Link:     exceptionQueueLink,
		GroupKey: "exception_decided:" + exceptionID.String(),
	}
	if err := g.store.Record(ctx, n); err != nil {
		return fmt.Errorf("notifyfeed: exception decided: %w", err)
	}
	return nil
}

// ExceptionExpiringSoon warns approvers that an approved exception is about to
// lapse (after which its rules re-enter scope). Uses the QUIET fan-out: the
// expiry sweep re-evaluates hourly, so a non-quiet record would re-surface the
// same warning unread every hour. Grouped per exception.
func (g *GovernanceProjector) ExceptionExpiringSoon(ctx context.Context, exceptionID, hostID uuid.UUID, ruleID string) error {
	host := g.store.hostName(ctx, hostID)
	h := hostID
	n := Notification{
		Kind:     "exception_expiring",
		Severity: "medium",
		Title:    fmt.Sprintf("Exception expiring soon: %s on %s", ruleID, host),
		Body:     "An approved compliance exception is about to expire. Its rules will re-enter scope unless renewed.",
		HostID:   &h,
		Link:     exceptionQueueLink,
		GroupKey: "exception_expiring:" + exceptionID.String(),
	}
	if err := g.store.RecordForRolesQuiet(ctx, roleStrings(auth.RolesWithPermission(auth.ExceptionApprove)), n); err != nil {
		return fmt.Errorf("notifyfeed: exception expiring soon: %w", err)
	}
	return nil
}

// ExceptionExpired notifies approvers that an exception has lapsed and its rules
// are back in scope. Fires once per exception (the sweep flips each to expired
// exactly once), so the standard fan-out is used. Grouped per exception.
func (g *GovernanceProjector) ExceptionExpired(ctx context.Context, exceptionID, hostID uuid.UUID, ruleID string) error {
	host := g.store.hostName(ctx, hostID)
	h := hostID
	n := Notification{
		Kind:     "exception_expired",
		Severity: "medium",
		Title:    fmt.Sprintf("Exception expired: %s on %s", ruleID, host),
		Body:     "A compliance exception has expired. Its rules are back in scope and will be evaluated on the next scan.",
		HostID:   &h,
		Link:     exceptionQueueLink,
		GroupKey: "exception_expired:" + exceptionID.String(),
	}
	if err := g.store.RecordForRoles(ctx, roleStrings(auth.RolesWithPermission(auth.ExceptionApprove)), n); err != nil {
		return fmt.Errorf("notifyfeed: exception expired: %w", err)
	}
	return nil
}

// PasswordExpiring warns host operators that a host user account's password is
// about to expire (or has expired). Reaches everyone who can view the host
// (host:read). Uses the QUIET fan-out: the daily sweep re-evaluates every 24h,
// so a non-quiet record would re-surface the same warning unread each day.
// Grouped per (host, user) so the daily re-sweep collapses onto one row and a
// later "expired" simply updates the same item. Best-effort.
func (g *GovernanceProjector) PasswordExpiring(ctx context.Context, hostID uuid.UUID, username string, daysLeft int, expired bool) error {
	host := g.store.hostName(ctx, hostID)
	h := hostID
	n := Notification{
		Kind:   "account_password_expiring",
		HostID: &h,
		Link:   "/hosts/" + hostID.String(),
	}
	// Distinct group keys for the two states: crossing from "expiring soon"
	// into "expired" is a more urgent, distinct event that MUST surface as a
	// fresh unread item even if the operator already read the expiring
	// warning (the quiet upsert would otherwise DO NOTHING on the same key).
	// Within each state the daily re-sweep stays quiet.
	if expired {
		n.Severity = "high"
		n.Title = fmt.Sprintf("Password expired: %s on %s", username, host)
		n.Body = "A host user account's password has expired. Rotate it on the host before it blocks login."
		n.GroupKey = fmt.Sprintf("password_expired:%s:%s", hostID, username)
	} else {
		n.Severity = "medium"
		n.Title = fmt.Sprintf("Password expiring soon: %s on %s (in %d days)", username, host, daysLeft)
		n.Body = "A host user account's password is about to expire. Rotate it on the host before it lapses."
		n.GroupKey = fmt.Sprintf("password_expiring:%s:%s", hostID, username)
	}
	if err := g.store.RecordForRolesQuiet(ctx, roleStrings(auth.RolesWithPermission(auth.HostRead)), n); err != nil {
		return fmt.Errorf("notifyfeed: password expiring: %w", err)
	}
	return nil
}

// RemediationFailed records a "remediation failed / rolled back" notification
// for the operators who can act on it (remediation:execute → ops_lead,
// security_admin, admin). Grouped per (host, rule). finalStatus is the
// terminal remediation status ("failed" | "rolled_back"); action is
// "execute" | "rollback".
func (g *GovernanceProjector) RemediationFailed(ctx context.Context, hostID uuid.UUID, ruleID, action, finalStatus string) error {
	host := g.store.hostName(ctx, hostID)
	h := hostID
	lead := "Remediation failed"
	if finalStatus == "rolled_back" {
		lead = "Remediation rolled back"
	}
	n := Notification{
		Kind:     "remediation_failed",
		Severity: "high",
		Title:    fmt.Sprintf("%s: %s on %s", lead, ruleID, host),
		Body:     "An automated fix did not complete successfully. Review the host and re-run or remediate manually.",
		HostID:   &h,
		Link:     "/hosts/" + hostID.String(),
		GroupKey: "remediation_failed:" + hostID.String() + ":" + ruleID,
	}
	if err := g.store.RecordForRoles(ctx, roleStrings(auth.RolesWithPermission(auth.RemediationExecute)), n); err != nil {
		return fmt.Errorf("notifyfeed: remediation failed: %w", err)
	}
	return nil
}

// roleStrings adapts auth.RoleID values to the plain strings RecordForRoles
// queries user_roles.role_id with.
func roleStrings(ids []auth.RoleID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}
