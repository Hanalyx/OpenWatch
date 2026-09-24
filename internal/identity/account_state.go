package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AccountStatus is what the binders and the issuance paths ask about a
// user before they will bind or mint a credential.
//
// The zero value is AccountUnknown and it never authenticates. That is
// deliberate: a status that has not been determined must not be able to
// arrive at a caller looking like permission. Spec C-31.
type AccountStatus int

const (
	// AccountUnknown is the zero value. It means nobody determined the
	// state, and it authenticates nothing.
	AccountUnknown AccountStatus = iota
	// AccountActive may authenticate.
	AccountActive
	// AccountDisabled was disabled by an administrator.
	AccountDisabled
	// AccountDeleted was soft-deleted.
	AccountDeleted
	// AccountMissing has no users row at all.
	AccountMissing
)

// MayAuthenticate reports whether a credential bound to this account may
// be honored. Only AccountActive may.
func (s AccountStatus) MayAuthenticate() bool { return s == AccountActive }

// Reason is the audit reason recorded when this status refuses a
// credential. Empty for AccountActive, which refuses nothing.
func (s AccountStatus) Reason() string {
	switch s {
	case AccountActive:
		return ""
	case AccountDisabled:
		return "account_disabled"
	case AccountDeleted:
		return "account_deleted"
	case AccountMissing:
		return "account_missing"
	default:
		return "account_state_unknown"
	}
}

// ErrAccountStateUnavailable reports that account state could not be
// determined. It is an infrastructure failure, not a rejected
// credential, and callers must answer 503 rather than 401. Spec C-32.
var ErrAccountStateUnavailable = errors.New("identity: account state unavailable")

// accountStateStmt is the single source of the account-state read. Both
// the pool-backed and the transaction-backed readers use it so the two
// cannot drift apart.
const accountStateStmt = `SELECT disabled_at IS NOT NULL, deleted_at IS NOT NULL FROM users WHERE id = $1`

// ReadAccountStatus reads a user's account state. A missing row is
// AccountMissing, which is a determinate answer. Any other failure
// returns ErrAccountStateUnavailable wrapped, and AccountUnknown.
func ReadAccountStatus(ctx context.Context, q DBTX, userID uuid.UUID) (AccountStatus, error) {
	var disabled, deleted bool
	err := q.QueryRow(ctx, accountStateStmt, userID).Scan(&disabled, &deleted)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return AccountMissing, nil
	case err != nil:
		return AccountUnknown, fmt.Errorf("%w: %v", ErrAccountStateUnavailable, err)
	}
	// Deletion outranks disable when both are set: it is the stronger
	// statement about the account and the one an operator acted on last.
	switch {
	case deleted:
		return AccountDeleted, nil
	case disabled:
		return AccountDisabled, nil
	}
	return AccountActive, nil
}

// AuthInputs is the set of authentication inputs a login verified
// BEFORE it took the per-user lock, re-read under that lock so the
// locked values decide.
//
// Account state is not the only thing that can go stale between
// verifying a credential and issuing one. The password can be reset, and
// MFA enrollment can complete. Spec C-39.
type AuthInputs struct {
	// LastPasswordChangeAt is the credential version. The only statement
	// that writes password_hash also bumps this column, so a change to
	// the password is always visible as a change here. The column is
	// NOT NULL with a default, so there is no absent case.
	LastPasswordChangeAt time.Time
	// MFAEnrolled is CONFIRMED enrollment: a secret whose first OTP has
	// been verified. A secret written by a begun-but-unconfirmed
	// enrollment does not require an OTP at login.
	MFAEnrolled bool
}

// PasswordUnchangedSince reports whether the password is still the one
// whose version was captured before the transaction.
//
// A zero captured value is treated as NO evidence and therefore as a
// mismatch. The column is NOT NULL, so a real capture is never zero, and
// a caller that forgot to capture one must not pass this check.
func (a AuthInputs) PasswordUnchangedSince(captured time.Time) bool {
	if captured.IsZero() {
		return false
	}
	return a.LastPasswordChangeAt.Equal(captured)
}

// ReadAuthInputs re-reads the authentication inputs inside the caller's
// transaction, which must already hold the per-user lock. Spec C-34, C-39.
func ReadAuthInputs(ctx context.Context, q DBTX, userID uuid.UUID) (AuthInputs, error) {
	var in AuthInputs
	err := q.QueryRow(ctx, `
		SELECT u.last_password_change_at,
		       EXISTS (SELECT 1 FROM auth_mfa_secrets m
		               WHERE m.user_id = u.id AND m.last_verified_at IS NOT NULL)
		FROM users u WHERE u.id = $1`, userID).Scan(&in.LastPasswordChangeAt, &in.MFAEnrolled)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// No row is not "no change": it is an account that cannot
		// authenticate, and the caller's account-state check answers it.
		return AuthInputs{}, fmt.Errorf("%w: user %s absent", ErrAccountStateUnavailable, userID)
	case err != nil:
		return AuthInputs{}, fmt.Errorf("%w: %v", ErrAccountStateUnavailable, err)
	}
	return in, nil
}

// BearerVerdict is the result of evaluating a session-bound access
// token. The zero value is BearerUnknown and authorizes nothing.
//
// The order of the checks and the reason vocabulary follow the recorded
// Bearer binding table (OW-062 section 4) so an operator triaging a 401
// reads the term the design uses. Spec C-38.
type BearerVerdict int

const (
	// BearerUnknown is the zero value and authorizes nothing.
	BearerUnknown BearerVerdict = iota
	// BearerOK: the token may bind an identity.
	BearerOK
	// BearerSIDAbsent: the token carries no session id.
	BearerSIDAbsent
	// BearerSessionAbsent: no session row for the id.
	BearerSessionAbsent
	// BearerOwnerMismatch: the session belongs to a different user.
	BearerOwnerMismatch
	// BearerSessionRevoked: the session was revoked.
	BearerSessionRevoked
	// BearerAbsoluteExpired: the session passed its ABSOLUTE deadline.
	BearerAbsoluteExpired
	// BearerAccountDisabled / BearerAccountDeleted: account state.
	BearerAccountDisabled
	BearerAccountDeleted
)

// OK reports whether the token may authenticate.
func (v BearerVerdict) OK() bool { return v == BearerOK }

// Reason is the audit reason recorded when this verdict refuses.
func (v BearerVerdict) Reason() string {
	switch v {
	case BearerOK:
		return ""
	case BearerSIDAbsent:
		return "sid_absent"
	case BearerSessionAbsent:
		return "session_absent"
	case BearerOwnerMismatch:
		return "session_owner_mismatch"
	case BearerSessionRevoked:
		return "session_revoked"
	case BearerAbsoluteExpired:
		return "session_absolute_expired"
	case BearerAccountDisabled:
		return "account_disabled"
	case BearerAccountDeleted:
		return "account_deleted"
	default:
		return "session_binding_unknown"
	}
}

// EvaluateBearerBinding decides a session-bound access token in ONE
// query over sessions joined to users.
//
// It deliberately does NOT consider the idle window. The idle window
// tracks real user activity in a browser session; a Bearer request is
// not that, and neither sliding it nor expiring against it is right.
// Bearer traffic is bounded by the session's ABSOLUTE deadline, which is
// the ceiling a login established and nothing can extend. Spec C-29, C-38.
//
// The deadline is evaluated with clock_timestamp() in the database, not
// against this process's clock, so skew between the application and the
// database cannot change who is allowed in.
func EvaluateBearerBinding(ctx context.Context, q DBTX, sessionID, subject uuid.UUID) (BearerVerdict, error) {
	if sessionID == uuid.Nil {
		return BearerSIDAbsent, nil
	}
	var (
		owner           uuid.UUID
		sessionRevoked  bool
		absoluteExpired bool
		accountDisabled bool
		accountDeleted  bool
	)
	err := q.QueryRow(ctx, `
		SELECT s.user_id,
		       s.revoked_at IS NOT NULL                   AS session_revoked,
		       clock_timestamp() >= s.absolute_expires_at AS absolute_expired,
		       u.disabled_at IS NOT NULL                  AS account_disabled,
		       u.deleted_at  IS NOT NULL                  AS account_deleted
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = $1`, sessionID).
		Scan(&owner, &sessionRevoked, &absoluteExpired, &accountDisabled, &accountDeleted)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return BearerSessionAbsent, nil
	case err != nil:
		return BearerUnknown, fmt.Errorf("%w: %v", ErrAccountStateUnavailable, err)
	}
	switch {
	case owner != subject:
		// The token is correctly signed and names a live session, but
		// not one belonging to the subject it claims. Nothing legitimate
		// produces this pair.
		return BearerOwnerMismatch, nil
	case sessionRevoked:
		return BearerSessionRevoked, nil
	case absoluteExpired:
		return BearerAbsoluteExpired, nil
	case accountDeleted:
		return BearerAccountDeleted, nil
	case accountDisabled:
		return BearerAccountDisabled, nil
	}
	return BearerOK, nil
}
