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
