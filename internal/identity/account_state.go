package identity

import (
	"context"
	"errors"
	"fmt"

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
