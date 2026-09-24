package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBTX is the subset of the pgx surface these helpers need. Both
// *pgxpool.Pool and pgx.Tx satisfy it, so a helper can run standalone or
// inside a caller's transaction under the per-user lock without owning
// one itself. Spec C-34.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// RevokeUserCredentials performs USER-WIDE INTERACTIVE revocation: every
// session and every refresh family belonging to the user. It is what
// Disable, AdminResetPassword and SoftDelete perform.
//
// It deliberately does NOT touch api_tokens. Service-account tokens are
// not interactive credentials, they have their own lifecycle, and their
// behavior on account state is a separate decision. Spec C-36.
//
// The function owns no transaction. Callers that must be atomic with
// another change pass their own pgx.Tx. Spec C-34.
func RevokeUserCredentials(ctx context.Context, db DBTX, userID uuid.UUID) error {
	if _, err := db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID); err != nil {
		return fmt.Errorf("identity: revoke sessions for user: %w", err)
	}
	if _, err := db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID); err != nil {
		return fmt.Errorf("identity: revoke refresh tokens for user: %w", err)
	}
	return nil
}

// RevokeUserCredentialsPool is the convenience wrapper for callers that
// have no transaction of their own to join.
func RevokeUserCredentialsPool(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID) error {
	return RevokeUserCredentials(ctx, pool, userID)
}

// LockUser takes the per-user advisory position for interactive
// credential work: a row lock on the users row, as the FIRST statement
// of the caller's transaction.
//
// FOR NO KEY UPDATE rather than FOR UPDATE: 23 foreign keys reference
// users(id), and FOR UPDATE takes a lock that blocks every child insert
// that needs FOR KEY SHARE on the parent. FOR NO KEY UPDATE serializes
// writers to the row without blocking those inserts, which is exactly
// the scope wanted here.
//
// A missing user row is reported as pgx.ErrNoRows so the caller can
// treat it as a determinate refusal. Spec C-34.
//
// The wait is bounded by LockWaitBound. Without a bound nothing ends it:
// the http.Server WriteTimeout does not cancel a handler, so a request
// blocked here waited until its client disconnected. A wait that exceeds
// the bound returns ErrLockWaitExceeded, a determinate failure: the
// transaction made no change. Spec C-43.
func LockUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	// set_config with is_local=true is SET LOCAL: it lasts until the
	// transaction ends and cannot leak to the pooled connection.
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		fmt.Sprintf("%dms", LockWaitBound.Milliseconds())); err != nil {
		return fmt.Errorf("identity: set lock wait bound: %w", err)
	}
	var one int
	if err := tx.QueryRow(ctx,
		`SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE`, userID).Scan(&one); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == sqlStateLockNotAvailable {
			return fmt.Errorf("%w: %w", ErrLockWaitExceeded, err)
		}
		return err
	}
	return nil
}

// LockWaitBound caps how long a credential transaction waits for the
// per-user lock. The lock is held only across short database statements:
// password hashing and every network call run outside it by design
// (C-39), so a wait this long means a stuck holder rather than ordinary
// contention. It leaves most of the 60 s http.Server WriteTimeout for the
// response that reports the failure. Spec C-43.
const LockWaitBound = 5 * time.Second

// ErrLockWaitExceeded reports that the per-user lock was not acquired
// within LockWaitBound. Nothing was read or changed under the lock, so
// the caller may say that nothing happened and that a retry is safe.
var ErrLockWaitExceeded = errors.New("identity: per-user lock wait exceeded")

// sqlStateLockNotAvailable is what PostgreSQL raises when lock_timeout
// expires.
const sqlStateLockNotAvailable = "55P03"
