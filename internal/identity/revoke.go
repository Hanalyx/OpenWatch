package identity

import (
	"context"
	"fmt"

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
func LockUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	var one int
	if err := tx.QueryRow(ctx,
		`SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE`, userID).Scan(&one); err != nil {
		return err
	}
	return nil
}
