package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MaxSerializedAttempts is the total number of attempts, not the number
// of retries. Three means the original plus two more. Spec C-37.
const MaxSerializedAttempts = 3

// PostgreSQL SQLSTATEs that mean "this transaction lost a race and can
// be retried from the beginning". Nothing else is retryable: a unique
// violation or a check failure will fail identically on a second run,
// and retrying it only multiplies the work. Spec C-37.
const (
	sqlStateDeadlockDetected     = "40P01"
	sqlStateSerializationFailure = "40001"
)

// ErrCommitUnknown reports that a commit's outcome could not be
// determined. The transaction may or may not have committed. Callers
// MUST answer 503 and assert NEITHER result: retrying can duplicate an
// issuance, and reporting failure can tell a user a credential does not
// exist when it does. Spec C-37.
var ErrCommitUnknown = errors.New("identity: commit outcome unknown")

// ErrSerializationExhausted reports that every allowed attempt lost the
// same race. It is a server-side failure, not a rejected request.
var ErrSerializationExhausted = errors.New("identity: serialization attempts exhausted")

// txBeginner is the subset of *pgxpool.Pool that RunSerialized needs.
// Narrow on purpose: tests inject a beginner whose transactions fail
// with chosen SQLSTATEs, so attempt counts are asserted exactly rather
// than provoked by real contention. Spec C-37.
type txBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// IsRetryableTxError reports whether err is a lost race that a whole
// transaction restart can resolve.
func IsRetryableTxError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == sqlStateDeadlockDetected || pgErr.Code == sqlStateSerializationFailure
}

// commitIsIndeterminate reports whether a commit error leaves the
// outcome unknown.
//
// The rule: if the server answered, the answer carries a SQLSTATE, and
// an answered commit that failed did not commit. If there is no
// SQLSTATE the failure happened at the transport or before any reply was
// read, and nothing on this side knows whether the server applied it.
func commitIsIndeterminate(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	return !errors.As(err, &pgErr)
}

// RunSerialized runs fn inside ONE transaction that holds the per-user
// lock, and owns the whole lifecycle: begin, lock, fn, commit.
//
// fn MUST NOT commit or roll back. It receives the transaction so every
// read, revalidation and write it performs is inside the same atomic
// unit as the lock that protects them. Spec C-34.
//
// Retry is bounded and restarts the WHOLE transaction, because a
// transaction that hit 40P01 is already dead and re-running one
// statement inside it cannot work. The loop stops early when the request
// deadline has passed, so a retry never outlives the caller's context.
// Spec C-37.
func RunSerialized(ctx context.Context, db txBeginner, userID uuid.UUID, fn func(context.Context, pgx.Tx) error) error {
	var lastErr error
	for attempt := 1; attempt <= MaxSerializedAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}
		err := runSerializedOnce(ctx, db, userID, fn)
		if err == nil {
			return nil
		}
		// An unknown commit outcome is never retried. Retrying could
		// issue a second credential for a first one that may already
		// exist. Spec C-37.
		if errors.Is(err, ErrCommitUnknown) {
			return err
		}
		if !IsRetryableTxError(err) {
			return err
		}
		lastErr = err
		slog.WarnContext(ctx, "identity: serialized transaction lost a race; restarting",
			slog.Int("attempt", attempt),
			slog.Int("max_attempts", MaxSerializedAttempts),
			slog.String("user_id", userID.String()))
	}
	return fmt.Errorf("%w after %d attempts: %v", ErrSerializationExhausted, MaxSerializedAttempts, lastErr)
}

func runSerializedOnce(ctx context.Context, db txBeginner, userID uuid.UUID, fn func(context.Context, pgx.Tx) error) (err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	// The lock is the FIRST statement. Everything fn reads afterwards is
	// read under it, which is what makes a revalidation meaningful.
	if err := LockUser(ctx, tx, userID); err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		if commitIsIndeterminate(err) {
			// Do not claim this failed. Nothing here knows.
			slog.ErrorContext(ctx, "identity: commit outcome unknown; asserting neither result",
				slog.String("user_id", userID.String()),
				slog.String("error", err.Error()))
			return fmt.Errorf("%w: %v", ErrCommitUnknown, err)
		}
		return fmt.Errorf("identity: commit: %w", err)
	}
	committed = true
	return nil
}
