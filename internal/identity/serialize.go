package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

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

// SQLSTATEs that state, in the standard's own words, that the outcome is
// UNKNOWN. A SQLSTATE is not evidence of a known result: these codes
// exist precisely to report that the server could not tell the caller
// what happened.
//
//	40003  statement_completion_unknown
//	08007  transaction_resolution_unknown
//
// Neither is in the retryable set, and that separation is deliberate:
// retrying an unknown commit can duplicate an issuance.
const (
	sqlStateStatementCompletionUnknown   = "40003"
	sqlStateTransactionResolutionUnknown = "08007"
	// sqlStateClassConnectionException is class 08. A connection
	// exception reported FOR A COMMIT leaves the outcome unknown: the
	// statement was sent and the reply was not read, which is the same
	// epistemic position as no SQLSTATE at all.
	sqlStateClassConnectionException = "08"
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

// TxBeginner is the subset of *pgxpool.Pool that RunSerialized needs.
//
// It is exported for DETERMINISTIC FAULT INJECTION. C-37's rules turn on
// which outcome a commit failure represents, and a test that wants a
// specific one needs to choose it rather than hope for it. Substituting
// the transaction source makes each branch reachable on demand and on
// every run, which is what makes the assertions worth anything.
type TxBeginner interface {
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
// Classification is by the error's MEANING, not by whether a SQLSTATE is
// present. An earlier version of this function treated every PgError as
// determinate, on the reasoning that an answered commit which failed did
// not commit. That reasoning is wrong for at least two codes the
// standard defines for exactly this situation: 40003
// statement_completion_unknown and 08007 transaction_resolution_unknown
// both carry a SQLSTATE and both say the outcome is unknown. Class 08
// more broadly reports a connection exception, which for a commit leaves
// the caller in the same position as no reply at all.
//
// The bias is deliberate. Treating a determinate rollback as unknown
// costs a truthful 503 that a user can resolve by signing in again.
// Treating an unknown commit as determinate can duplicate an issuance or
// tell a user a credential does not exist when it does. When in doubt,
// report doubt.
//
// This does not claim any particular server emits these codes on this
// path. It claims that if one does, the classifier must not mistake the
// code for certainty.
func commitIsIndeterminate(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		// No SQLSTATE: the failure happened at the transport or before
		// any reply was read, so nothing here knows what the server did.
		return true
	}
	switch {
	case pgErr.Code == sqlStateStatementCompletionUnknown,
		pgErr.Code == sqlStateTransactionResolutionUnknown:
		return true
	case strings.HasPrefix(pgErr.Code, sqlStateClassConnectionException):
		return true
	}
	return false
}

// ClassifyCommitError wraps a commit error whose outcome is unknown in
// ErrCommitUnknown, so a caller outside RunSerialized reports it the same
// way: neither success nor failure. A determinate error is returned
// unchanged. Spec C-37, C-43.
func ClassifyCommitError(err error) error {
	if err != nil && commitIsIndeterminate(err) {
		// Both stay visible to errors.Is. A deadline that expired during
		// the commit is therefore still a deadline underneath, and a
		// caller MUST test ErrCommitUnknown first: the commit's outcome
		// is what matters, not what interrupted it.
		return fmt.Errorf("%w: %w", ErrCommitUnknown, err)
	}
	return err
}

// ErrNotBegun reports that a transaction never began, for example because
// no pooled connection became free before the deadline. Nothing was read
// or written, so the operation was not applied. Spec C-43.
var ErrNotBegun = errors.New("identity: transaction did not begin")

// RollbackCleanupLimit bounds the detached rollback. Cleanup runs after
// the operation deadline may already have expired, so it can add up to
// this much beyond OperationDeadline; it is not contained within it.
// Spec C-43.
const RollbackCleanupLimit = 2 * time.Second

// RollbackDetached rolls tx back on a context detached from ctx's
// cancellation, keeping ctx's values, with its own RollbackCleanupLimit.
// When a deadline expired between statements, a rollback on the expired
// context would fail at once and the connection would be discarded; this
// one ends the transaction on the connection. When the deadline canceled a
// query in flight, pgx has already closed the connection and the server
// aborts the transaction with it.
//
// Its result never changes how the operation is reported. A transaction
// that never reached COMMIT cannot have committed, whether or not cleanup
// is confirmed; what an unconfirmed rollback leaves uncertain is when the
// server releases the transaction's locks. And an uncertain commit stays
// uncertain: cleanup after it proves nothing about the commit. When the
// rollback fails, pgx discards the connection and the failure is logged.
func RollbackDetached(ctx context.Context, tx pgx.Tx) {
	if err := RollbackDetachedErr(ctx, tx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		slog.WarnContext(context.WithoutCancel(ctx), "identity: rollback did not complete; the connection is discarded",
			slog.String("error", err.Error()))
	}
}

// RollbackDetachedErr is RollbackDetached returning the rollback's own
// error, so a test can see what the driver reported. Production callers
// use RollbackDetached, because the result must not change the outcome.
func RollbackDetachedErr(ctx context.Context, tx pgx.Tx) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RollbackCleanupLimit)
	defer cancel()
	return tx.Rollback(rctx)
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
//
// The whole operation, pool acquisition, every statement, the commit and
// any retries, runs under OperationDeadline, or under the caller's own
// deadline when that is earlier. A deadline that expires during the
// commit leaves the outcome unknown and is reported as ErrCommitUnknown,
// like any other commit error without a SQLSTATE. Spec C-43.
func RunSerialized(ctx context.Context, db TxBeginner, userID uuid.UUID, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := WithOperationDeadline(ctx)
	defer cancel()
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

func runSerializedOnce(ctx context.Context, db TxBeginner, userID uuid.UUID, fn func(context.Context, pgx.Tx) error) (err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin: %w: %w", ErrNotBegun, err)
	}
	committed := false
	defer func() {
		if !committed {
			RollbackDetached(ctx, tx)
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
