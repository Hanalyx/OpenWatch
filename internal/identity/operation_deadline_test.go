// @spec system-auth-identity

package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// blockingTx blocks at the lock or at the commit until its context ends,
// then fails with the context's error, as a real driver does.
type blockingTx struct {
	pgx.Tx
	blockLock   bool
	blockCommit bool
}

type ctxRow struct{ err error }

func (r ctxRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) > 0 {
		if p, ok := dest[0].(*int); ok {
			*p = 1
		}
	}
	return nil
}

func (b *blockingTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (b *blockingTx) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	if b.blockLock {
		<-ctx.Done()
		return ctxRow{err: ctx.Err()}
	}
	return ctxRow{}
}

func (b *blockingTx) Commit(ctx context.Context) error {
	if b.blockCommit {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (b *blockingTx) Rollback(context.Context) error { return nil }

type blockingBeginner struct {
	begun       int
	blockLock   bool
	blockCommit bool
}

func (b *blockingBeginner) Begin(context.Context) (pgx.Tx, error) {
	b.begun++
	return &blockingTx{blockLock: b.blockLock, blockCommit: b.blockCommit}, nil
}

// @ac AC-82
// AC-82: RunSerialized bounds the whole operation, never extends an
// earlier caller deadline, reports a deadline that expires during the
// commit as an unknown outcome, and one that expires before it as a
// known failure.
func TestRunSerialized_OperationDeadline(t *testing.T) {
	t.Run("system-auth-identity/AC-82", func(t *testing.T) {
		uid := uuid.New()

		t.Run("establishes a deadline", func(t *testing.T) {
			var deadline time.Time
			var ok bool
			start := time.Now()
			err := RunSerialized(context.Background(), &blockingBeginner{}, uid, func(ctx context.Context, _ pgx.Tx) error {
				deadline, ok = ctx.Deadline()
				return nil
			})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if !ok {
				t.Fatal("the operation ran with no deadline")
			}
			if limit := start.Add(OperationDeadline); deadline.After(limit.Add(time.Second)) {
				t.Errorf("deadline %v is later than the operation limit %v", deadline, limit)
			}
		})

		t.Run("preserves an earlier caller deadline", func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			want, _ := parent.Deadline()
			var got time.Time
			if err := RunSerialized(parent, &blockingBeginner{}, uid, func(ctx context.Context, _ pgx.Tx) error {
				got, _ = ctx.Deadline()
				return nil
			}); err != nil {
				t.Fatalf("run: %v", err)
			}
			if !got.Equal(want) {
				t.Errorf("deadline = %v, want the caller's %v", got, want)
			}
		})

		t.Run("expiry during the commit is an unknown outcome", func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			b := &blockingBeginner{blockCommit: true}
			err := RunSerialized(parent, b, uid, func(context.Context, pgx.Tx) error { return nil })
			if !errors.Is(err, ErrCommitUnknown) {
				t.Errorf("err = %v, want ErrCommitUnknown", err)
			}
			if b.begun != 1 {
				t.Errorf("transactions begun = %d, want 1: an unknown outcome is not retried", b.begun)
			}
		})

		t.Run("expiry before the commit is a known failure", func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			b := &blockingBeginner{blockLock: true}
			err := RunSerialized(parent, b, uid, func(context.Context, pgx.Tx) error {
				t.Error("fn ran although the lock was never acquired")
				return nil
			})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want the deadline", err)
			}
			if errors.Is(err, ErrCommitUnknown) || errors.Is(err, ErrLockWaitExceeded) {
				t.Errorf("err = %v is misclassified: nothing reached a commit and no lock_timeout fired", err)
			}
			if b.begun != 1 {
				t.Errorf("transactions begun = %d, want 1", b.begun)
			}
		})

		t.Run("a commit error without a SQLSTATE is unknown outside RunSerialized too", func(t *testing.T) {
			if err := ClassifyCommitError(context.DeadlineExceeded); !errors.Is(err, ErrCommitUnknown) {
				t.Errorf("ClassifyCommitError(deadline) = %v, want ErrCommitUnknown", err)
			}
			known := &pgconn.PgError{Code: "23505"}
			if err := ClassifyCommitError(known); errors.Is(err, ErrCommitUnknown) {
				t.Error("a determinate commit error was classified unknown")
			}
		})
	})
}
