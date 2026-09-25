// @spec system-auth-identity

package identity

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// rollbackCapture records the context its Rollback receives.
type rollbackCapture struct {
	pgx.Tx
	got      context.Context
	errAt    error // ctx.Err() while the rollback runs
	calledAt time.Time
}

func (r *rollbackCapture) Rollback(ctx context.Context) error {
	r.got = ctx
	r.errAt = ctx.Err()
	r.calledAt = time.Now()
	return nil
}

type cleanupKey struct{}

// @ac AC-91
// AC-91, the cleanup context: detached from the operation's cancellation,
// carrying its values, with a deadline of its own no more than
// RollbackCleanupLimit away.
func TestRollbackDetached_CleanupContext(t *testing.T) {
	t.Run("system-auth-identity/AC-91", func(t *testing.T) {
		parent, cancel := context.WithTimeout(
			context.WithValue(context.Background(), cleanupKey{}, "request-value"), time.Millisecond)
		defer cancel()
		<-parent.Done() // the operation deadline has expired

		tx := &rollbackCapture{}
		RollbackDetached(parent, tx)
		if tx.got == nil {
			t.Fatal("Rollback was not called")
		}
		if err := tx.errAt; err != nil {
			t.Errorf("cleanup context is already done (%v): it was not detached from the expired operation", err)
		}
		if v, _ := tx.got.Value(cleanupKey{}).(string); v != "request-value" {
			t.Errorf("cleanup context lost the caller's values (got %q)", v)
		}
		deadline, ok := tx.got.Deadline()
		if !ok {
			t.Fatal("cleanup context has no deadline: cleanup is unbounded")
		}
		remaining := deadline.Sub(tx.calledAt)
		if remaining <= 0 || remaining > RollbackCleanupLimit {
			t.Errorf("cleanup deadline %v away, want positive and at most %v", remaining, RollbackCleanupLimit)
		}
		if RollbackCleanupLimit > 2*time.Second {
			t.Errorf("RollbackCleanupLimit = %v, the documented limit is 2s", RollbackCleanupLimit)
		}
	})
}
