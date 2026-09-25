// @spec system-auth-identity
//
// Cleanup after a failed administrative transaction (C-43, AC-91). The
// real driver's failure path is exercised against the database; the HTTP
// classification is exercised through the users service's transaction
// seam. Durable-state assertions use a user created for the case, so they
// describe this attempt alone.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/jackc/pgx/v5"
	pgerr "github.com/jackc/pgx/v5/pgconn"
)

// failingCleanupBeginner wraps real transactions. Its rollback always
// reports a failure, after really rolling back. mode selects how the
// attempt fails first: "pre-commit" fails the first statement with the
// deadline; "unknown commit" rolls back and then fails the commit with no
// SQLSTATE, so its outcome cannot be known.
type failingCleanupBeginner struct {
	inner     identity.TxBeginner
	mode      string
	rollbacks atomic.Int32
}

type failingCleanupTx struct {
	pgx.Tx
	b *failingCleanupBeginner
}

func (b *failingCleanupBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &failingCleanupTx{Tx: tx, b: b}, nil
}

func (tx *failingCleanupTx) Exec(ctx context.Context, sql string, args ...any) (pgerr.CommandTag, error) {
	if tx.b.mode == "pre-commit" && strings.Contains(sql, "set_config") {
		return pgerr.CommandTag{}, context.DeadlineExceeded
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx *failingCleanupTx) Commit(ctx context.Context) error {
	if tx.b.mode == "unknown commit" {
		_ = tx.Tx.Rollback(ctx)
		return fmt.Errorf("write tcp 127.0.0.1:5432: %w", errors.New("connection reset by peer"))
	}
	return tx.Tx.Commit(ctx)
}

func (tx *failingCleanupTx) Rollback(ctx context.Context) error {
	tx.b.rollbacks.Add(1)
	_ = tx.Tx.Rollback(ctx)
	return errors.New("injected cleanup failure")
}

// @ac AC-91
// AC-91: a rollback that fails in the real driver discards the
// connection, and a failed cleanup never changes how the attempt is
// reported.
func TestRollbackCleanup_FailureAndClassification(t *testing.T) {
	t.Run("system-auth-identity/AC-91", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithMaxConns(t, lockTestPoolSize)
		ctx := context.Background()

		t.Run("a real rollback failure discards the connection", func(t *testing.T) {
			for _, terminate := range []bool{false, true} {
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatalf("begin: %v", err)
				}
				var pid int32
				if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					t.Fatalf("backend pid: %v", err)
				}
				if terminate {
					// The backend goes away under an open transaction, so the
					// real ROLLBACK fails on the wire.
					if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
						t.Fatalf("terminate backend: %v", err)
					}
					deadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(deadline) {
						var n int
						_ = pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&n)
						if n == 0 {
							break
						}
						time.Sleep(20 * time.Millisecond)
					}
				}
				conn := tx.Conn()
				identity.RollbackDetached(ctx, tx)
				if closed := conn.IsClosed(); closed != terminate {
					t.Errorf("terminated=%v: connection closed = %v, want %v", terminate, closed, terminate)
				}
			}
			waitPoolIdle(t, pool)
		})

		for _, tc := range []struct {
			mode      string
			retryable bool
			says      string
		}{
			{"pre-commit", true, "did not complete in time"},
			{"unknown commit", false, "may or may not"},
		} {
			tc := tc
			t.Run(tc.mode+" with failed cleanup", func(t *testing.T) {
				li := loginFresh(t, url, pool, "ac91"+strings.ReplaceAll(tc.mode, " ", ""))
				before := readAccountState(t, pool, li.u.ID)
				creds := snapshotCredentials(t, pool, li.u.ID)
				b := &failingCleanupBeginner{inner: pool, mode: tc.mode}
				srv.handlers.users.UseTxSource(b)
				got := doAPI(t, asRole(t, "POST", url+"/api/v1/users/"+li.u.ID.String()+":disable", auth.RoleAdmin, nil))
				srv.handlers.users.UseTxSource(nil)

				if b.rollbacks.Load() == 0 {
					t.Fatal("the cleanup was never attempted, so this case proves nothing")
				}
				if got.status != http.StatusServiceUnavailable || got.code != "server.error" || got.retryable != tc.retryable {
					t.Errorf("response = %d %q retryable=%v, want 503 server.error retryable=%v", got.status, got.code, got.retryable, tc.retryable)
				}
				if !strings.Contains(got.message, tc.says) {
					t.Errorf("message %q, want it to say %q", got.message, tc.says)
				}
				// A user created for this case, so these describe this
				// attempt: nothing it wrote survived.
				if readAccountState(t, pool, li.u.ID) != before {
					t.Error("the account changed")
				}
				if !snapshotCredentials(t, pool, li.u.ID).equal(creds) {
					t.Error("credential rows changed")
				}
			})
		}
	})
}
