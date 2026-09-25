// @spec system-auth-identity
//
// Administrative account mutations report failures by the stage the
// transaction reached (C-43): never began, rolled back before the commit,
// or uncertain at the commit.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// beginRecorder records every Begin outcome from the pool it wraps.
type beginRecorder struct {
	inner identity.TxBeginner
	mu    sync.Mutex
	began int
	errs  []error
}

func (b *beginRecorder) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.inner.Begin(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.errs = append(b.errs, err)
		return nil, err
	}
	b.began++
	return tx, nil
}

// deadlineAtCommitBeginner rolls back, then fails the commit with the
// context deadline, as when the deadline expires while COMMIT is in flight
// and the outcome cannot be known.
type deadlineAtCommitBeginner struct{ inner identity.TxBeginner }

type deadlineAtCommitTx struct{ pgx.Tx }

func (b deadlineAtCommitBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return deadlineAtCommitTx{tx}, nil
}

func (tx deadlineAtCommitTx) Commit(ctx context.Context) error {
	_ = tx.Tx.Rollback(ctx)
	return context.DeadlineExceeded
}

type accountState struct {
	disabled, deleted bool
	passwordHash      string
}

func readAccountState(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id uuid.UUID) accountState {
	t.Helper()
	var s accountState
	if err := pool.QueryRow(context.Background(),
		`SELECT disabled_at IS NOT NULL, deleted_at IS NOT NULL, password_hash FROM users WHERE id = $1`, id).
		Scan(&s.disabled, &s.deleted, &s.passwordHash); err != nil {
		t.Fatalf("read account: %v", err)
	}
	return s
}

// @ac AC-90
// AC-90: an administrative mutation that cannot start its transaction, or
// whose deadline expires after it began, reports "not applied" and changes
// nothing; the commit stage keeps precedence, so an uncertain commit is
// never reported as not applied.
func TestAdminMutations_ClassifiedByTransactionStage(t *testing.T) {
	t.Run("system-auth-identity/AC-90", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithMaxConns(t, lockTestPoolSize)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		t.Run("pool exhausted: no transaction begins", func(t *testing.T) {
			// A deliberately small pool for the account transactions, with
			// its only connection held. The binder and the audit writer use
			// the server's own pool, so the request reaches the handler.
			small := poolWithMaxConns(t, 1)
			held, err := small.Acquire(ctx)
			if err != nil {
				t.Fatalf("hold the small pool's connection: %v", err)
			}
			rec := &beginRecorder{inner: small}
			srv.handlers.users.UseTxSource(rec)
			defer srv.handlers.users.UseTxSource(nil)

			type tcase struct {
				name string
				id   uuid.UUID
				req  func(id uuid.UUID) *http.Request
			}
			mk := func(name string, disable bool, req func(uuid.UUID) *http.Request) tcase {
				li := loginFresh(t, url, pool, "ac90"+strings.ReplaceAll(name, " ", ""))
				if disable {
					if err := svc.Disable(ctx, li.u.ID); err != nil {
						t.Fatalf("disable: %v", err)
					}
				}
				return tcase{name, li.u.ID, req}
			}
			userURL := func(id uuid.UUID) string { return url + "/api/v1/users/" + id.String() }
			cases := []tcase{
				mk("disable", false, func(id uuid.UUID) *http.Request {
					return asRole(t, "POST", userURL(id)+":disable", auth.RoleAdmin, nil)
				}),
				mk("enable", true, func(id uuid.UUID) *http.Request {
					return asRole(t, "POST", userURL(id)+":enable", auth.RoleAdmin, nil)
				}),
				mk("reset", false, func(id uuid.UUID) *http.Request {
					return asRole(t, "POST", userURL(id)+":reset-password", auth.RoleAdmin,
						map[string]string{"new_password": "ac90-reset-Passphrase-3317"}) // pragma: allowlist secret
				}),
				mk("soft delete", false, func(id uuid.UUID) *http.Request {
					return asRole(t, "DELETE", userURL(id), auth.RoleAdmin, nil)
				}),
			}
			// The four requests run together: each waits the full operation
			// deadline for a connection that never frees.
			var wg sync.WaitGroup
			for _, c := range cases {
				c := c
				before := readAccountState(t, pool, c.id)
				creds := snapshotCredentials(t, pool, c.id)
				wg.Add(1)
				go func() {
					defer wg.Done()
					req := c.req(c.id)
					cid := "ac90-" + strings.ReplaceAll(uuid.NewString(), "-", "")
					req.Header.Set("X-Correlation-Id", cid)
					start := time.Now()
					got := doAPI(t, req)
					elapsed := time.Since(start)
					if got.status != http.StatusServiceUnavailable || got.code != "server.error" || !got.retryable {
						t.Errorf("%s: response = %d %q retryable=%v, want 503 server.error retryable", c.name, got.status, got.code, got.retryable)
					}
					if !strings.Contains(got.message, "could not start") {
						t.Errorf("%s: message %q does not say the change could not start", c.name, got.message)
					}
					if elapsed < identity.OperationDeadline-time.Second {
						t.Errorf("%s: answered after %v, before the %v operation deadline", c.name, elapsed, identity.OperationDeadline)
					}
					if after := readAccountState(t, pool, c.id); after != before {
						t.Errorf("%s: account state changed: %+v -> %+v", c.name, before, after)
					}
					if !snapshotCredentials(t, pool, c.id).equal(creds) {
						t.Errorf("%s: credential rows changed", c.name)
					}
					time.Sleep(2 * time.Second) // the audit writer batches
					var n int
					if err := pool.QueryRow(context.Background(),
						`SELECT count(*) FROM audit_events WHERE action LIKE 'admin.user.%' AND correlation_id = $1`, cid).Scan(&n); err != nil {
						t.Errorf("%s: read audit: %v", c.name, err)
					} else if n != 0 {
						t.Errorf("%s: %d success audit events for a change that was not applied", c.name, n)
					}
				}()
			}
			wg.Wait()
			held.Release()

			rec.mu.Lock()
			defer rec.mu.Unlock()
			if rec.began != 0 {
				t.Errorf("%d transactions began on the exhausted pool, want 0", rec.began)
			}
			if len(rec.errs) != len(cases) {
				t.Errorf("begin attempts = %d, want %d", len(rec.errs), len(cases))
			}
			for _, e := range rec.errs {
				if !errors.Is(e, context.DeadlineExceeded) {
					t.Errorf("begin failed with %v, want the operation deadline", e)
				}
			}
		})

		t.Run("deadline after the transaction began rolls back and releases", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac90midwork")
			before := readAccountState(t, pool, li.u.ID)
			release := holdUserLock(t, pool, li.u.ID, identity.LockWaitBound+15*time.Second)
			dctx, cancel := context.WithTimeout(ctx, time.Second)
			err := svc.Disable(dctx, li.u.ID)
			cancel()
			release()
			if err == nil || errors.Is(err, identity.ErrNotBegun) || errors.Is(err, identity.ErrCommitUnknown) {
				t.Errorf("err = %v, want a deadline after the transaction began", err)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v does not carry the deadline", err)
			}
			if readAccountState(t, pool, li.u.ID) != before {
				t.Error("the account changed although the transaction did not reach its commit")
			}
			waitPoolIdle(t, pool)
			// The transaction ended. The deadline canceled a query in
			// flight, so pgx closed that connection and the server aborted
			// the transaction with it; no backend is left holding the
			// account lock, and it can be taken at once.
			var idleInTx int
			if err := pool.QueryRow(ctx, `
				SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND state LIKE 'idle in transaction%'
				  AND pid <> pg_backend_pid()`).Scan(&idleInTx); err != nil {
				t.Fatalf("read activity: %v", err)
			}
			if idleInTx != 0 {
				t.Errorf("%d backends left idle in a transaction", idleInTx)
			}
			lctx, lcancel := context.WithTimeout(ctx, time.Second)
			defer lcancel()
			probe, err := pool.Begin(lctx)
			if err != nil {
				t.Fatalf("begin probe: %v", err)
			}
			if err := identity.LockUser(lctx, probe, li.u.ID); err != nil {
				t.Errorf("the account lock is still held after the deadline: %v", err)
			}
			_ = probe.Rollback(ctx)
		})

		t.Run("mapping is by stage, commit first", func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				err       error
				status    int
				retryable bool
				says      string
			}{
				{"not begun", fmt.Errorf("users: begin: %w: %w", identity.ErrNotBegun, context.DeadlineExceeded), 503, true, "could not start"},
				{"rolled back after a deadline", fmt.Errorf("users: lock: %w", context.DeadlineExceeded), 503, true, "did not complete in time"},
				{"uncertain commit interrupted by a deadline", identity.ClassifyCommitError(context.DeadlineExceeded), 503, false, "may or may not"},
			} {
				rec := httptest.NewRecorder()
				if !mapUserAdminErr(rec, tc.err) {
					t.Fatalf("%s: not mapped", tc.name)
				}
				body := rec.Body.String()
				if rec.Code != tc.status || !strings.Contains(body, tc.says) ||
					strings.Contains(body, `"retryable":true`) != tc.retryable {
					t.Errorf("%s: %d %s", tc.name, rec.Code, body)
				}
			}
		})

		t.Run("deadline during the commit stays unknown over HTTP", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac90commit")
			before := readAccountState(t, pool, li.u.ID)
			srv.handlers.users.UseTxSource(deadlineAtCommitBeginner{inner: pool})
			got := doAPI(t, asRole(t, "POST", url+"/api/v1/users/"+li.u.ID.String()+":disable", auth.RoleAdmin, nil))
			srv.handlers.users.UseTxSource(nil)
			if got.status != http.StatusServiceUnavailable || got.retryable || !strings.Contains(got.message, "may or may not") {
				t.Errorf("response = %d retryable=%v %q, want the unknown outcome", got.status, got.retryable, got.message)
			}
			if readAccountState(t, pool, li.u.ID) != before {
				t.Error("the account changed although this variant rolled back")
			}
		})
	})
}
