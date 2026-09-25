// @spec system-auth-identity
//
// Cookie-session verification is bounded (bugs/OW-077, C-44), and the
// users service's own limits and unknown commits (C-43).

package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cookieMe sends GET /auth/me with the session cookie and its own
// correlation id. background marks it as a non-user request.
func cookieMe(t *testing.T, url string, c *http.Cookie, background bool) (apiResult, string) {
	t.Helper()
	cid := "ow77-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
	req.AddCookie(c)
	req.Header.Set("X-Correlation-Id", cid)
	if background {
		req.Header.Set(identity.BackgroundRefreshHeader, "1")
	}
	return doAPI(t, req), cid
}

func sessionExpiry(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) time.Time {
	t.Helper()
	var exp time.Time
	if err := pool.QueryRow(context.Background(), `SELECT expires_at FROM sessions WHERE id = $1`, id).Scan(&exp); err != nil {
		t.Fatalf("read expires_at: %v", err)
	}
	return exp
}

// waitForSlideWaiter waits until a request is blocked on the idle slide.
func waitForSlideWaiter(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query ILIKE '%SET last_seen%'
			  AND pid <> pg_backend_pid()`).Scan(&n); err == nil && n > 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// handlerRan reports whether /auth/me's own handler produced the body.
func (r apiResult) handlerRan() bool {
	_, hasError := r.body["error"]
	return !hasError && r.status == http.StatusOK
}

// @ac AC-83
// AC-83: an ordinary cookie request whose session row is locked elsewhere
// answers 503 once the lock limit expires. The protected handler does not
// run, no cookie is cleared, and the session is untouched.
func TestCookieVerification_LockedSessionIsBounded503(t *testing.T) {
	t.Run("system-auth-identity/AC-83", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		li := loginFresh(t, url, pool, "ac83locked")
		sid := sessionIDOf(t, pool, li.u.ID)
		expBefore := sessionExpiry(t, pool, sid)
		release := holdRowLocks(t, pool, "sessions", li.u.ID, identity.LockWaitBound+15*time.Second)
		start := time.Now()
		got, cid := cookieMe(t, url, li.sessionCookie, false)
		elapsed := time.Since(start)
		release()

		if got.status != http.StatusServiceUnavailable || got.code != "server.error" {
			t.Errorf("response = %d %q, want 503 server.error", got.status, got.code)
		}
		if got.handlerRan() {
			t.Error("the protected handler ran")
		}
		if got.clearsCredential() || got.setsCredential() {
			t.Error("the response changed a credential cookie")
		}
		if elapsed < identity.LockWaitBound-250*time.Millisecond || elapsed > identity.LockWaitBound+5*time.Second {
			t.Errorf("answered after %v; the lock limit is %v", elapsed, identity.LockWaitBound)
		}
		if reason := loginFailureReasonFor(t, pool, cid); reason != "session_lookup_failed" {
			t.Errorf("audit reason = %q, want session_lookup_failed", reason)
		}
		if !sessionExpiry(t, pool, sid).Equal(expBefore) {
			t.Error("the idle window moved although verification did not complete")
		}
		if code := authMe(t, url, li.sessionCookie); code != http.StatusOK {
			t.Errorf("the session no longer works after the lock was released: %d", code)
		}
	})
}

// @ac AC-84
// AC-84: a lock released before the limit lets verification finish
// normally, and the idle window is extended.
func TestCookieVerification_ReleaseBeforeLimitSlides(t *testing.T) {
	t.Run("system-auth-identity/AC-84", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		li := loginFresh(t, url, pool, "ac84released")
		sid := sessionIDOf(t, pool, li.u.ID)
		expBefore := sessionExpiry(t, pool, sid)
		release := holdRowLocks(t, pool, "sessions", li.u.ID, identity.LockWaitBound+15*time.Second)
		done := make(chan apiResult, 1)
		go func() {
			got, _ := cookieMe(t, url, li.sessionCookie, false)
			done <- got
		}()
		if !waitForSlideWaiter(t, pool) {
			t.Fatal("the request never waited on the idle slide")
		}
		time.Sleep(time.Second)
		release()
		got := <-done
		if got.status != http.StatusOK || !got.handlerRan() {
			t.Errorf("response = %d, want 200 from the handler", got.status)
		}
		if !sessionExpiry(t, pool, sid).After(expBefore) {
			t.Error("the idle window was not extended")
		}
	})
}

// @ac AC-85
// AC-85: a session revoked while verification waits is refused. The
// request does not authenticate from the read it made before waiting.
func TestCookieVerification_RevokedDuringWaitIsRefused(t *testing.T) {
	t.Run("system-auth-identity/AC-85", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ac85revoked")
		holder, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = holder.Rollback(ctx) }()
		// The revocation takes the row lock and holds it uncommitted.
		if _, err := holder.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE user_id = $1`, li.u.ID); err != nil {
			t.Fatalf("revoke under a held lock: %v", err)
		}
		type out struct {
			got apiResult
			cid string
		}
		done := make(chan out, 1)
		go func() {
			got, cid := cookieMe(t, url, li.sessionCookie, false)
			done <- out{got, cid}
		}()
		if !waitForSlideWaiter(t, pool) {
			t.Fatal("the request never waited on the idle slide")
		}
		if err := holder.Commit(ctx); err != nil {
			t.Fatalf("commit revocation: %v", err)
		}
		o := <-done
		if o.got.status != http.StatusUnauthorized || o.got.handlerRan() {
			t.Errorf("response = %d, want 401 without the handler running", o.got.status)
		}
		if reason := loginFailureReasonFor(t, pool, o.cid); reason != "session_revoked" {
			t.Errorf("audit reason = %q, want session_revoked", reason)
		}
	})
}

// @ac AC-86
// AC-86: logout under a real session-row lock reaches its own bounded
// outcome instead of waiting in the binder.
func TestLogout_SessionRowLockIsBounded(t *testing.T) {
	t.Run("system-auth-identity/AC-86", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		li := loginFresh(t, url, pool, "ac86logout")
		before := snapshotCredentials(t, pool, li.u.ID)
		release := holdRowLocks(t, pool, "sessions", li.u.ID, identity.LockWaitBound+15*time.Second)
		start := time.Now()
		got := doAPI(t, logoutRequest(url, li.sessionCookie, li.refreshCookie))
		elapsed := time.Since(start)
		release()
		if got.status != http.StatusInternalServerError || got.code != "auth.logout_incomplete" {
			t.Errorf("response = %d %q, want 500 auth.logout_incomplete", got.status, got.code)
		}
		if !got.clearsCredential() {
			t.Error("logout did not clear the cookies")
		}
		if strings.Contains(got.message, "account lock") {
			t.Errorf("message %q claims the account lock was not acquired; it was", got.message)
		}
		// One lock limit, in the revocation: the binder did not wait.
		if elapsed < identity.LockWaitBound-250*time.Millisecond || elapsed > 2*identity.LockWaitBound-time.Second {
			t.Errorf("answered after %v; want one %v lock limit, not two", elapsed, identity.LockWaitBound)
		}
		if !snapshotCredentials(t, pool, li.u.ID).equal(before) {
			t.Error("credential rows changed although the revocation rolled back")
		}
	})
}

// capturingBeginner records the deadline of the context each transaction
// began under.
type capturingBeginner struct {
	inner identity.TxBeginner
	mu    sync.Mutex
	got   []time.Time
}

func (c *capturingBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	d, ok := ctx.Deadline()
	c.mu.Lock()
	if ok {
		c.got = append(c.got, d)
	} else {
		c.got = append(c.got, time.Time{})
	}
	c.mu.Unlock()
	return c.inner.Begin(ctx)
}

func (c *capturingBeginner) first() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.got) == 0 {
		return time.Time{}
	}
	return c.got[0]
}

// @ac AC-87
// AC-87: an earlier caller deadline ends verification before the lock
// limit, and a credential request has one budget, not one per layer.
func TestVerificationDeadline_OneBudgetAndCallerFirst(t *testing.T) {
	t.Run("system-auth-identity/AC-87", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)

		t.Run("an earlier caller deadline ends verification", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac87caller")
			release := holdRowLocks(t, pool, "sessions", li.u.ID, identity.LockWaitBound+15*time.Second)
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			_, err := identity.VerifySession(ctx, pool, li.sessionCookie.Value)
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("verification succeeded although its deadline expired during the wait")
			}
			if errors.Is(err, identity.ErrSessionRevoked) || errors.Is(err, identity.ErrSessionExpired) || errors.Is(err, identity.ErrSessionNotFound) {
				t.Errorf("err = %v reports a session state, but nothing about the session was learned", err)
			}
			if elapsed > identity.LockWaitBound-time.Second {
				t.Errorf("returned after %v; the 1s caller deadline was not honored", elapsed)
			}
		})

		t.Run("one budget across the binder and the handler", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac87budget")
			cb := &capturingBeginner{inner: pool}
			srv.handlers.serializer = cb
			defer func() { srv.handlers.serializer = nil }()
			release := holdRowLocks(t, pool, "sessions", li.u.ID, identity.LockWaitBound+15*time.Second)
			// The login carries the session cookie, so the binder slides it
			// and waits on the held row. Release after 2 s.
			time.AfterFunc(2*time.Second, release)
			req := loginRequest(url, li.u.Username, li.u.Password, nil)
			req.AddCookie(li.sessionCookie)
			start := time.Now()
			got := doAPI(t, req)
			if got.status != http.StatusOK {
				t.Fatalf("login = %d %q, want 200", got.status, got.code)
			}
			d := cb.first()
			if d.IsZero() {
				t.Fatal("the login transaction ran with no deadline")
			}
			if limit := start.Add(identity.OperationDeadline + 500*time.Millisecond); d.After(limit) {
				t.Errorf("transaction deadline %v is after %v: the handler restarted the budget after the binder spent 2 s",
					d.Sub(start), identity.OperationDeadline)
			}
		})
	})
}

// @ac AC-88
// AC-88: a background request neither slides the idle window nor waits
// on a locked session row.
func TestCookieVerification_BackgroundDoesNotSlideOrWait(t *testing.T) {
	t.Run("system-auth-identity/AC-88", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		li := loginFresh(t, url, pool, "ac88background")
		sid := sessionIDOf(t, pool, li.u.ID)
		expBefore := sessionExpiry(t, pool, sid)
		release := holdRowLocks(t, pool, "sessions", li.u.ID, identity.LockWaitBound+15*time.Second)
		start := time.Now()
		got, _ := cookieMe(t, url, li.sessionCookie, true)
		elapsed := time.Since(start)
		release()
		if got.status != http.StatusOK || !got.handlerRan() {
			t.Errorf("background request = %d, want 200", got.status)
		}
		if elapsed > time.Second {
			t.Errorf("background request took %v; it waited on the session row", elapsed)
		}
		if !sessionExpiry(t, pool, sid).Equal(expBefore) {
			t.Error("a background request moved the idle window")
		}
	})
}

// @ac AC-89
// AC-89: the users service's account transactions carry a deadline of
// their own, and an unknown commit reaches the administrator as an
// unknown outcome, whether or not the change was durable.
func TestUsersService_DeadlineAndUnknownCommit(t *testing.T) {
	t.Run("system-auth-identity/AC-89", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)

		t.Run("default deadline", func(t *testing.T) {
			svc := users.NewService(pool, nil)
			cb := &capturingBeginner{inner: pool}
			svc.UseTxSource(cb)
			u := seedAuthUser(t, svc, "ac89deadline", false)
			start := time.Now()
			if err := svc.Disable(context.Background(), u.ID); err != nil {
				t.Fatalf("disable: %v", err)
			}
			d := cb.first()
			if d.IsZero() {
				t.Fatal("the account transaction ran with no deadline")
			}
			if d.After(start.Add(identity.OperationDeadline + 500*time.Millisecond)) {
				t.Errorf("deadline %v from the start, want at most %v", d.Sub(start), identity.OperationDeadline)
			}
		})

		for _, durable := range []bool{true, false} {
			durable := durable
			name := map[bool]string{true: "durable", false: "non-durable"}[durable]
			t.Run("unknown commit, "+name, func(t *testing.T) {
				li := loginFresh(t, url, pool, "ac89"+strings.ReplaceAll(name, "-", ""))
				srv.handlers.users.UseTxSource(&indeterminateBeginner{inner: pool, commitFirst: durable})
				req := asRole(t, "POST", url+"/api/v1/users/"+li.u.ID.String()+":disable", auth.RoleAdmin, nil)
				cid := "ac89-" + strings.ReplaceAll(uuid.NewString(), "-", "")
				req.Header.Set("X-Correlation-Id", cid)
				got := doAPI(t, req)
				srv.handlers.users.UseTxSource(nil)

				if got.status != http.StatusServiceUnavailable || got.code != "server.error" || got.retryable {
					t.Errorf("response = %d %q retryable=%v, want 503 server.error not retryable", got.status, got.code, got.retryable)
				}
				if !strings.Contains(got.message, "may or may not") {
					t.Errorf("message %q asserts an outcome", got.message)
				}
				if isDisabled(t, pool, li.u.ID) != durable {
					t.Errorf("disabled = %v, want %v for the %s variant", !durable, durable, name)
				}
				// No success event for an outcome nobody knows. Absence is
				// read after a settle period, because the writer batches.
				time.Sleep(2 * time.Second)
				var n int
				if err := pool.QueryRow(context.Background(),
					`SELECT count(*) FROM audit_events WHERE action = 'admin.user.disabled' AND correlation_id = $1`, cid).Scan(&n); err != nil {
					t.Fatalf("read audit: %v", err)
				}
				if n != 0 {
					t.Errorf("admin.user.disabled recorded %d times for an unknown outcome", n)
				}
			})
		}
	})
}
