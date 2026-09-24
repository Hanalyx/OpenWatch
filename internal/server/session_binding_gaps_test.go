// @spec system-auth-identity
//
// The session-binding gaps found reviewing #876: ownership, refresh
// eligibility, descendant revocation, the Bearer idle policy and the
// foreign-key boundary.
//
// One thing shapes several of these tests. A refresh lineage does NOT
// keep one session id: the cookie path rebinds each successor to the
// session it mints. So a fixture that only ever refreshes on the cookie
// path cannot show a descendant attached to a session someone revoked.
// Where that case matters, the lineage is desynchronized on the BODY
// path first, which rotates the token without rebinding it.

package server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	pgconnlib "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func sessionIDOf(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC LIMIT 1`, uid).Scan(&id); err != nil {
		t.Fatalf("session id: %v", err)
	}
	return id
}

// @ac AC-54
// AC-54: the binder compares the bound session's owner with the token's
// subject. Both tokens below are correctly signed and both sessions are
// live, so only the pairing differs.
func TestBearer_RefusesASessionOwnedByAnotherUser(t *testing.T) {
	t.Run("system-auth-identity/AC-54", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		alice := loginFresh(t, url, pool, "ac54alice")
		bob := loginFresh(t, url, pool, "ac54bob")
		bobSession := sessionIDOf(t, pool, bob.u.ID)

		// Control: alice's own token binds normally.
		if code := authMeBearer(t, url, alice.accessToken); code != http.StatusOK {
			t.Fatalf("control: alice's own token = %d, want 200", code)
		}

		// alice's subject, bob's live session.
		crossed, _, err := identity.IssueJWTForSession(alice.u.ID, string(auth.RoleViewer), bobSession)
		if err != nil {
			t.Fatalf("mint crossed token: %v", err)
		}
		if _, verr := identity.VerifyJWT(crossed); verr != nil {
			t.Fatalf("the crossed token must be cryptographically valid, got %v", verr)
		}
		if code := authMeBearer(t, url, crossed); code != http.StatusUnauthorized {
			t.Errorf("crossed token = %d, want 401: a token must not bind a session it does not own", code)
		}
		if reason := lastLoginFailureReason(t, pool); reason != "session_owner_mismatch" {
			t.Errorf("audit reason = %q, want session_owner_mismatch", reason)
		}
	})
}

// @ac AC-55
// AC-55: rotation refuses a token whose LINKED session is revoked, on
// both endpoints, each with its own unconsumed fixture.
func TestRefresh_RefusesATokenWhoseSessionIsRevoked(t *testing.T) {
	t.Run("system-auth-identity/AC-55", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		// Controls first, on separate users.
		ctrlBody := loginFresh(t, url, pool, "ac55cb")
		if code, _ := refreshBody(t, url, ctrlBody.bodyRefresh); code != http.StatusOK {
			t.Errorf("body control = %d, want 200", code)
		}
		ctrlCookie := loginFresh(t, url, pool, "ac55cc")
		if code, sess := refreshCookie(t, url, ctrlCookie.refreshCookie); code != http.StatusOK || sess == nil {
			t.Errorf("cookie control = %d (session set %v), want 200 with a session", code, sess != nil)
		}

		for _, tc := range []struct {
			name string
			user string
			run  func(li loggedInUser) (int, bool)
		}{
			{"body path", "ac55body", func(li loggedInUser) (int, bool) {
				code, access := refreshBody(t, url, li.bodyRefresh)
				return code, access != ""
			}},
			{"cookie path", "ac55cookie", func(li loggedInUser) (int, bool) {
				code, sess := refreshCookie(t, url, li.refreshCookie)
				return code, sess != nil
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, tc.user)
				// Revoke ONLY the session, leaving the refresh row live
				// and unconsumed, so the refusal is attributable to the
				// session rather than to the token's own state.
				if _, err := pool.Exec(ctx,
					`UPDATE sessions SET revoked_at = now() WHERE user_id = $1`, li.u.ID); err != nil {
					t.Fatalf("revoke session: %v", err)
				}
				var live int
				if err := pool.QueryRow(ctx,
					`SELECT count(*) FROM refresh_tokens
					 WHERE user_id=$1 AND revoked_at IS NULL AND rotated_to_id IS NULL`,
					li.u.ID).Scan(&live); err != nil {
					t.Fatalf("count: %v", err)
				}
				if live == 0 {
					t.Fatal("precondition: the refresh token must be live and unconsumed")
				}

				sessionsBefore, _ := liveCredentials(t, pool, li.u.ID)
				code, issued := tc.run(li)
				if code == http.StatusOK {
					t.Errorf("%s rotated a token whose session is revoked (status %d)", tc.name, code)
				}
				if issued {
					t.Errorf("%s issued a credential for a revoked session", tc.name)
				}
				sessionsAfter, _ := liveCredentials(t, pool, li.u.ID)
				if sessionsAfter > sessionsBefore {
					t.Errorf("%s minted a session (%d -> %d)", tc.name, sessionsBefore, sessionsAfter)
				}
				// The refusal must not be reuse: that would revoke the
				// user's other families for someone else's logout.
				var reuse int
				if err := pool.QueryRow(ctx,
					`SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND reuse_detected_at IS NOT NULL`,
					li.u.ID).Scan(&reuse); err != nil {
					t.Fatalf("count reuse: %v", err)
				}
				if reuse != 0 {
					t.Errorf("%s recorded reuse detection (%d rows) for a revoked-session refusal", tc.name, reuse)
				}
			})
		}
	})
}

// @ac AC-58
// AC-58: the foreign key does not cascade. The delete is REFUSED by the
// database, which is asserted against the actual constraint rather than
// against the migration text.
func TestSessionFK_DoesNotCascadeOnDelete(t *testing.T) {
	t.Run("system-auth-identity/AC-58", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ac58user")
		sid := sessionIDOf(t, pool, li.u.ID)

		var attached int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM refresh_tokens WHERE session_id = $1`, sid).Scan(&attached); err != nil {
			t.Fatalf("count attached: %v", err)
		}
		if attached == 0 {
			t.Fatal("precondition: the session must have a refresh token attached")
		}

		_, err := pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sid)
		if err == nil {
			t.Fatal("deleting a session with attached refresh rows succeeded; the FK cascades")
		}
		var pgErr *pgconnlib.PgError
		if !errors.As(err, &pgErr) {
			t.Fatalf("want a PostgreSQL error, got %T: %v", err, err)
		}
		if pgErr.Code != "23503" {
			t.Errorf("SQLSTATE = %s, want 23503 foreign_key_violation", pgErr.Code)
		}
		// Nothing was removed.
		var stillAttached, stillSessions int
		if err := pool.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM refresh_tokens WHERE session_id=$1),
			       (SELECT count(*) FROM sessions WHERE id=$1)`, sid).
			Scan(&stillAttached, &stillSessions); err != nil {
			t.Fatalf("recount: %v", err)
		}
		if stillAttached != attached || stillSessions != 1 {
			t.Errorf("the refused delete changed state: refresh %d->%d sessions=%d",
				attached, stillAttached, stillSessions)
		}
	})
}

// @ac AC-57
// AC-57: Bearer traffic is exempt from the idle window and bounded by the
// absolute deadline, evaluated in the database.
func TestBearer_ExemptFromIdleBoundedByAbsolute(t *testing.T) {
	t.Run("system-auth-identity/AC-57", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		idleWindow := func(uid uuid.UUID) (time.Time, time.Time) {
			var exp, seen time.Time
			if err := pool.QueryRow(ctx,
				`SELECT expires_at, last_seen FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`,
				uid).Scan(&exp, &seen); err != nil {
				t.Fatalf("read windows: %v", err)
			}
			return exp, seen
		}

		t.Run("past idle, inside absolute", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac57idle")
			if _, err := pool.Exec(ctx,
				`UPDATE sessions SET expires_at = now() - interval '1 hour'
				 WHERE user_id = $1`, li.u.ID); err != nil {
				t.Fatalf("age the idle window: %v", err)
			}
			expBefore, seenBefore := idleWindow(li.u.ID)
			if code := authMeBearer(t, url, li.accessToken); code != http.StatusOK {
				t.Errorf("status = %d, want 200: Bearer traffic is not bounded by the idle window", code)
			}
			expAfter, seenAfter := idleWindow(li.u.ID)
			if !expAfter.Equal(expBefore) || !seenAfter.Equal(seenBefore) {
				t.Error("the Bearer request advanced the idle window")
			}
		})

		t.Run("past absolute", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac57abs")
			if _, err := pool.Exec(ctx,
				`UPDATE sessions SET absolute_expires_at = now() - interval '1 minute'
				 WHERE user_id = $1`, li.u.ID); err != nil {
				t.Fatalf("age the absolute deadline: %v", err)
			}
			if code := authMeBearer(t, url, li.accessToken); code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 past the absolute deadline", code)
			}
			if reason := lastLoginFailureReason(t, pool); reason != "session_absolute_expired" {
				t.Errorf("audit reason = %q, want session_absolute_expired", reason)
			}
		})

		t.Run("fresh control", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac57fresh")
			expBefore, seenBefore := idleWindow(li.u.ID)
			if code := authMeBearer(t, url, li.accessToken); code != http.StatusOK {
				t.Errorf("status = %d, want 200", code)
			}
			expAfter, seenAfter := idleWindow(li.u.ID)
			if !expAfter.Equal(expBefore) || !seenAfter.Equal(seenBefore) {
				t.Error("a Bearer request advanced the idle window")
			}
		})
	})
}

var _ = users.NewService

// logoutWith sends a logout carrying the supplied cookies.
func logoutWith(t *testing.T, url string, session, refresh *http.Cookie) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/logout", nil)
	if session != nil {
		req.AddCookie(session)
	}
	if refresh != nil {
		req.AddCookie(refresh)
	}
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "test-csrf-token"})
	req.Header.Set("X-CSRF-Token", "test-csrf-token")
	resp := doReq(t, req)
	resp.Body.Close()
	return resp.StatusCode
}

// desyncedLineage logs in and then rotates ONCE on the body path. The
// body path does not rebind, so the live successor stays attached to the
// original session while the browser cookie still holds the consumed
// token. Without this the cookie path would have rebound the successor to
// a fresh session and the descendant case would be invisible.
func desyncedLineage(t *testing.T, url string, pool *pgxpool.Pool, name string) (loggedInUser, string, uuid.UUID) {
	t.Helper()
	li := loginFresh(t, url, pool, name)
	sid := sessionIDOf(t, pool, li.u.ID)
	code, _ := refreshBody(t, url, li.bodyRefresh)
	if code != http.StatusOK {
		t.Fatalf("precondition: the body rotation must succeed, got %d", code)
	}
	var live string
	if err := pool.QueryRow(context.Background(), `
		SELECT id::text FROM refresh_tokens
		WHERE user_id = $1 AND revoked_at IS NULL AND rotated_to_id IS NULL`,
		li.u.ID).Scan(&live); err != nil {
		t.Fatalf("find the live successor: %v", err)
	}
	var boundTo uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`SELECT session_id FROM refresh_tokens WHERE id = $1`, live).Scan(&boundTo); err != nil {
		t.Fatalf("read the successor's session: %v", err)
	}
	if boundTo != sid {
		t.Fatalf("precondition: the body path must NOT rebind; successor bound to %s, original %s", boundTo, sid)
	}
	return li, live, sid
}

func attachedLive(t *testing.T, pool *pgxpool.Pool, sid uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL`,
		sid).Scan(&n); err != nil {
		t.Fatalf("count attached: %v", err)
	}
	return n
}

// @ac AC-56
// AC-56: revoking a session makes its descendants unusable, in BOTH
// serialization orders, and logout takes the same per-user lock as the
// issuance paths. Other login families and service tokens are untouched.
func TestLogout_RevokesDescendantsUnderTheSameLock(t *testing.T) {
	t.Run("system-auth-identity/AC-56", func(t *testing.T) {
		t.Run("logout then refresh", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			ctx := context.Background()
			li, _, sid := desyncedLineage(t, url, pool, "ac56order1")

			// A second, independent login for the same user, and a
			// service token. Neither may be touched.
			second := loginFresh(t, url, pool, "ac56order1b")
			if _, err := pool.Exec(ctx, `
				INSERT INTO api_tokens (name, token_hash, prefix, role_id, created_by)
				VALUES ('ac56', $1, 'owk_ac56', 'viewer', $2)`,
				[]byte("ac56-token-hash-not-a-real-secret"), li.u.ID); err != nil {
				t.Fatalf("seed api token: %v", err)
			}

			if attachedLive(t, pool, sid) == 0 {
				t.Fatal("precondition: a live descendant must be attached to the session")
			}
			// The cookie carries the CONSUMED token, which is exactly the
			// case where revoking only the presented token misses.
			if code := logoutWith(t, url, li.sessionCookie, li.refreshCookie); code != http.StatusNoContent {
				t.Fatalf("logout = %d, want 204", code)
			}
			if n := attachedLive(t, pool, sid); n != 0 {
				t.Errorf("live descendants after logout = %d, want 0", n)
			}
			// And nothing the lineage holds can rotate afterwards.
			var liveToken string
			_ = pool.QueryRow(ctx, `
				SELECT count(*)::text FROM refresh_tokens
				WHERE user_id=$1 AND revoked_at IS NULL AND rotated_to_id IS NULL`,
				li.u.ID).Scan(&liveToken)
			if liveToken != "0" {
				t.Errorf("unconsumed live tokens for the user after logout = %s, want 0", liveToken)
			}

			// Preserved.
			if code := authMe(t, url, second.sessionCookie); code != http.StatusOK {
				t.Errorf("the second independent login was signed out too (%d)", code)
			}
			var tokensLive int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM api_tokens WHERE created_by=$1 AND revoked_at IS NULL`,
				li.u.ID).Scan(&tokensLive); err != nil {
				t.Fatalf("count tokens: %v", err)
			}
			if tokensLive != 1 {
				t.Errorf("service tokens live = %d, want 1 untouched", tokensLive)
			}
		})

		t.Run("refresh then logout", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			li, _, sid := desyncedLineage(t, url, pool, "ac56order2")

			// The lineage already rotated once on the body path inside
			// desyncedLineage, so the live successor predates the logout.
			if code := logoutWith(t, url, li.sessionCookie, li.refreshCookie); code != http.StatusNoContent {
				t.Fatalf("logout = %d, want 204", code)
			}
			if n := attachedLive(t, pool, sid); n != 0 {
				t.Errorf("live descendants after logout = %d, want 0", n)
			}
			// Nothing attached to that session authenticates or rotates.
			if code := authMe(t, url, li.sessionCookie); code != http.StatusUnauthorized {
				t.Errorf("the logged-out session cookie still authenticates (%d)", code)
			}
			if code := authMeBearer(t, url, li.accessToken); code != http.StatusUnauthorized {
				t.Errorf("an access token bound to the logged-out session still authenticates (%d)", code)
			}
		})

		t.Run("concurrent, logout blocked on the lock", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			ctx := context.Background()
			li, _, sid := desyncedLineage(t, url, pool, "ac56concurrent")

			// Hold the user row so the logout blocks on the per-user lock.
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			var one int
			if err := tx.QueryRow(ctx,
				`SELECT 1 FROM users WHERE id=$1 FOR NO KEY UPDATE`, li.u.ID).Scan(&one); err != nil {
				t.Fatalf("hold lock: %v", err)
			}
			done := make(chan int, 1)
			go func() { done <- logoutWith(t, url, li.sessionCookie, li.refreshCookie) }()
			if !waitForUserLockWaiter(t, pool) {
				t.Fatal("the logout never reached the per-user lock; it is not serialized with issuance")
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("release lock: %v", err)
			}
			if code := <-done; code != http.StatusNoContent {
				t.Errorf("logout = %d, want 204", code)
			}
			if n := attachedLive(t, pool, sid); n != 0 {
				t.Errorf("live descendants after a serialized logout = %d, want 0", n)
			}
		})
	})
}
