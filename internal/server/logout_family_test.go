// @spec system-auth-identity
//
// Logout family resolution (C-41): session-only anchors, idle-expired
// anchors, conflicting cookies, atomic rollback, and enforced isolation.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// logoutAuditDetail polls for the newest auth.logout row for a user and
// returns its raw detail. It waits until the reading stops changing,
// because the audit writer batches.
func logoutAuditDetail(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) (map[string]any, string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last, stable := "", 0
	for {
		var raw string
		err := pool.QueryRow(context.Background(), `
			SELECT COALESCE(detail::text, '') FROM audit_events
			WHERE action = 'auth.logout' AND (resource_id = $1 OR actor_id = $1)
			ORDER BY occurred_at DESC, id DESC LIMIT 1`, uid.String()).Scan(&raw)
		if err != nil {
			raw = ""
		}
		if raw == last && raw != "" {
			stable++
			if stable >= 2 {
				var m map[string]any
				_ = json.Unmarshal([]byte(raw), &m)
				return m, raw
			}
		} else {
			stable, last = 0, raw
		}
		if time.Now().After(deadline) {
			var m map[string]any
			_ = json.Unmarshal([]byte(last), &m)
			return m, last
		}
	}
}

// @ac AC-63
// AC-63: a session cookie ALONE locates and ends a rebound family.
func TestLogout_SessionCookieAloneEndsAReboundFamily(t *testing.T) {
	t.Run("system-auth-identity/AC-63", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		for _, tc := range []struct {
			name string
			user string
			pick func(old, rebound *http.Cookie) *http.Cookie
		}{
			{"pre-rotation session cookie only", "ac63old",
				func(old, _ *http.Cookie) *http.Cookie { return old }},
			{"post-rotation session cookie only", "ac63new",
				func(_, rebound *http.Cookie) *http.Cookie { return rebound }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, tc.user)
				code, rebound, _ := refreshCookieBoth(t, url, li.refreshCookie)
				if code != http.StatusOK || rebound == nil {
					t.Fatalf("precondition: refresh = %d", code)
				}
				if lc := logoutWith(t, url, tc.pick(li.sessionCookie, rebound), nil); lc != http.StatusNoContent {
					t.Fatalf("logout = %d, want 204", lc)
				}
				if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
					t.Errorf("live sessions=%d refresh=%d, want 0/0 with no refresh cookie presented", s, r)
				}
			})
		}
	})
}

// @ac AC-64
// AC-64: an idle-expired session cookie ALONE ends its family, including
// the still-valid Bearer credentials bound to it, and authorizes nothing
// else.
func TestLogout_IdleExpiredSessionCookieAloneEndsBearerCredentials(t *testing.T) {
	t.Run("system-auth-identity/AC-64", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ac64user")
		if _, err := pool.Exec(ctx,
			`UPDATE sessions SET expires_at = now() - interval '1 hour' WHERE user_id = $1`,
			li.u.ID); err != nil {
			t.Fatalf("age the idle window: %v", err)
		}

		// The Bearer credential works BEFORE the logout, so the refusal
		// afterwards is attributable to the logout.
		if code := authMeBearer(t, url, li.accessToken); code != http.StatusOK {
			t.Fatalf("precondition: bound Bearer token = %d, want 200", code)
		}
		// And the expired cookie authorizes nothing on a protected route.
		if code := authMe(t, url, li.sessionCookie); code != http.StatusUnauthorized {
			t.Errorf("the idle-expired cookie authorized a protected request (%d)", code)
		}

		if lc := logoutWith(t, url, li.sessionCookie, nil); lc != http.StatusNoContent {
			t.Fatalf("logout = %d, want 204", lc)
		}
		if code := authMeBearer(t, url, li.accessToken); code != http.StatusUnauthorized {
			t.Errorf("bound Bearer token after logout = %d, want 401", code)
		}
		if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
			t.Errorf("live sessions=%d refresh=%d, want 0/0", s, r)
		}
	})
}

// @ac AC-65
// AC-65: when the two cookies name DIFFERENT families, only the session
// cookie's family is revoked, and the disagreement is recorded without
// any credential value.
func TestLogout_ConflictingCookiesRevokeOnlyTheSessionFamily(t *testing.T) {
	t.Run("system-auth-identity/AC-65", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		a := loginFresh(t, url, pool, "ac65user")
		respB := login(t, url, map[string]string{"username": a.u.Username, "password": a.u.Password})
		b := collectLogin(t, respB)
		if b.sessionCookie == nil || b.refreshCookie == nil {
			t.Fatal("the second login returned no cookies")
		}
		aSession := sessionIDOf(t, pool, a.u.ID)
		_ = aSession

		// A's session cookie with B's refresh cookie.
		if lc := logoutWith(t, url, a.sessionCookie, b.refreshCookie); lc != http.StatusNoContent {
			t.Fatalf("logout = %d, want 204", lc)
		}

		// Counted BEFORE family B refreshes below: a cookie refresh mints
		// a new session (the separate session-continuity issue), which
		// would make this count 2 for a reason unrelated to logout.
		var b1 int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`,
			a.u.ID).Scan(&b1); err != nil {
			t.Fatalf("count: %v", err)
		}
		if b1 != 1 {
			t.Errorf("live sessions for the user = %d, want exactly 1 (family B)", b1)
		}
		if code := authMe(t, url, a.sessionCookie); code != http.StatusUnauthorized {
			t.Errorf("family A still authenticates (%d)", code)
		}
		if code := authMe(t, url, b.sessionCookie); code != http.StatusOK {
			t.Errorf("family B was signed out (%d): the refresh cookie's family must be untouched", code)
		}
		if code, sess, _ := refreshCookieBoth(t, url, b.refreshCookie); code != http.StatusOK || sess == nil {
			t.Errorf("family B can no longer refresh (%d)", code)
		}

		detail, raw := logoutAuditDetail(t, pool, a.u.ID)
		if detail["target_conflict"] != true {
			t.Errorf("audit target_conflict = %v, want true (detail %s)", detail["target_conflict"], raw)
		}
		if detail["anchor"] != "session" {
			t.Errorf("audit anchor = %v, want session", detail["anchor"])
		}
		for _, credential := range []string{a.sessionCookie.Value, b.refreshCookie.Value} {
			if credential != "" && containsFold(raw, credential) {
				t.Error("the audit detail carries a credential value")
			}
		}
	})
}

// @ac AC-66
// AC-66: a failure during the family sweep rolls back EVERY revocation.
func TestLogout_SweepFailureRollsBackEverything(t *testing.T) {
	t.Run("system-auth-identity/AC-66", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ac66user")
		code, rebound, newRefresh := refreshCookieBoth(t, url, li.refreshCookie)
		if code != http.StatusOK || rebound == nil {
			t.Fatalf("precondition: refresh = %d", code)
		}
		beforeS, beforeR := liveCounts(t, pool, li.u.ID)
		if beforeS < 2 || beforeR < 1 {
			t.Fatalf("precondition: a two-session family, got sessions=%d refresh=%d", beforeS, beforeR)
		}

		// The session revocation runs first; the refresh revocation fails.
		restore := failOnWrite(t, pool, "refresh_tokens", "UPDATE")
		lc := logoutWith(t, url, rebound, newRefresh)
		restore()

		if lc != http.StatusInternalServerError {
			t.Errorf("logout = %d, want 500 auth.logout_incomplete", lc)
		}
		afterS, afterR := liveCounts(t, pool, li.u.ID)
		if afterS != beforeS || afterR != beforeR {
			t.Errorf("a failed sweep changed state: sessions %d->%d refresh %d->%d",
				beforeS, afterS, beforeR, afterR)
		}
		_ = ctx
	})
}

// @ac AC-67
// AC-67: isolation is ENFORCED during traversal. A cross-user link makes
// logout revoke nothing; a rotation cycle terminates within the family.
func TestLogout_EnforcesFamilyIsolation(t *testing.T) {
	t.Run("system-auth-identity/AC-67", func(t *testing.T) {
		t.Run("cross-user link", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			ctx := context.Background()
			mine := loginFresh(t, url, pool, "ac67mine")
			other := loginFresh(t, url, pool, "ac67other")

			// Point my refresh row at the other user's refresh row.
			if _, err := pool.Exec(ctx, `
				UPDATE refresh_tokens SET rotated_to_id =
				  (SELECT id FROM refresh_tokens WHERE user_id = $2 LIMIT 1)
				WHERE user_id = $1`, mine.u.ID, other.u.ID); err != nil {
				t.Fatalf("plant cross-user link: %v", err)
			}
			beforeS, beforeR := liveCounts(t, pool, mine.u.ID)

			lc := logoutWith(t, url, mine.sessionCookie, nil)
			if lc != http.StatusInternalServerError {
				t.Errorf("logout over inconsistent links = %d, want 500 (revoke nothing, report it)", lc)
			}
			if s, r := liveCounts(t, pool, mine.u.ID); s != beforeS || r != beforeR {
				t.Errorf("an inconsistent family was partly revoked: sessions %d->%d refresh %d->%d",
					beforeS, s, beforeR, r)
			}
			if code := authMe(t, url, other.sessionCookie); code != http.StatusOK {
				t.Errorf("the other user was signed out (%d)", code)
			}
		})

		t.Run("rotation cycle", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			ctx := context.Background()
			li := loginFresh(t, url, pool, "ac67cycle")
			code, rebound, _ := refreshCookieBoth(t, url, li.refreshCookie)
			if code != http.StatusOK || rebound == nil {
				t.Fatalf("precondition: refresh = %d", code)
			}
			bystander := loginFresh(t, url, pool, "ac67bystander")

			// Close the chain into a cycle: the successor points back.
			if _, err := pool.Exec(ctx, `
				UPDATE refresh_tokens r SET rotated_to_id = p.id
				FROM refresh_tokens p
				WHERE p.rotated_to_id = r.id AND r.user_id = $1`, li.u.ID); err != nil {
				t.Fatalf("plant cycle: %v", err)
			}

			done := make(chan int, 1)
			go func() { done <- logoutWith(t, url, rebound, nil) }()
			select {
			case lc := <-done:
				if lc != http.StatusNoContent {
					t.Errorf("logout over a cycle = %d, want 204", lc)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("logout did not terminate on a rotation cycle")
			}
			if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
				t.Errorf("family after logout: sessions=%d refresh=%d, want 0/0", s, r)
			}
			if code := authMe(t, url, bystander.sessionCookie); code != http.StatusOK {
				t.Errorf("an unrelated user was signed out (%d)", code)
			}
		})
	})
}
