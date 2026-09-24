// @spec system-auth-identity
//
// FAILING BY DESIGN. These four criteria describe required behavior that
// this branch does NOT yet provide. They are committed red on purpose, so
// the gap is visible in CI rather than described in a comment, and they
// stay red until the rebound-lineage decision is made.
//
// What they are about: targeted logout is supposed to end one login
// family. Two mechanisms defeat it today.
//
//   - The cookie path REBINDS each rotated successor to the new session
//     it mints, so the family's live credential moves to a session the
//     logout never names. Revoking the named session then reaches
//     nothing.
//   - Logout only revokes a session that VerifySession accepts, so an
//     IDLE-EXPIRED session is never revoked. Combined with Bearer traffic
//     being exempt from the idle window (C-38), a token bound to that
//     session keeps authenticating after a logout that answered 204.

package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func liveCounts(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) (sessions, refresh int) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL),
		       (SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND revoked_at IS NULL)`,
		uid).Scan(&sessions, &refresh); err != nil {
		t.Fatalf("live counts: %v", err)
	}
	return
}

// @ac AC-59
// AC-59: a targeted logout ends the family even when the cookie path has
// REBOUND its live successor to a session the logout does not name.
//
// Measured on this branch: live sessions 1, live refresh 1, and the
// rebound session still answers /auth/me with 200.
func TestLogout_ReachesCookieReboundDescendants(t *testing.T) {
	t.Run("system-auth-identity/AC-59", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		li := loginFresh(t, url, pool, "ac59user")
		oldSession, oldRefresh := li.sessionCookie, li.refreshCookie

		// One cookie refresh: the successor is rebound to a NEW session.
		code, rebound := refreshCookie(t, url, li.refreshCookie)
		if code != http.StatusOK || rebound == nil {
			t.Fatalf("precondition: the cookie refresh must succeed, got %d", code)
		}

		// Log out presenting what the client held BEFORE that rotation.
		if lc := logoutWith(t, url, oldSession, oldRefresh); lc != http.StatusNoContent {
			t.Fatalf("logout = %d, want 204", lc)
		}

		sessions, refresh := liveCounts(t, pool, li.u.ID)
		if sessions != 0 {
			t.Errorf("live sessions after logout = %d, want 0: the rebound session escaped the targeted logout", sessions)
		}
		if refresh != 0 {
			t.Errorf("live refresh tokens after logout = %d, want 0: the rebound successor escaped", refresh)
		}
		if got := authMe(t, url, rebound); got != http.StatusUnauthorized {
			t.Errorf("the rebound session still authenticates after logout (%d), want 401", got)
		}
	})
}

// @ac AC-60
// AC-60: both ACTUAL orderings of a real refresh against a real logout
// end the family. Neither order may leave a usable credential.
func TestLogoutAndRefresh_BothActualOrderings(t *testing.T) {
	t.Run("system-auth-identity/AC-60", func(t *testing.T) {
		t.Run("refresh commits, then logout", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			li := loginFresh(t, url, pool, "ac60a")
			code, rebound, newRefresh := refreshCookieBoth(t, url, li.refreshCookie)
			if code != http.StatusOK || rebound == nil || newRefresh == nil {
				t.Fatalf("precondition: refresh = %d (session=%v refresh=%v)", code, rebound != nil, newRefresh != nil)
			}
			// The client logs out with exactly what it now holds.
			if lc := logoutWith(t, url, rebound, newRefresh); lc != http.StatusNoContent {
				t.Fatalf("logout = %d, want 204", lc)
			}
			if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
				t.Errorf("after refresh-then-logout: live sessions=%d refresh=%d, want 0/0", s, r)
			}
		})

		t.Run("logout commits, then refresh", func(t *testing.T) {
			url, pool := freshAPIServer(t)
			li := loginFresh(t, url, pool, "ac60b")
			if lc := logoutWith(t, url, li.sessionCookie, li.refreshCookie); lc != http.StatusNoContent {
				t.Fatalf("logout = %d, want 204", lc)
			}
			// Nothing the client held may rotate afterwards, on either path.
			if code, _ := refreshBody(t, url, li.bodyRefresh); code == http.StatusOK {
				t.Error("the body path rotated after a logout")
			}
			if code, sess := refreshCookie(t, url, li.refreshCookie); code == http.StatusOK || sess != nil {
				t.Errorf("the cookie path rotated after a logout (%d, session=%v)", code, sess != nil)
			}
			if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
				t.Errorf("after logout-then-refresh: live sessions=%d refresh=%d, want 0/0", s, r)
			}
		})
	})
}

// @ac AC-61
// AC-61: a targeted logout ends ONE family. A second, independent login
// belonging to the SAME user keeps working, and so does that user's
// service-account token.
//
// This is the guard on whatever fix reaches rebound descendants: a fix
// that revokes by user_id would satisfy AC-59 and AC-60 and break this.
func TestLogout_LeavesTheUsersOtherLoginFamilyAlone(t *testing.T) {
	t.Run("system-auth-identity/AC-61", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		first := loginFresh(t, url, pool, "ac61user")

		// A second login for the SAME user, by signing in again.
		resp := login(t, url, map[string]string{"username": first.u.Username, "password": first.u.Password})
		second := collectLogin(t, resp)
		if second.sessionCookie == nil {
			t.Fatal("the second login returned no session cookie")
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO api_tokens (name, token_hash, prefix, role_id, created_by)
			VALUES ('ac61', $1, 'owk_ac61', 'viewer', $2)`,
			[]byte("ac61-token-hash-not-a-real-secret"), first.u.ID); err != nil {
			t.Fatalf("seed api token: %v", err)
		}

		// Rotate the FIRST family on the cookie path so it is rebound.
		if code, _ := refreshCookie(t, url, first.refreshCookie); code != http.StatusOK {
			t.Fatalf("precondition: refresh = %d", code)
		}
		if lc := logoutWith(t, url, first.sessionCookie, first.refreshCookie); lc != http.StatusNoContent {
			t.Fatalf("logout = %d, want 204", lc)
		}

		if got := authMe(t, url, second.sessionCookie); got != http.StatusOK {
			t.Errorf("the SECOND login was signed out by the first's logout (%d), want 200", got)
		}
		var tokensLive int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM api_tokens WHERE created_by=$1 AND revoked_at IS NULL`,
			first.u.ID).Scan(&tokensLive); err != nil {
			t.Fatalf("count tokens: %v", err)
		}
		if tokensLive != 1 {
			t.Errorf("service tokens live = %d, want 1 untouched", tokensLive)
		}
	})
}

// @ac AC-62
// AC-62: logout revokes the session it names even when that session is
// IDLE-EXPIRED, and ends its family.
//
// Measured on this branch: the logout answers 204 having revoked nothing
// (live sessions 1, revoked 0), and a Bearer token bound to that session
// still authenticates, because C-38 exempts Bearer traffic from the idle
// window while logout only revokes sessions VerifySession accepts.
func TestLogout_RevokesAnIdleExpiredSession(t *testing.T) {
	t.Run("system-auth-identity/AC-62", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ac62user")

		if _, err := pool.Exec(ctx,
			`UPDATE sessions SET expires_at = now() - interval '1 hour' WHERE user_id = $1`,
			li.u.ID); err != nil {
			t.Fatalf("age the idle window: %v", err)
		}

		if lc := logoutWith(t, url, li.sessionCookie, li.refreshCookie); lc != http.StatusNoContent {
			t.Fatalf("logout = %d, want 204", lc)
		}

		var revoked int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NOT NULL`,
			li.u.ID).Scan(&revoked); err != nil {
			t.Fatalf("count revoked: %v", err)
		}
		if revoked == 0 {
			t.Error("the idle-expired session was not revoked; logout answered 204 having revoked nothing")
		}
		if s, r := liveCounts(t, pool, li.u.ID); s != 0 || r != 0 {
			t.Errorf("after logout: live sessions=%d refresh=%d, want 0/0", s, r)
		}
		if got := authMeBearer(t, url, li.accessToken); got != http.StatusUnauthorized {
			t.Errorf("a Bearer token bound to the logged-out session still authenticates (%d), want 401", got)
		}
	})
}

// collectLogin reads the credentials out of a login response.
func collectLogin(t *testing.T, resp *http.Response) loggedInUser {
	t.Helper()
	defer resp.Body.Close()
	var out loggedInUser
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "openwatch_session":
			out.sessionCookie = &http.Cookie{Name: c.Name, Value: c.Value}
		case "openwatch_refresh":
			out.refreshCookie = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	return out
}

// refreshCookieBoth performs a cookie refresh and returns BOTH cookies
// the response set, which is what the browser then holds. The existing
// refreshCookie helper returns only the session cookie, and logging out
// without the new refresh cookie would understate what a real client
// presents.
func refreshCookieBoth(t *testing.T, url string, rc *http.Cookie) (int, *http.Cookie, *http.Cookie) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/refresh-cookie", nil)
	req.AddCookie(rc)
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "test-csrf-token"})
	req.Header.Set("X-CSRF-Token", "test-csrf-token")
	resp := doReq(t, req)
	defer resp.Body.Close()
	var sess, refresh *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Value == "" {
			continue
		}
		switch c.Name {
		case "openwatch_session":
			sess = &http.Cookie{Name: c.Name, Value: c.Value}
		case "openwatch_refresh":
			refresh = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	return resp.StatusCode, sess, refresh
}
