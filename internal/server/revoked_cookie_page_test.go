// @spec system-auth-identity
//
// OW-090, end to end through the real router, the embedded SPA and the
// real refresh-cookie endpoint. The browser sequence each test replays is
// what the SPA does on every load: GET the page, then GET /api/v1/auth/me
// (bootstrapAuth), and on a 401 POST /api/v1/auth/refresh-cookie once
// (client.ts onResponse), replaying /auth/me on success and routing to
// /login on failure.

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
)

type pageResult struct {
	status      int
	contentType string
	setCookies  []*http.Cookie
	errCode     string
}

func (p pageResult) deleted(name string) bool {
	for _, c := range p.setCookies {
		if c.Name == name && c.MaxAge < 0 && c.Value == "" {
			return true
		}
	}
	return false
}

func (p pageResult) set(name string) *http.Cookie {
	for _, c := range p.setCookies {
		if c.Name == name && c.Value != "" && c.MaxAge >= 0 {
			return &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	return nil
}

func browserReq(t *testing.T, method, url, path string, cookies ...*http.Cookie) pageResult {
	t.Helper()
	req, _ := http.NewRequest(method, url+path, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	resp := doReq(t, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	out := pageResult{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), setCookies: resp.Cookies()}
	if strings.HasPrefix(out.contentType, "application/json") {
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &env)
		out.errCode = env.Error.Code
	}
	return out
}

// pageLoads asserts the SPA and sign-in page load and set no cookie.
func pageLoads(t *testing.T, url string, cookies ...*http.Cookie) {
	t.Helper()
	for _, path := range []string{"/login", "/", "/hosts"} {
		got := browserReq(t, http.MethodGet, url, path, cookies...)
		if got.status != http.StatusOK || !strings.HasPrefix(got.contentType, "text/html") {
			t.Errorf("GET %s = %d %q, want 200 text/html (errCode %q)", path, got.status, got.contentType, got.errCode)
		}
		if len(got.setCookies) != 0 {
			t.Errorf("GET %s touched cookies %v; a page load must leave them to the refresh path", path, got.setCookies)
		}
	}
}

// @ac AC-96
// AC-96: an idle-expired session with a live refresh token whose absolute
// deadline has not passed ends in a working session with no new sign-in:
// the page loads and keeps the refresh cookie, /auth/me answers the 401
// the client refreshes on, refresh-cookie mints a new session, and
// /auth/me succeeds with it. Past the absolute deadline the same sequence
// is refused and ends at sign-in (C-28).
func TestExpiredSession_LiveRefresh_PageLoadThenRefreshRecovers(t *testing.T) {
	t.Run("system-auth-identity/AC-96", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		li := loginFresh(t, url, pool, "ow090idle")
		ago := time.Now().UTC().Add(-time.Minute)
		if _, err := pool.Exec(ctx,
			`UPDATE sessions SET expires_at = $1 WHERE user_id = $2`, ago, li.u.ID); err != nil {
			t.Fatalf("idle-expire the session: %v", err)
		}
		var absFuture bool
		if err := pool.QueryRow(ctx,
			`SELECT bool_and(absolute_expires_at > now()) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`,
			li.u.ID).Scan(&absFuture); err != nil || !absFuture {
			t.Fatalf("precondition: the refresh token's absolute deadline must be in the future (ok=%v err=%v)", absFuture, err)
		}

		pageLoads(t, url, li.sessionCookie, li.refreshCookie)

		me := browserReq(t, http.MethodGet, url, "/api/v1/auth/me", li.sessionCookie, li.refreshCookie)
		if me.status != http.StatusUnauthorized || me.errCode != "auth.session_invalid" {
			t.Fatalf("GET /auth/me with the expired session = %d %q, want 401 auth.session_invalid", me.status, me.errCode)
		}

		ref := browserReq(t, http.MethodPost, url, "/api/v1/auth/refresh-cookie", li.refreshCookie)
		if ref.status != http.StatusOK {
			t.Fatalf("refresh-cookie with the live refresh token = %d %q, want 200", ref.status, ref.errCode)
		}
		newSession := ref.set(identity.SessionCookieName)
		if newSession == nil || ref.set(identity.RefreshCookieName) == nil {
			t.Fatalf("refresh-cookie did not set a new session and refresh cookie: %v", ref.setCookies)
		}
		if again := browserReq(t, http.MethodGet, url, "/api/v1/auth/me", newSession); again.status != http.StatusOK {
			t.Errorf("GET /auth/me with the refreshed session = %d %q, want 200", again.status, again.errCode)
		}

		// Past the absolute deadline the refresh is refused (C-28) and the
		// cookies are cleared, so the client routes to sign-in.
		late := loginFresh(t, url, pool, "ow090absolute")
		if _, err := pool.Exec(ctx,
			`UPDATE sessions SET expires_at = $1, absolute_expires_at = $1 WHERE user_id = $2`, ago, late.u.ID); err != nil {
			t.Fatalf("expire session: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE refresh_tokens SET absolute_expires_at = $1 WHERE user_id = $2`, ago, late.u.ID); err != nil {
			t.Fatalf("pass the absolute deadline: %v", err)
		}
		pageLoads(t, url, late.sessionCookie, late.refreshCookie)
		lateRef := browserReq(t, http.MethodPost, url, "/api/v1/auth/refresh-cookie", late.refreshCookie)
		if lateRef.status == http.StatusOK {
			t.Errorf("refresh-cookie past the absolute deadline = 200, want a refusal")
		}
		if !lateRef.deleted(identity.SessionCookieName) || !lateRef.deleted(identity.RefreshCookieName) {
			t.Errorf("a refused refresh must clear both cookies; got %v", lateRef.setCookies)
		}
	})
}

// @ac AC-94
// AC-94 end to end: revoked session and revoked refresh token, as
// migration 0065 or a logout leaves them. The page loads, /auth/me is
// refused, the refresh is refused and clears both cookies, and the
// cookie-less sign-in page then loads with /auth/me answering 401 and a
// refresh refused, so the client stays on /login with no loop.
func TestRevokedCookies_CannotBlockTheSPAOrSignIn(t *testing.T) {
	t.Run("system-auth-identity/AC-94", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ow090pages")

		if _, err := pool.Exec(ctx,
			`UPDATE sessions SET revoked_at = now() WHERE user_id = $1`, li.u.ID); err != nil {
			t.Fatalf("revoke sessions: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1`, li.u.ID); err != nil {
			t.Fatalf("revoke refresh tokens: %v", err)
		}

		pageLoads(t, url, li.sessionCookie, li.refreshCookie)

		me := browserReq(t, http.MethodGet, url, "/api/v1/auth/me", li.sessionCookie, li.refreshCookie)
		if me.status != http.StatusUnauthorized || me.errCode != "auth.session_invalid" {
			t.Errorf("GET /auth/me with the revoked session = %d %q, want 401 auth.session_invalid", me.status, me.errCode)
		}
		ref := browserReq(t, http.MethodPost, url, "/api/v1/auth/refresh-cookie", li.refreshCookie)
		if ref.status == http.StatusOK {
			t.Fatalf("refresh-cookie accepted a revoked refresh token")
		}
		if !ref.deleted(identity.SessionCookieName) || !ref.deleted(identity.RefreshCookieName) {
			t.Errorf("the refused refresh must clear both cookies; got %v", ref.setCookies)
		}

		// After the client routes to /login the browser holds no auth cookie.
		pageLoads(t, url)
		bare := browserReq(t, http.MethodGet, url, "/api/v1/auth/me")
		if bare.status != http.StatusUnauthorized {
			t.Errorf("GET /auth/me with no cookie = %d, want 401", bare.status)
		}
		if again := browserReq(t, http.MethodPost, url, "/api/v1/auth/refresh-cookie"); again.status == http.StatusOK {
			t.Errorf("refresh-cookie with no cookie = 200; the client would not settle on /login")
		}
	})
}

// @ac AC-97
// AC-97: a session cookie of a disabled or soft-deleted account. The page
// loads anonymously, and /auth/me and the refresh are refused. Covered
// both through the service (which also revokes credentials, C-36) and by
// setting the account state alone, so the binder's own account-state
// check (C-31) is what refuses.
func TestDisabledOrDeletedAccount_PageLoadsAPIAndRefreshRefused(t *testing.T) {
	t.Run("system-auth-identity/AC-97", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		for _, tc := range []struct {
			name string
			act  func(li loggedInUser)
		}{
			{"disabled via the service", func(li loggedInUser) {
				if err := svc.Disable(ctx, li.u.ID); err != nil {
					t.Fatalf("disable: %v", err)
				}
			}},
			{"soft-deleted via the service", func(li loggedInUser) {
				if err := svc.SoftDelete(ctx, li.u.ID); err != nil {
					t.Fatalf("soft delete: %v", err)
				}
			}},
			{"disabled_at set with credentials still live", func(li loggedInUser) {
				if _, err := pool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, li.u.ID); err != nil {
					t.Fatalf("set disabled_at: %v", err)
				}
			}},
			{"deleted_at set with credentials still live", func(li loggedInUser) {
				if _, err := pool.Exec(ctx, `UPDATE users SET deleted_at = now() WHERE id = $1`, li.u.ID); err != nil {
					t.Fatalf("set deleted_at: %v", err)
				}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, "ow090acct"+strings.ReplaceAll(strings.Fields(tc.name)[0], "_", ""))
				tc.act(li)

				pageLoads(t, url, li.sessionCookie, li.refreshCookie)
				me := browserReq(t, http.MethodGet, url, "/api/v1/auth/me", li.sessionCookie, li.refreshCookie)
				if me.status != http.StatusUnauthorized || me.errCode != "auth.session_invalid" {
					t.Errorf("GET /auth/me = %d %q, want 401 auth.session_invalid", me.status, me.errCode)
				}
				ref := browserReq(t, http.MethodPost, url, "/api/v1/auth/refresh-cookie", li.refreshCookie)
				if ref.status == http.StatusOK {
					t.Errorf("refresh-cookie minted a session for a %s account", tc.name)
					if s := ref.set(identity.SessionCookieName); s != nil {
						if m := browserReq(t, http.MethodGet, url, "/api/v1/auth/me", s); m.status == http.StatusOK {
							t.Errorf("and that session authenticates")
						}
					}
				}
			})
		}
	})
}

// @ac AC-95
// AC-95 end to end: a live session still loads pages with no cookie
// touched, reads the API, refreshes, logs out, and afterwards the API
// refuses the logged-out cookie while the sign-in page still loads.
func TestRevokedCookies_APIStillRefusesAndCredentialPathsHold(t *testing.T) {
	t.Run("system-auth-identity/AC-95", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		live := loginFresh(t, url, pool, "ow090live")
		pageLoads(t, url, live.sessionCookie, live.refreshCookie)
		if code := authMe(t, url, live.sessionCookie); code != http.StatusOK {
			t.Errorf("GET /api/v1/auth/me with a live session = %d, want 200", code)
		}
		if got := browserReq(t, http.MethodGet, url, "/api/v1/hosts", live.sessionCookie); got.status != http.StatusOK {
			t.Errorf("GET /api/v1/hosts with a live session = %d %q, want 200", got.status, got.errCode)
		}
		ref := browserReq(t, http.MethodPost, url, "/api/v1/auth/refresh-cookie", live.refreshCookie)
		if ref.status != http.StatusOK {
			t.Errorf("refresh-cookie with a live refresh token = %d, want 200", ref.status)
		}
		session := ref.set(identity.SessionCookieName)
		if session == nil {
			t.Fatalf("refresh-cookie set no new session: %v", ref.setCookies)
		}

		lo := browserReq(t, http.MethodPost, url, "/api/v1/auth/logout", session, ref.set(identity.RefreshCookieName))
		if lo.status != http.StatusNoContent {
			t.Errorf("logout = %d, want 204", lo.status)
		}
		if !lo.deleted(identity.SessionCookieName) || !lo.deleted(identity.RefreshCookieName) {
			t.Errorf("logout must clear both cookies; got %v", lo.setCookies)
		}
		for _, path := range []string{"/api/v1/auth/me", "/api/v1/hosts"} {
			got := browserReq(t, http.MethodGet, url, path, session)
			if got.status != http.StatusUnauthorized || got.errCode != "auth.session_invalid" {
				t.Errorf("GET %s with the logged-out session = %d %q, want 401 auth.session_invalid", path, got.status, got.errCode)
			}
		}
		pageLoads(t, url, session)
	})
}
