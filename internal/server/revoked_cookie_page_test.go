// @spec system-auth-identity
//
// OW-090, end to end through the real router and the embedded SPA: after
// an upgrade revokes every session (migration 0065), a browser that still
// holds the dead cookies must be able to load the sign-in page, while the
// protected API keeps refusing the dead session. Login, logout and the
// refresh-cookie path are checked around it.

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/identity"
)

type pageResult struct {
	status      int
	contentType string
	cleared     map[string]bool
	errCode     string
}

func getWithCookies(t *testing.T, url, path string, cookies ...*http.Cookie) pageResult {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url+path, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := doReq(t, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	out := pageResult{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), cleared: map[string]bool{}}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 && c.Value == "" {
			out.cleared[c.Name] = true
		}
	}
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

// @ac AC-94
// AC-94 end to end: revoked cookies on the SPA and the sign-in page get the
// page and a response that deletes both auth cookies.
func TestRevokedCookies_CannotBlockTheSPAOrSignIn(t *testing.T) {
	t.Run("system-auth-identity/AC-94", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		li := loginFresh(t, url, pool, "ow090pages")

		// What migration 0065 does to every live credential.
		if _, err := pool.Exec(ctx,
			`UPDATE sessions SET revoked_at = now() WHERE user_id = $1`, li.u.ID); err != nil {
			t.Fatalf("revoke sessions: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1`, li.u.ID); err != nil {
			t.Fatalf("revoke refresh tokens: %v", err)
		}

		for _, path := range []string{"/login", "/", "/hosts"} {
			got := getWithCookies(t, url, path, li.sessionCookie, li.refreshCookie)
			if got.status != http.StatusOK || !strings.HasPrefix(got.contentType, "text/html") {
				t.Errorf("GET %s with revoked cookies = %d %q, want 200 text/html (errCode %q)",
					path, got.status, got.contentType, got.errCode)
			}
			for _, name := range []string{identity.SessionCookieName, identity.RefreshCookieName} {
				if !got.cleared[name] {
					t.Errorf("GET %s did not delete %s", path, name)
				}
			}
		}
	})
}

// @ac AC-95
// AC-95 end to end: the protected API still refuses the revoked session,
// the refresh-cookie path refuses the revoked refresh token, and a live
// session still works, logs out, and after logout can still load sign-in.
func TestRevokedCookies_APIStillRefusesAndCredentialPathsHold(t *testing.T) {
	t.Run("system-auth-identity/AC-95", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		dead := loginFresh(t, url, pool, "ow090api")
		if _, err := pool.Exec(ctx,
			`UPDATE sessions SET revoked_at = now() WHERE user_id = $1`, dead.u.ID); err != nil {
			t.Fatalf("revoke sessions: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1`, dead.u.ID); err != nil {
			t.Fatalf("revoke refresh tokens: %v", err)
		}
		for _, path := range []string{"/api/v1/auth/me", "/api/v1/hosts"} {
			got := getWithCookies(t, url, path, dead.sessionCookie, dead.refreshCookie)
			if got.status != http.StatusUnauthorized || got.errCode != "auth.session_invalid" {
				t.Errorf("GET %s with a revoked session = %d %q, want 401 auth.session_invalid",
					path, got.status, got.errCode)
			}
		}

		// The refresh-cookie path refuses a revoked refresh token and
		// deletes the cookies, so the browser stops presenting them.
		req, _ := http.NewRequest(http.MethodPost, url+"/api/v1/auth/refresh-cookie", nil)
		req.AddCookie(dead.refreshCookie)
		resp := doReq(t, req)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("refresh-cookie accepted a revoked refresh token")
		}

		// A live session: the page loads with no cookie deletion, the API
		// answers, refresh works, and logout ends it.
		live := loginFresh(t, url, pool, "ow090live")
		if got := getWithCookies(t, url, "/login", live.sessionCookie); got.status != http.StatusOK || len(got.cleared) != 0 {
			t.Errorf("GET /login with a live session = %d, cleared %v; want 200 and nothing deleted", got.status, got.cleared)
		}
		if code := authMe(t, url, live.sessionCookie); code != http.StatusOK {
			t.Errorf("GET /api/v1/auth/me with a live session = %d, want 200", code)
		}
		rreq, _ := http.NewRequest(http.MethodPost, url+"/api/v1/auth/refresh-cookie", nil)
		rreq.AddCookie(live.refreshCookie)
		rresp := doReq(t, rreq)
		_, _ = io.Copy(io.Discard, rresp.Body)
		rresp.Body.Close()
		if rresp.StatusCode != http.StatusOK {
			t.Errorf("refresh-cookie with a live refresh token = %d, want 200", rresp.StatusCode)
		}

		lreq, _ := http.NewRequest(http.MethodPost, url+"/api/v1/auth/logout", nil)
		lreq.AddCookie(live.sessionCookie)
		lresp := doReq(t, lreq)
		_, _ = io.Copy(io.Discard, lresp.Body)
		lresp.Body.Close()
		if lresp.StatusCode != http.StatusNoContent {
			t.Errorf("logout = %d, want 204", lresp.StatusCode)
		}
		if code := authMe(t, url, live.sessionCookie); code != http.StatusUnauthorized {
			t.Errorf("GET /api/v1/auth/me after logout = %d, want 401", code)
		}
		// A browser that kept the logged-out cookie can still reach sign-in.
		if got := getWithCookies(t, url, "/login", live.sessionCookie); got.status != http.StatusOK {
			t.Errorf("GET /login with the logged-out cookie = %d %q, want 200", got.status, got.errCode)
		}
	})
}
