// @spec system-auth-identity
//
// Logout's two boundaries: CSRF when cookies select the target (C-42),
// and a truthful answer when the revocation's commit outcome is unknown
// (C-37, C-40).

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/jackc/pgx/v5"
)

type logoutResult struct {
	status    int
	code      string
	retryable bool
	human     string
	cookies   []*http.Cookie
}

// logoutCSRF sends a logout with the given credential cookies and a CSRF
// state: "missing" sends the XSRF cookie and no header, "mismatched"
// sends a header that differs, "valid" sends a matching pair.
func logoutCSRF(t *testing.T, url string, session, refresh *http.Cookie, csrf, authz string) logoutResult {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/v1/auth/logout", nil)
	if session != nil {
		req.AddCookie(session)
	}
	if refresh != nil {
		req.AddCookie(refresh)
	}
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "csrf-token-under-test"})
	switch csrf {
	case "valid":
		req.Header.Set("X-CSRF-Token", "csrf-token-under-test")
	case "mismatched":
		req.Header.Set("X-CSRF-Token", "a-different-token")
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp := doReq(t, req)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env struct {
		Error struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
			Human     string `json:"human_message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return logoutResult{
		status: resp.StatusCode, code: env.Error.Code,
		retryable: env.Error.Retryable, human: env.Error.Human,
		cookies: resp.Cookies(),
	}
}

// @ac AC-68
// AC-68: logout enforces CSRF whenever a cookie selects the target, for
// every anchor shape, and an Authorization header does not bypass it.
func TestLogout_EnforcesCSRFForCookieAuthority(t *testing.T) {
	t.Run("system-auth-identity/AC-68", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		type anchorCase struct {
			name  string
			build func(tag string) (session, refresh *http.Cookie, check func(t *testing.T, csrf string))
		}
		anchors := []anchorCase{
			{"session cookie only", func(tag string) (*http.Cookie, *http.Cookie, func(*testing.T, string)) {
				li := loginFresh(t, url, pool, "ac68s"+tag)
				return li.sessionCookie, nil, func(t *testing.T, csrf string) {
					s, r := liveCounts(t, pool, li.u.ID)
					if csrf == "valid" && (s != 0 || r != 0) {
						t.Errorf("valid CSRF: live %d/%d, want 0/0", s, r)
					}
					if csrf != "valid" && (s != 1 || r != 1) {
						t.Errorf("%s CSRF revoked something: live %d/%d, want 1/1", csrf, s, r)
					}
				}
			}},
			{"refresh cookie only", func(tag string) (*http.Cookie, *http.Cookie, func(*testing.T, string)) {
				li := loginFresh(t, url, pool, "ac68r"+tag)
				return nil, li.refreshCookie, func(t *testing.T, csrf string) {
					s, r := liveCounts(t, pool, li.u.ID)
					if csrf == "valid" && (s != 0 || r != 0) {
						t.Errorf("valid CSRF: live %d/%d, want 0/0", s, r)
					}
					if csrf != "valid" && (s != 1 || r != 1) {
						t.Errorf("%s CSRF revoked something: live %d/%d, want 1/1", csrf, s, r)
					}
				}
			}},
			{"both cookies, same family", func(tag string) (*http.Cookie, *http.Cookie, func(*testing.T, string)) {
				li := loginFresh(t, url, pool, "ac68b"+tag)
				return li.sessionCookie, li.refreshCookie, func(t *testing.T, csrf string) {
					s, r := liveCounts(t, pool, li.u.ID)
					if csrf == "valid" && (s != 0 || r != 0) {
						t.Errorf("valid CSRF: live %d/%d, want 0/0", s, r)
					}
					if csrf != "valid" && (s != 1 || r != 1) {
						t.Errorf("%s CSRF revoked something: live %d/%d, want 1/1", csrf, s, r)
					}
				}
			}},
			{"conflicting cookies", func(tag string) (*http.Cookie, *http.Cookie, func(*testing.T, string)) {
				a := loginFresh(t, url, pool, "ac68c"+tag)
				b := collectLogin(t, login(t, url, map[string]string{"username": a.u.Username, "password": a.u.Password}))
				return a.sessionCookie, b.refreshCookie, func(t *testing.T, csrf string) {
					s, r := liveCounts(t, pool, a.u.ID)
					if csrf == "valid" {
						if s != 1 || r != 1 {
							t.Errorf("valid CSRF: live %d/%d, want 1/1 (family B only)", s, r)
						}
						if authMe(t, url, b.sessionCookie) != http.StatusOK {
							t.Error("valid CSRF with conflicting cookies signed out family B")
						}
					} else if s != 2 || r != 2 {
						t.Errorf("%s CSRF revoked something: live %d/%d, want 2/2", csrf, s, r)
					}
				}
			}},
		}

		for _, ac := range anchors {
			for _, csrf := range []string{"missing", "mismatched", "valid"} {
				t.Run(ac.name+", "+csrf, func(t *testing.T) {
					session, refresh, check := ac.build(csrf)
					got := logoutCSRF(t, url, session, refresh, csrf, "")
					if csrf == "valid" {
						if got.status != http.StatusNoContent {
							t.Errorf("status = %d, want 204", got.status)
						}
					} else {
						if got.status != http.StatusForbidden || got.code != "authz.csrf_invalid" {
							t.Errorf("status/code = %d/%q, want 403/authz.csrf_invalid", got.status, got.code)
						}
						if len(got.cookies) != 0 {
							t.Errorf("a refused logout set %d cookie(s); it must not clear or replace any", len(got.cookies))
						}
					}
					check(t, csrf)
				})
			}
		}

		t.Run("Authorization header does not bypass", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac68authz")
			got := logoutCSRF(t, url, li.sessionCookie, nil, "missing", "Bearer "+li.accessToken)
			if got.status != http.StatusForbidden {
				t.Errorf("status = %d, want 403: an Authorization header must not bypass CSRF when cookies select the target", got.status)
			}
			if s, r := liveCounts(t, pool, li.u.ID); s != 1 || r != 1 {
				t.Errorf("the bypass attempt revoked something: live %d/%d", s, r)
			}
		})
	})
}

// countingBeginner counts transactions begun, so a replay is visible.
type countingBeginner struct {
	inner identity.TxBeginner
	mu    sync.Mutex
	n     int
}

func (c *countingBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.inner.Begin(ctx)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// @ac AC-69
// AC-69: an unknown commit outcome on logout is reported truthfully and
// is not retryable; cookies are still cleared; nothing is replayed.
func TestLogout_UnknownCommitIsReportedTruthfully(t *testing.T) {
	t.Run("system-auth-identity/AC-69", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			commitFirst bool
			wantLive    int
		}{
			{"durable commit, lost acknowledgement", true, 0},
			{"non-durable", false, 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				url, pool, srv := freshAPIServerWithHandles(t)
				li := loginFresh(t, url, pool, "ac69"+map[bool]string{true: "d", false: "n"}[tc.commitFirst])

				logs := &lockedBuffer{}
				prev := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
				defer slog.SetDefault(prev)

				counter := &countingBeginner{inner: &indeterminateBeginner{inner: pool, commitFirst: tc.commitFirst}}
				srv.handlers.serializer = counter
				got := logoutCSRF(t, url, li.sessionCookie, li.refreshCookie, "valid", "")
				srv.handlers.serializer = nil

				if got.status != http.StatusServiceUnavailable || got.code != "server.error" {
					t.Errorf("status/code = %d/%q, want 503/server.error", got.status, got.code)
				}
				if got.retryable {
					t.Error("retryable = true on an unknown logout outcome")
				}
				if !containsFold(got.human, "revocation of your session could not be confirmed") {
					t.Errorf("message does not say the revocation could not be confirmed: %q", got.human)
				}
				for _, claim := range []string{"could not revoke", "was revoked", "nothing was revoked", "rolled back"} {
					if containsFold(got.human, claim) {
						t.Errorf("message asserts an outcome (%q): %q", claim, got.human)
					}
				}
				log := logs.String()
				if !containsFold(log, "outcome unknown") {
					t.Errorf("log does not record an unknown outcome:\n%s", log)
				}
				if containsFold(log, "nothing was revoked") || containsFold(log, "rolled back") {
					t.Errorf("log asserts a rollback that nothing here knows happened:\n%s", log)
				}
				counter.mu.Lock()
				begun := counter.n
				counter.mu.Unlock()
				if begun != 1 {
					t.Errorf("transactions begun = %d, want 1: an unknown commit must not be replayed", begun)
				}
				cleared := map[string]bool{}
				for _, c := range got.cookies {
					if c.MaxAge < 0 || c.Value == "" {
						cleared[c.Name] = true
					}
				}
				for _, name := range []string{identity.SessionCookieName, identity.RefreshCookieName} {
					if !cleared[name] {
						t.Errorf("cookie %s was not cleared", name)
					}
				}
				if s, _ := liveCounts(t, pool, li.u.ID); s != tc.wantLive {
					t.Errorf("live sessions = %d, want %d for this variant (the response must read the same either way)", s, tc.wantLive)
				}
			})
		}
	})
}
