// @spec system-auth-identity
//
// OW-090: a dead session cookie must not stop the browser loading the SPA
// or the sign-in page (C-47), while API paths keep the 401 envelope the
// frontend's refresh logic depends on (C-12), a rejected Bearer token keeps
// its 401 everywhere, and an infrastructure failure keeps its 503 (C-32).

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// deadSessionCookies returns a session cookie in each rejected state the
// binder distinguishes: an unknown token, an expired session and a revoked
// one.
func deadSessionCookies(t *testing.T, pool *pgxpool.Pool) map[string]string {
	t.Helper()
	ctx := context.Background()
	out := map[string]string{"unknown": "not-a-real-token"}

	expiredUser := seedUser(t, pool, "c47-expired")
	expired, _, err := IssueSession(ctx, pool, expiredUser, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	ago := time.Now().UTC().Add(-time.Minute)
	if _, err := pool.Exec(ctx,
		`UPDATE sessions SET expires_at = $1, absolute_expires_at = $1 WHERE user_id = $2`,
		ago, expiredUser); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	out["expired"] = expired

	revokedUser := seedUser(t, pool, "c47-revoked")
	revoked, _, err := IssueSession(ctx, pool, revokedUser, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("issue revoked: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1`, revokedUser); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	out["revoked"] = revoked
	return out
}

// envelopeCode returns error.code from a JSON error envelope.
func envelopeCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%q", err, rr.Body.String())
	}
	return env.Error.Code
}

// clearedCookies returns the auth cookies a response deletes.
func clearedCookies(rr *httptest.ResponseRecorder) map[string]bool {
	out := map[string]bool{}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 && c.Value == "" && c.Path == "/" && c.HttpOnly && c.Secure {
			out[c.Name] = true
		}
	}
	return out
}

// @ac AC-94
// AC-94: a page load presenting a dead session cookie is served
// anonymously, and the response deletes both auth cookies.
func TestBinder_PageLoadWithDeadSession_ServedAnonymouslyAndCleared(t *testing.T) {
	t.Run("system-auth-identity/AC-94", func(t *testing.T) {
		pool := freshPool(t)
		for state, token := range deadSessionCookies(t, pool) {
			for _, path := range []string{"/", "/login", "/hosts/01a0ed4c-c03a-752b-8600-a15fff968665", "/assets/app-abc123.js"} {
				t.Run(state+" "+path, func(t *testing.T) {
					h := Binder(pool, adminLookups)(echoHandler(t, true))
					req := httptest.NewRequest(http.MethodGet, path, nil)
					req.Header.Set("Accept", "text/html")
					req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
					req.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: "stale-refresh"})
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, req)
					if rr.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200 (the page must load); body=%q", rr.Code, rr.Body.String())
					}
					got := clearedCookies(rr)
					for _, name := range []string{SessionCookieName, RefreshCookieName} {
						if !got[name] {
							t.Errorf("response does not delete %s; Set-Cookie=%q", name, rr.Header().Values("Set-Cookie"))
						}
					}
				})
			}
		}
	})
}

// @ac AC-95
// AC-95: the page-load exception does not reach API paths, a rejected
// Bearer token, or an infrastructure failure.
func TestBinder_PageLoadException_DoesNotReachAPIOrBearerOr503(t *testing.T) {
	t.Run("system-auth-identity/AC-95", func(t *testing.T) {
		pool := freshPool(t)
		dead := deadSessionCookies(t, pool)

		for state, token := range dead {
			for _, path := range []string{"/api/v1/auth/me", "/api/v1/hosts", "/api"} {
				t.Run("api "+state+" "+path, func(t *testing.T) {
					h := Binder(pool, adminLookups)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						t.Errorf("downstream ran for a dead cookie on an API path")
						w.WriteHeader(http.StatusOK)
					}))
					req := httptest.NewRequest(http.MethodGet, path, nil)
					req.Header.Set("Accept", "text/html")
					req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, req)
					if rr.Code != http.StatusUnauthorized {
						t.Errorf("status = %d, want 401", rr.Code)
					}
					if code := envelopeCode(t, rr); code != "auth.session_invalid" {
						t.Errorf("error.code = %q, want auth.session_invalid", code)
					}
				})
			}
		}

		t.Run("bearer on a page path", func(t *testing.T) {
			h := Binder(pool, adminLookups)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Errorf("downstream ran for a rejected Bearer token")
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			req.Header.Set("Authorization", "Bearer not-a-real-jwt")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401: a Bearer credential is never a page load", rr.Code)
			}
		})

		t.Run("state unavailable on a page path stays 503", func(t *testing.T) {
			user := seedUser(t, pool, "c47-unavailable")
			token, _, err := IssueSession(context.Background(), pool, user, "127.0.0.1", "ua")
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			broken := stubLookups{statusErr: errors.New("database unreachable")}
			h := Binder(pool, broken)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Errorf("downstream ran when account state was unavailable")
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rr.Code)
			}
			if len(clearedCookies(rr)) != 0 {
				t.Errorf("an infrastructure failure must not delete a possibly live session; Set-Cookie=%q",
					rr.Header().Values("Set-Cookie"))
			}
		})
	})
}
