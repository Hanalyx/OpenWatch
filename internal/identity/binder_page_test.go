// @spec system-auth-identity
//
// OW-090: a rejected session cookie must not stop the browser loading the
// SPA or the sign-in page (C-47). The page is served anonymously and no
// cookie is touched, so the refresh-cookie path still decides whether the
// user needs to sign in again. API paths keep the 401 envelope the
// frontend refreshes on (C-12), a rejected Bearer token keeps its 401
// everywhere, and an infrastructure failure keeps its 503 (C-32).

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rejectedCookie is a session cookie the binder refuses, with the account
// state the lookups report for its user.
type rejectedCookie struct {
	token   string
	lookups stubLookups
}

// rejectedSessionCookies returns a session cookie in each state C-47 names:
// unknown, expired, revoked, and a live session whose account is disabled
// or soft-deleted.
func rejectedSessionCookies(t *testing.T, pool *pgxpool.Pool) map[string]rejectedCookie {
	t.Helper()
	ctx := context.Background()
	out := map[string]rejectedCookie{"unknown": {token: "not-a-real-token", lookups: adminLookups}}

	issue := func(name string) (string, Session) {
		t.Helper()
		tok, sess, err := IssueSession(ctx, pool, seedUser(t, pool, name), "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("issue %s: %v", name, err)
		}
		return tok, sess
	}

	expired, es := issue("c47-expired")
	ago := time.Now().UTC().Add(-time.Minute)
	if _, err := pool.Exec(ctx,
		`UPDATE sessions SET expires_at = $1, absolute_expires_at = $1 WHERE id = $2`, ago, es.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	out["expired"] = rejectedCookie{token: expired, lookups: adminLookups}

	revoked, rs := issue("c47-revoked")
	if _, err := pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, rs.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	out["revoked"] = rejectedCookie{token: revoked, lookups: adminLookups}

	disabled, _ := issue("c47-disabled")
	out["disabled account"] = rejectedCookie{token: disabled,
		lookups: stubLookups{role: auth.RoleAdmin, status: AccountDisabled}}

	deleted, _ := issue("c47-deleted")
	out["deleted account"] = rejectedCookie{token: deleted,
		lookups: stubLookups{role: auth.RoleAdmin, status: AccountDeleted}}
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

// @ac AC-94
// AC-94: a page load presenting a rejected session cookie is served
// anonymously and sets no cookie, so a refresh token that still works
// survives for the SPA's refresh call.
func TestBinder_PageLoadWithRejectedSession_ServedAnonymouslyCookiesKept(t *testing.T) {
	t.Run("system-auth-identity/AC-94", func(t *testing.T) {
		pool := freshPool(t)
		for state, rc := range rejectedSessionCookies(t, pool) {
			for _, path := range []string{"/", "/login", "/hosts/01a0ed4c-c03a-752b-8600-a15fff968665", "/assets/app-abc123.js"} {
				t.Run(state+" "+path, func(t *testing.T) {
					h := Binder(pool, rc.lookups)(echoHandler(t, true))
					req := httptest.NewRequest(http.MethodGet, path, nil)
					req.Header.Set("Accept", "text/html")
					req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rc.token})
					req.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: "a-refresh-token"})
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, req)
					if rr.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200 (the page must load); body=%q", rr.Code, rr.Body.String())
					}
					if sc := rr.Header().Values("Set-Cookie"); len(sc) != 0 {
						t.Errorf("a page load must not touch the credential cookies; Set-Cookie=%q", sc)
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

		for state, rc := range rejectedSessionCookies(t, pool) {
			for _, path := range []string{"/api/v1/auth/me", "/api/v1/hosts", "/api"} {
				t.Run("api "+state+" "+path, func(t *testing.T) {
					h := Binder(pool, rc.lookups)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						t.Errorf("downstream ran for a rejected cookie on an API path")
						w.WriteHeader(http.StatusOK)
					}))
					req := httptest.NewRequest(http.MethodGet, path, nil)
					req.Header.Set("Accept", "text/html")
					req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rc.token})
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
			token, _, err := IssueSession(context.Background(), pool, seedUser(t, pool, "c47-unavailable"), "127.0.0.1", "ua")
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
			if sc := rr.Header().Values("Set-Cookie"); len(sc) != 0 {
				t.Errorf("an infrastructure failure must not touch a possibly live session; Set-Cookie=%q", sc)
			}
		})
	})
}
