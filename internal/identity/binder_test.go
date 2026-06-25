// @spec system-auth-identity
//
// IdentityBinder behavioral tests for AC-21 (presented-but-rejected
// credentials short-circuit with 401) and the bypass-list invariant
// that keeps credential-lifecycle endpoints (login, logout, refresh
// paths) reachable when the only cookie the browser still has is a
// stale session.

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

// adminLookups returns RoleAdmin for any user — keeps the binder happy
// without standing up the real users.Service. Reuses the stubLookups
// shape defined in mfa_test.go (same package).
var adminLookups = stubLookups{role: auth.RoleAdmin}

// echoHandler is the downstream the binder calls when it lets a request
// through. Tests fail if it runs unexpectedly.
func echoHandler(t *testing.T, expectAnonymous bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := auth.FromContext(r.Context())
		if id.IsAnonymous != expectAnonymous {
			t.Errorf("expected anonymous=%v, got %+v", expectAnonymous, id)
		}
		w.WriteHeader(http.StatusOK)
	})
}

// @ac AC-21
// AC-21: A request that presents an INVALID session cookie short-circuits
// with HTTP 401 and envelope error.code="auth.session_invalid". The
// downstream handler MUST NOT run.
func TestBinder_RejectedSession_Writes401(t *testing.T) {
	t.Run("system-auth-identity/AC-21", func(t *testing.T) {
		pool := freshPool(t)
		var pinged bool
		downstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			pinged = true
		})
		h := Binder(pool, adminLookups)(downstream)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-a-real-token"})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status: want 401, got %d", rr.Code)
		}
		if pinged {
			t.Errorf("downstream handler ran on rejected credential — binder failed to short-circuit")
		}
		var env map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode body: %v\nbody=%q", err, rr.Body.String())
		}
		errBody, _ := env["error"].(map[string]any)
		if got, _ := errBody["code"].(string); got != "auth.session_invalid" {
			t.Errorf("error.code: want auth.session_invalid, got %q", got)
		}
		if got, _ := errBody["retryable"].(bool); !got {
			t.Errorf("error.retryable: want true (frontend retries via refresh-cookie)")
		}
	})
}

// @ac AC-21
// AC-21 (other half): a request with NO credential at all flows through
// anonymously. The contract: anonymous-because-nothing-presented stays
// anonymous; only presented-but-rejected gets the 401.
func TestBinder_NoCredential_FallsThroughAnonymous(t *testing.T) {
	t.Run("system-auth-identity/AC-21", func(t *testing.T) {
		pool := freshPool(t)
		h := Binder(pool, adminLookups)(echoHandler(t, true))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("status: want 200 (downstream runs), got %d", rr.Code)
		}
	})
}

// @ac AC-21
// AC-21 bypass list: a stale session cookie presented to one of the
// credential-lifecycle endpoints (login, logout, refresh, refresh-cookie)
// MUST NOT short-circuit. These endpoints manage credentials themselves
// and need to run anonymously even when a stale session sits alongside.
func TestBinder_BypassList_RejectedSession_StillPasses(t *testing.T) {
	t.Run("system-auth-identity/AC-21", func(t *testing.T) {
		pool := freshPool(t)
		paths := []string{
			"/api/v1/auth/login",
			"/api/v1/auth/logout",
			"/api/v1/auth/refresh",
			"/api/v1/auth/refresh-cookie",
		}
		for _, p := range paths {
			t.Run(p, func(t *testing.T) {
				h := Binder(pool, adminLookups)(echoHandler(t, true))
				req := httptest.NewRequest(http.MethodPost, p, strings.NewReader("{}"))
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-real"})
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					t.Errorf("status on %s: want 200 (bypass), got %d", p, rr.Code)
				}
			})
		}
	})
}

// @ac AC-21
// AC-21: An expired session — a session row that exists but whose
// expires_at is in the past — must produce the same 401 short-circuit
// as an unknown token. This is the exact scenario reported in the
// dev session: the row is real, just stale.
func TestBinder_ExpiredSession_Writes401(t *testing.T) {
	t.Run("system-auth-identity/AC-21", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "expired-binder")
		token, _, err := IssueSession(context.Background(), pool, userID, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		// Backdate the expiry so VerifySession returns ErrSessionExpired.
		ago := time.Now().UTC().Add(-time.Minute)
		if _, err := pool.Exec(context.Background(),
			"UPDATE sessions SET expires_at = $1, absolute_expires_at = $1 WHERE user_id = $2",
			ago, userID); err != nil {
			t.Fatalf("backdate: %v", err)
		}

		h := Binder(pool, adminLookups)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Errorf("downstream handler ran on expired session")
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status: want 401, got %d", rr.Code)
		}
	})
}

// @ac AC-31
// AC-31 (AUTH-1 c): the binder slides the idle window only on user-initiated
// requests. A request carrying X-Background-Refresh validates the session but
// does NOT advance expires_at; an unmarked request does.
func TestBinder_SlideOnlyOnUserActivity(t *testing.T) {
	t.Run("system-auth-identity/AC-31", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "slide-binder")
		token, sess, err := IssueSession(context.Background(), pool, userID, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		// Backdate expires_at so a slide is observable.
		if _, err := pool.Exec(context.Background(),
			`UPDATE sessions SET expires_at = expires_at - interval '10 minutes' WHERE id = $1`,
			sess.ID); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		readExpiry := func() time.Time {
			var e time.Time
			if err := pool.QueryRow(context.Background(),
				`SELECT expires_at FROM sessions WHERE id = $1`, sess.ID).Scan(&e); err != nil {
				t.Fatalf("read expiry: %v", err)
			}
			return e
		}
		h := Binder(pool, adminLookups)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		do := func(background bool) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			if background {
				req.Header.Set(BackgroundRefreshHeader, "1")
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status: want 200, got %d", rr.Code)
			}
		}

		before := readExpiry()
		// Background request must NOT slide.
		do(true)
		if got := readExpiry(); !got.Equal(before) {
			t.Errorf("background request slid the window: before=%v after=%v", before, got)
		}
		// User-initiated request must slide.
		do(false)
		if got := readExpiry(); !got.After(before) {
			t.Errorf("user request did not slide the window: before=%v after=%v", before, got)
		}

		// The SSE events stream must NOT slide — it cannot send the header but
		// is a long-lived background subscription.
		afterUser := readExpiry()
		req := httptest.NewRequest(http.MethodGet, sseEventsPath, nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if got := readExpiry(); !got.Equal(afterUser) {
			t.Errorf("SSE request slid the window: before=%v after=%v", afterUser, got)
		}
	})
}

// Silence the unused-import warning when the test runs without DB.
var _ = pgxpool.Config{}
