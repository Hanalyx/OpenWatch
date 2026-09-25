// @spec system-auth-identity
//
// Session-bound access tokens (C-38). The administrative-reset case is
// the one an account-state check cannot reach: the account stays
// enabled, so only the binding can refuse the token.

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// @ac AC-43
// AC-43: an access token stops authenticating once its session is
// revoked, while the account stays enabled and undeleted.
func TestAccessToken_DiesWithItsSession(t *testing.T) {
	t.Run("system-auth-identity/AC-43", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		for _, tc := range []struct {
			name string
			user string
			act  func(uid uuid.UUID)
		}{
			{"session revoked directly", "ac43direct", func(uid uuid.UUID) {
				if _, err := pool.Exec(ctx,
					`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
					uid); err != nil {
					t.Fatalf("revoke session: %v", err)
				}
			}},
			{"revoked via AdminResetPassword", "ac43reset", func(uid uuid.UUID) {
				if err := svc.AdminResetPassword(ctx, uid, "another-strong-passphrase-Zz9"); err != nil {
					t.Fatalf("admin reset: %v", err)
				}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				li := loginFresh(t, url, pool, tc.user)
				if code := authMeBearer(t, url, li.accessToken); code != http.StatusOK {
					t.Fatalf("precondition: the token must work first, got %d", code)
				}

				tc.act(li.u.ID)

				// The account is deliberately untouched, so no
				// account-state check can produce this refusal.
				var disabled, deleted bool
				if err := pool.QueryRow(ctx,
					`SELECT disabled_at IS NOT NULL, deleted_at IS NOT NULL FROM users WHERE id = $1`,
					li.u.ID).Scan(&disabled, &deleted); err != nil {
					t.Fatalf("read account state: %v", err)
				}
				if disabled || deleted {
					t.Fatalf("the account must stay active for this case; disabled=%v deleted=%v", disabled, deleted)
				}

				if code := authMeBearer(t, url, li.accessToken); code != http.StatusUnauthorized {
					t.Errorf("access token after %s = %d, want 401", tc.name, code)
				}
			})
		}
	})
}

// @ac AC-44
// AC-44: an unbound access token is refused, and every interactive
// issuance path mints a bound one.
func TestAccessToken_BindingIsRequiredAndAlwaysIssued(t *testing.T) {
	t.Run("system-auth-identity/AC-44", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		li := loginFresh(t, url, pool, "ac44user")

		// Password login mints a bound token and a bound refresh row.
		claims, err := identity.VerifyJWT(li.accessToken)
		if err != nil {
			t.Fatalf("login token does not verify: %v", err)
		}
		if claims.SessionID == "" {
			t.Error("password login minted an access token with no session binding")
		}
		var boundRows int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND session_id IS NOT NULL`,
			li.u.ID).Scan(&boundRows); err != nil {
			t.Fatalf("count bound refresh rows: %v", err)
		}
		if boundRows == 0 {
			t.Error("password login wrote a refresh row with no session binding")
		}

		// An UNBOUND token is cryptographically valid and differs only
		// in the claim. It must still be refused.
		unbound, _, err := identity.IssueJWT(li.u.ID, string(auth.RoleViewer))
		if err != nil {
			t.Fatalf("mint unbound token: %v", err)
		}
		if _, err := identity.VerifyJWT(unbound); err != nil {
			t.Fatalf("the unbound token must be otherwise valid, got %v", err)
		}
		code, cid := authMeBearerCorrelated(t, url, unbound)
		if code != http.StatusUnauthorized {
			t.Errorf("unbound access token = %d, want 401", code)
		}
		// The REASON matters. An empty sid also fails UUID parsing, so a
		// test that only checked the status passed with the unbound
		// branch deleted. An operator seeing "invalid_jwt_session" would
		// look for a malformed token; "sid_absent" says a client is
		// minting tokens with no binding at all. The vocabulary is the
		// recorded one (OW-062 section 4).
		if reason := loginFailureReasonFor(t, pool, cid); reason != "sid_absent" {
			t.Errorf("audit reason for an unbound token = %q, want sid_absent", reason)
		}

		// A body refresh preserves the binding rather than dropping it.
		code, rotated := refreshBody(t, url, li.bodyRefresh)
		if code != http.StatusOK {
			t.Fatalf("body refresh = %d, want 200", code)
		}
		rc, err := identity.VerifyJWT(rotated)
		if err != nil {
			t.Fatalf("rotated token does not verify: %v", err)
		}
		if rc.SessionID == "" {
			t.Error("the body refresh minted an access token with no session binding")
		}
		if code := authMeBearer(t, url, rotated); code != http.StatusOK {
			t.Errorf("rotated access token = %d, want 200", code)
		}
	})
}

// authMeBearerCorrelated presents a Bearer token on GET /auth/me with a
// unique X-Correlation-Id and returns the status and that id. The id is
// what ties an audit row to THIS request (bugs/OW-075).
func authMeBearerCorrelated(t *testing.T, url, token string) (int, string) {
	t.Helper()
	cid := "ac-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Correlation-Id", cid)
	resp := doReq(t, req)
	defer resp.Body.Close()
	return resp.StatusCode, cid
}

// authMeCookieCorrelated is the cookie-path equivalent.
func authMeCookieCorrelated(t *testing.T, url string, c *http.Cookie) (int, string) {
	t.Helper()
	cid := "ac-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	req, _ := http.NewRequest("GET", url+"/api/v1/auth/me", nil)
	req.AddCookie(c)
	req.Header.Set("X-Correlation-Id", cid)
	resp := doReq(t, req)
	defer resp.Body.Close()
	return resp.StatusCode, cid
}

// loginFailureReasonFor returns the reason on the ONE auth.login.failure
// row the request with this correlation id produced. It waits, bounded,
// for that row to land, because the audit writer batches, and fails the
// test when the row never appears or when the request produced more than
// one. It never falls back to another request's row. bugs/OW-075.
func loginFailureReasonFor(t *testing.T, pool *pgxpool.Pool, correlationID string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows, err := pool.Query(context.Background(), `
			SELECT COALESCE(detail->>'reason','') FROM audit_events
			WHERE action = 'auth.login.failure' AND correlation_id = $1`, correlationID)
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		var reasons []string
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				t.Fatalf("scan audit: %v", err)
			}
			reasons = append(reasons, r)
		}
		rows.Close()
		if len(reasons) > 1 {
			t.Fatalf("request %s recorded %d login failures, want 1: %v", correlationID, len(reasons), reasons)
		}
		if len(reasons) == 1 {
			return reasons[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("request %s recorded no auth.login.failure within 10s", correlationID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
