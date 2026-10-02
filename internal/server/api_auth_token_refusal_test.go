// @spec api-auth
//
// AC traceability (DSN-gated):
//
//	AC-15  TestAuthSelfService_RefusesAPIToken
package server

import (
	"context"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-15
func TestAuthSelfService_RefusesAPIToken(t *testing.T) {
	t.Run("api-auth/AC-15", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		owner := roleUserIDs[auth.RoleAdmin]
		raw, _ := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		before := queryString(t, pool, `SELECT COALESCE(display_name,'') || '|' || password_hash FROM users WHERE id = $1`, owner)

		assertTokenRefused(t, url, raw, "GET", "/api/v1/auth/me", nil)
		assertTokenRefused(t, url, raw, "PATCH", "/api/v1/auth/me", map[string]any{"display_name": "by-token"})
		assertTokenRefused(t, url, raw, "POST", "/api/v1/auth/mfa:enroll", nil)
		assertTokenRefused(t, url, raw, "POST", "/api/v1/auth/mfa:verify", map[string]any{"otp": "123456"})
		assertTokenRefused(t, url, raw, "POST", "/api/v1/auth/password:change", map[string]any{"current_password": "x", "new_password": "By-Token-Pass-2026!"})

		if after := queryString(t, pool, `SELECT COALESCE(display_name,'') || '|' || password_hash FROM users WHERE id = $1`, owner); after != before {
			t.Error("the owner's profile or password changed")
		}
		var mfa int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM auth_mfa_secrets WHERE user_id = $1`, owner).Scan(&mfa)
		if mfa != 0 {
			t.Errorf("a token enrolled MFA for its owner (%d rows)", mfa)
		}
	})
}
