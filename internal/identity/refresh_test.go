// @spec system-auth-identity
//
// Refresh-token revocation tests (AC-24). The reuse + rotation flow
// (AC-12, AC-13) is covered indirectly by sessions_test.go and the
// PostAuthRefresh handler tests; this file pins down RevokeRefreshToken,
// which logout uses to invalidate the refresh cookie alongside the
// session cookie.

package identity

import (
	"context"
	"crypto/sha256"
	"testing"
)

// @ac AC-24
// AC-24: RevokeRefreshToken sets revoked_at on the row whose token_hash
// matches the presentation token. Subsequent ConsumeRefreshToken on
// that token returns ErrRefreshTokenRevoked.
func TestRefresh_Revoke(t *testing.T) {
	t.Run("system-auth-identity/AC-24", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "refresh-revoke")

		ctx := context.Background()
		token, err := IssueRefreshToken(ctx, pool, userID)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if err := RevokeRefreshToken(ctx, pool, token); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		// DB check: row marked revoked.
		hash := sha256.Sum256([]byte(token))
		var revoked bool
		if err := pool.QueryRow(ctx,
			"SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash = $1",
			hash[:]).Scan(&revoked); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !revoked {
			t.Errorf("revoked_at was not set")
		}

		// Behavioral check: consume returns Revoked.
		if _, err := ConsumeRefreshToken(ctx, pool, token, ""); err == nil {
			t.Errorf("ConsumeRefreshToken after revoke: want error, got nil")
		} else if !isOneOf(err, ErrRefreshTokenRevoked) {
			t.Errorf("ConsumeRefreshToken after revoke: want ErrRefreshTokenRevoked, got %v", err)
		}
	})
}

// @ac AC-24
// AC-24 idempotency: revoking an unknown or empty token is a no-op (no
// error). Logout calls this best-effort and must not fail because the
// browser presented a junk cookie.
func TestRefresh_Revoke_Idempotent(t *testing.T) {
	t.Run("system-auth-identity/AC-24", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		if err := RevokeRefreshToken(ctx, pool, ""); err != nil {
			t.Errorf("empty token: %v", err)
		}
		if err := RevokeRefreshToken(ctx, pool, "unknown-token-value"); err != nil {
			t.Errorf("unknown token: %v", err)
		}
	})
}

// isOneOf wraps errors.Is for variadic comparison — keeps the test
// readable when a single error has several legitimate matches.
func isOneOf(got error, wants ...error) bool {
	for _, w := range wants {
		if got == w || (got != nil && got.Error() == w.Error()) {
			return true
		}
	}
	return false
}
