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
	"time"
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
		token, err := IssueRefreshToken(ctx, pool, userID, time.Now().UTC().Add(12*time.Hour))
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

// @ac AC-28
// AC-28 (AUTH-1 b): ConsumeRefreshToken refuses a token whose carried absolute
// deadline has passed (ErrRefreshSessionExpired), even though the 7-day window
// is still open; a token with a future deadline rotates normally.
func TestRefresh_AbsoluteCeiling(t *testing.T) {
	t.Run("system-auth-identity/AC-28", func(t *testing.T) {
		ensureKey(t)
		pool := freshPool(t)
		ctx := context.Background()
		userID := seedUser(t, pool, "refresh-abs-ceiling")

		// Past absolute deadline → refused (the 7-day refresh window is open).
		expired, err := IssueRefreshToken(ctx, pool, userID, time.Now().UTC().Add(-time.Minute))
		if err != nil {
			t.Fatalf("issue expired: %v", err)
		}
		if _, err := ConsumeRefreshToken(ctx, pool, expired, ""); !isOneOf(err, ErrRefreshSessionExpired) {
			t.Fatalf("consume past-deadline: want ErrRefreshSessionExpired, got %v", err)
		}

		// Future deadline → rotates normally.
		live, err := IssueRefreshToken(ctx, pool, userID, time.Now().UTC().Add(12*time.Hour))
		if err != nil {
			t.Fatalf("issue live: %v", err)
		}
		if _, err := ConsumeRefreshToken(ctx, pool, live, "viewer"); err != nil {
			t.Fatalf("consume live: %v", err)
		}
	})
}

// @ac AC-29
// AC-29 (AUTH-1 b): a successful rotation carries the ORIGINAL absolute deadline
// onto the rotated row unchanged and returns it on the TokenPair (so the
// cookie-refresh handler can preserve the ceiling).
func TestRefresh_CarriesAbsoluteForward(t *testing.T) {
	t.Run("system-auth-identity/AC-29", func(t *testing.T) {
		ensureKey(t)
		pool := freshPool(t)
		ctx := context.Background()
		userID := seedUser(t, pool, "refresh-carry")
		deadline := time.Now().UTC().Add(8 * time.Hour).Truncate(time.Second)

		tok, err := IssueRefreshToken(ctx, pool, userID, deadline)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		pair, err := ConsumeRefreshToken(ctx, pool, tok, "viewer")
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		// The TokenPair carries the original deadline.
		if !pair.AbsoluteExpiresAt.UTC().Truncate(time.Second).Equal(deadline) {
			t.Errorf("pair.AbsoluteExpiresAt = %v, want %v", pair.AbsoluteExpiresAt, deadline)
		}
		// The rotated DB row inherits the same deadline (not a fresh one).
		newHash := sha256.Sum256([]byte(pair.RefreshToken))
		var got time.Time
		if err := pool.QueryRow(ctx,
			"SELECT absolute_expires_at FROM refresh_tokens WHERE token_hash = $1",
			newHash[:]).Scan(&got); err != nil {
			t.Fatalf("scan new row: %v", err)
		}
		if !got.UTC().Truncate(time.Second).Equal(deadline) {
			t.Errorf("rotated absolute_expires_at = %v, want %v", got, deadline)
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
