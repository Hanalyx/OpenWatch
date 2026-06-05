// @spec system-auth-identity
//
// JWT mint/verify + refresh-token rotation tests (ACs 11, 12, 13, 20).

package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/internalrace"
	"github.com/google/uuid"
)

// ensureKey installs an ephemeral RS256 key for the test process. Safe
// to call multiple times — replaces the key each call. Tests that need
// a stable key across calls just call it once at the top of the test.
func ensureKey(t *testing.T) {
	t.Helper()
	if err := SetEphemeralJWTKey(); err != nil {
		t.Fatalf("SetEphemeralJWTKey: %v", err)
	}
}

// @ac AC-11
// AC-11: IssueJWT mints RS256 with {sub, iat, exp=iat+30min, jti, role}.
// VerifyJWT round-trips the same token and returns the claims.
func TestJWT_IssueAndVerify(t *testing.T) {
	t.Run("system-auth-identity/AC-11", func(t *testing.T) {
		ensureKey(t)
		userID, _ := uuid.NewV7()
		before := time.Now().UTC()
		signed, claims, err := IssueJWT(userID, "ops_lead")
		if err != nil {
			t.Fatalf("IssueJWT: %v", err)
		}
		if signed == "" {
			t.Fatal("signed token is empty")
		}
		// Subject = userID
		if claims.Subject != userID.String() {
			t.Errorf("Subject = %q, want %q", claims.Subject, userID.String())
		}
		// exp = iat + 30 min (±5s for clock skew)
		gap := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
		if gap < 29*time.Minute+55*time.Second || gap > 30*time.Minute+5*time.Second {
			t.Errorf("exp - iat = %v, want ~30m", gap)
		}
		if claims.ExpiresAt.Time.Before(before.Add(29 * time.Minute)) {
			t.Errorf("exp = %v, want > now+29m", claims.ExpiresAt.Time)
		}
		if claims.ID == "" {
			t.Error("jti is empty")
		}
		if claims.Role != "ops_lead" {
			t.Errorf("Role = %q, want ops_lead", claims.Role)
		}

		// VerifyJWT round-trips.
		got, err := VerifyJWT(signed)
		if err != nil {
			t.Fatalf("VerifyJWT: %v", err)
		}
		if got.Subject != claims.Subject {
			t.Errorf("verified Subject mismatch")
		}
		if got.Role != claims.Role {
			t.Errorf("verified Role mismatch")
		}
	})
}

// @ac AC-12
// AC-12: IssueRefreshToken persists a row; ConsumeRefreshToken returns
// a new (access, refresh) pair AND marks the old row's rotated_to_id
// at the new row.
func TestRefresh_RotationOnConsume(t *testing.T) {
	t.Run("system-auth-identity/AC-12", func(t *testing.T) {
		ensureKey(t)
		pool := freshPool(t)
		userID := seedUser(t, pool, "ac12-user")

		// Issue an initial refresh token.
		refresh1, err := IssueRefreshToken(context.Background(), pool, userID)
		if err != nil {
			t.Fatalf("IssueRefreshToken: %v", err)
		}
		if refresh1 == "" {
			t.Fatal("empty refresh token")
		}

		// Consume it — should mint a new pair.
		pair, err := ConsumeRefreshToken(context.Background(), pool, refresh1, "viewer")
		if err != nil {
			t.Fatalf("ConsumeRefreshToken: %v", err)
		}
		if pair.AccessToken == "" || pair.RefreshToken == "" {
			t.Error("pair missing tokens")
		}
		if pair.RefreshToken == refresh1 {
			t.Error("new refresh token equals old (rotation did not produce new entropy)")
		}
		// Old row marked rotated.
		var rotatedTo *uuid.UUID
		err = pool.QueryRow(context.Background(),
			`SELECT rotated_to_id FROM refresh_tokens WHERE token_hash = sha256($1::bytea)`,
			[]byte(refresh1),
		).Scan(&rotatedTo)
		if err != nil {
			t.Fatalf("query rotated_to_id: %v", err)
		}
		if rotatedTo == nil {
			t.Error("old row's rotated_to_id is null after consume")
		}
	})
}

// @ac AC-13
// AC-13: ConsumeRefreshToken called twice with the same input returns
// ErrRefreshTokenReused on the second call; the user's session chain
// is invalidated (all active sessions revoked).
func TestRefresh_ReuseDetectionCascadeRevokes(t *testing.T) {
	t.Run("system-auth-identity/AC-13", func(t *testing.T) {
		ensureKey(t)
		pool := freshPool(t)
		userID := seedUser(t, pool, "ac13-user")

		// User has an active session (cookie path) AND a refresh token
		// (JWT path). Both should die when reuse is detected.
		_, _, err := IssueSession(context.Background(), pool, userID, "1.2.3.4", "browser")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}

		refresh1, err := IssueRefreshToken(context.Background(), pool, userID)
		if err != nil {
			t.Fatalf("IssueRefreshToken: %v", err)
		}
		// First consume — succeeds.
		if _, err := ConsumeRefreshToken(context.Background(), pool, refresh1, "ops_lead"); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		// Second consume — reuse detected.
		_, err = ConsumeRefreshToken(context.Background(), pool, refresh1, "ops_lead")
		if !errors.Is(err, ErrRefreshTokenReused) {
			t.Errorf("second consume err = %v, want ErrRefreshTokenReused", err)
		}

		// Cascade revoke: every session for this user is revoked.
		var activeSessions int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`,
			userID,
		).Scan(&activeSessions)
		if activeSessions != 0 {
			t.Errorf("active sessions for user after reuse = %d, want 0", activeSessions)
		}

		// Cascade revoke: every refresh token (including the newly-rotated
		// one) for this user is revoked.
		var activeRefresh int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`,
			userID,
		).Scan(&activeRefresh)
		if activeRefresh != 0 {
			t.Errorf("active refresh tokens for user after reuse = %d, want 0", activeRefresh)
		}

		// The reused row's reuse_detected_at is now populated.
		var detected *time.Time
		_ = pool.QueryRow(context.Background(),
			`SELECT reuse_detected_at FROM refresh_tokens WHERE token_hash = sha256($1::bytea)`,
			[]byte(refresh1),
		).Scan(&detected)
		if detected == nil {
			t.Error("reuse_detected_at not populated on the reused row")
		}
	})
}

// @ac AC-20
// AC-20: IssueJWT + VerifyJWT round-trip p99 < 5ms over 1000 calls.
// RS256 verify is the dominant cost.
func TestJWT_RoundTripLatency(t *testing.T) {
	t.Run("system-auth-identity/AC-20", func(t *testing.T) {
		ensureKey(t)
		userID, _ := uuid.NewV7()

		const n = 1000
		durs := make([]time.Duration, n)
		for i := 0; i < n; i++ {
			start := time.Now()
			signed, _, err := IssueJWT(userID, "viewer")
			if err != nil {
				t.Fatalf("IssueJWT: %v", err)
			}
			if _, err := VerifyJWT(signed); err != nil {
				t.Fatalf("VerifyJWT: %v", err)
			}
			durs[i] = time.Since(start)
		}
		// Insertion sort + p99 pick (n=1000 fits inline).
		for i := 1; i < n; i++ {
			v := durs[i]
			j := i - 1
			for j >= 0 && durs[j] > v {
				durs[j+1] = durs[j]
				j--
			}
			durs[j+1] = v
		}
		nn := n
		idx := int(float64(nn) * 0.99)
		p99 := durs[idx]
		budget := 5 * time.Millisecond * time.Duration(internalrace.Multiplier())
		if p99 > budget {
			t.Errorf("JWT round-trip p99 = %v, want < %v (spec target 5ms)", p99, budget)
		}
		t.Logf("JWT round-trip p99 = %v over %d calls (budget %v)", p99, n, budget)
	})
}

// VerifyJWT against a tampered token returns ErrJWTInvalid. Defensive
// test; not an AC.
func TestJWT_VerifyTampered(t *testing.T) {
	ensureKey(t)
	userID, _ := uuid.NewV7()
	signed, _, err := IssueJWT(userID, "viewer")
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}
	// Flip a byte in the middle of the signature (last segment).
	tampered := signed[:len(signed)-3] + "AAA"
	_, err = VerifyJWT(tampered)
	if !errors.Is(err, ErrJWTInvalid) {
		t.Errorf("err = %v, want ErrJWTInvalid", err)
	}
}
