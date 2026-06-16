// @spec system-auth-identity
//
// Session lifecycle tests (ACs 06-10). Skipped without
// OPENWATCH_TEST_DSN since every test exercises the real sessions
// table.

package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// freshPool returns a pool against a migrated DB with sessions/users empty.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	// Cascade clears sessions + refresh_tokens + mfa via FK ON DELETE CASCADE.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	return pool
}

// seedUser inserts a minimal users row and returns its UUID. Tests
// that need a session need a user; this saves boilerplate.
func seedUser(t *testing.T, pool *pgxpool.Pool, username string) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	hash, err := HashPassword("seed-user-pw-12345")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		id, username, username+"@example.com", hash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// @ac AC-06
// AC-06: IssueSession persists a row with the hashed token, the user,
// expires_at = now + 15min, absolute_expires_at = now + 12h, and
// returns the presentation token.
func TestSession_Issue(t *testing.T) {
	t.Run("system-auth-identity/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "ac06-user")
		before := time.Now().UTC()

		token, sess, err := IssueSession(context.Background(), pool, userID, "1.2.3.4", "go-test")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}
		if token == "" {
			t.Fatal("token is empty")
		}
		if len(token) < 32 {
			t.Errorf("token length = %d, want >= 32 (256-bit entropy URL-safe encoded)", len(token))
		}
		if sess.UserID != userID {
			t.Errorf("UserID mismatch")
		}
		// Inactivity window: 15 min ± 5s for clock skew.
		if d := sess.ExpiresAt.Sub(before); d < 14*time.Minute+55*time.Second || d > 15*time.Minute+5*time.Second {
			t.Errorf("expires_at delta = %v, want ~15m", d)
		}
		// Absolute window: 12 hr ± 5s.
		if d := sess.AbsoluteExpiresAt.Sub(before); d < 12*time.Hour-5*time.Second || d > 12*time.Hour+5*time.Second {
			t.Errorf("absolute_expires_at delta = %v, want ~12h", d)
		}
		// Token is stored as SHA-256; presentation form is not in the DB.
		hash := sha256.Sum256([]byte(token))
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM sessions WHERE token_hash = $1`, hash[:],
		).Scan(&count)
		if count != 1 {
			t.Errorf("sessions row for hash count = %d, want 1", count)
		}
	})
}

// @ac AC-07
// AC-07: VerifySession against a valid token returns the Identity;
// touches last_seen; extends expires_at by 15 min but never past
// absolute_expires_at.
func TestSession_VerifyExtends(t *testing.T) {
	t.Run("system-auth-identity/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "ac07-user")
		token, sess, err := IssueSession(context.Background(), pool, userID, "", "")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}
		// Roll the DB expires_at backwards by 10 min so we can observe the
		// extension. Real production uses wall-clock; this is the only way
		// to assert "the extension happened" without sleeping 10 min in a test.
		_, err = pool.Exec(context.Background(),
			`UPDATE sessions SET expires_at = expires_at - interval '10 minutes',
			                     last_seen  = last_seen  - interval '10 minutes'
			 WHERE id = $1`, sess.ID)
		if err != nil {
			t.Fatalf("adjust expires: %v", err)
		}

		got, err := VerifySession(context.Background(), pool, token)
		if err != nil {
			t.Fatalf("VerifySession: %v", err)
		}
		if got.ID != sess.ID {
			t.Errorf("session ID mismatch")
		}
		// After verify, expires_at must be ~now + 15min (we rolled it back
		// 10 min; verify extends to now+15min, which is +25 min from the
		// rolled value).
		if got.ExpiresAt.Before(time.Now().UTC().Add(14 * time.Minute)) {
			t.Errorf("expires_at not extended: %v", got.ExpiresAt)
		}
		// Last seen touched.
		if time.Since(got.LastSeen) > time.Second {
			t.Errorf("last_seen not touched (delta = %v)", time.Since(got.LastSeen))
		}
	})
}

// @ac AC-08
// AC-08: VerifySession against a revoked token returns ErrSessionRevoked.
func TestSession_VerifyRevoked(t *testing.T) {
	t.Run("system-auth-identity/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "ac08-user")
		token, sess, err := IssueSession(context.Background(), pool, userID, "", "")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}
		if err := RevokeSession(context.Background(), pool, sess.ID); err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		_, err = VerifySession(context.Background(), pool, token)
		if !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("err = %v, want ErrSessionRevoked", err)
		}
	})
}

// @ac AC-09
// AC-09: RevokeSession sets revoked_at; subsequent VerifySession
// returns ErrSessionRevoked. Idempotent — revoking twice is fine.
func TestSession_Revoke(t *testing.T) {
	t.Run("system-auth-identity/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "ac09-user")
		token, sess, err := IssueSession(context.Background(), pool, userID, "", "")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}
		if err := RevokeSession(context.Background(), pool, sess.ID); err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		// Idempotent: second revoke is a no-op.
		if err := RevokeSession(context.Background(), pool, sess.ID); err != nil {
			t.Errorf("RevokeSession (2nd call): %v", err)
		}
		// revoked_at populated.
		var rt *time.Time
		_ = pool.QueryRow(context.Background(),
			`SELECT revoked_at FROM sessions WHERE id = $1`, sess.ID,
		).Scan(&rt)
		if rt == nil {
			t.Error("revoked_at not populated")
		}
		// Verify returns the revoked error.
		_, err = VerifySession(context.Background(), pool, token)
		if !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("err = %v, want ErrSessionRevoked", err)
		}
	})
}

// @ac AC-10
// AC-10: VerifySession against a token whose absolute_expires_at has
// passed returns ErrSessionExpired even if last_seen was recent.
func TestSession_AbsoluteTimeout(t *testing.T) {
	t.Run("system-auth-identity/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool, "ac10-user")
		token, sess, err := IssueSession(context.Background(), pool, userID, "", "")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}
		// Roll absolute_expires_at into the past; leave expires_at and
		// last_seen in the present. The session is "active" by inactivity
		// terms but past the 12-hour ceiling.
		_, err = pool.Exec(context.Background(),
			`UPDATE sessions SET absolute_expires_at = now() - interval '1 minute' WHERE id = $1`,
			sess.ID)
		if err != nil {
			t.Fatalf("adjust absolute_expires_at: %v", err)
		}
		_, err = VerifySession(context.Background(), pool, token)
		if !errors.Is(err, ErrSessionExpired) {
			t.Errorf("err = %v, want ErrSessionExpired", err)
		}
	})
}

// VerifySession with a never-issued token returns ErrSessionNotFound.
// Not an AC; defensive sanity check.
func TestSession_VerifyUnknownToken(t *testing.T) {
	pool := freshPool(t)
	_, err := VerifySession(context.Background(), pool, "never-issued-this-token")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("err = %v, want ErrSessionNotFound", err)
	}
}
