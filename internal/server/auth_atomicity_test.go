// @spec system-auth-identity
//
// Atomicity of the administrative reset (C-34, C-36) and of MFA
// consumption with issuance at the HANDLER (C-35).
//
// Both failures are injected with a real database trigger rather than a
// code seam. A trigger error carries a SQLSTATE, so it is a DETERMINATE
// failure: exactly the kind that must roll the whole transaction back,
// and distinct from the indeterminate commit C-40 covers.

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

// failOnWrite installs a trigger that raises on writes to table, and
// returns a function that removes it. Deterministic: every matching
// statement fails, on every run.
func failOnWrite(t *testing.T, pool *pgxpool.Pool, table, event string) func() {
	t.Helper()
	ctx := context.Background()
	fn := "ow_test_fail_" + table
	trg := "ow_test_trg_" + table
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION %s() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'injected failure on %s';
		END; $$ LANGUAGE plpgsql`, fn, table)); err != nil {
		t.Fatalf("create trigger fn: %v", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`,
		trg, event, table, fn)); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	return func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s`, trg, table))
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn))
	}
}

func passwordHashOf(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var h string
	if err := pool.QueryRow(context.Background(),
		`SELECT password_hash FROM users WHERE username = $1`, username).Scan(&h); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	return h
}

// @ac AC-47
// AC-47: the administrative reset applies the password change and the
// user-wide interactive revocation in ONE transaction. A failure leaves
// neither, and a login cannot observe the password changed with the
// revocation incomplete.
func TestAdminReset_IsAtomicWithRevocation(t *testing.T) {
	t.Run("system-auth-identity/AC-47", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)
		const newPassword = "a-replacement-passphrase-Zz9" // pragma: allowlist secret

		t.Run("commits", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac47commit")
			before := passwordHashOf(t, pool, li.u.Username)
			if err := svc.AdminResetPassword(ctx, li.u.ID, newPassword); err != nil {
				t.Fatalf("reset: %v", err)
			}
			if passwordHashOf(t, pool, li.u.Username) == before {
				t.Error("the password hash did not change")
			}
			if s, r := liveCredentials(t, pool, li.u.ID); s != 0 || r != 0 {
				t.Errorf("credentials survived the reset: sessions=%d refresh=%d", s, r)
			}
			if got := loginFor(t, url, li.u.Username, li.u.Password, nil); got.status == http.StatusOK {
				t.Error("the OLD password still authenticates after a reset")
			}
			if got := loginFor(t, url, li.u.Username, newPassword, nil); got.status != http.StatusOK {
				t.Errorf("the new password = %d, want 200", got.status)
			}
		})

		t.Run("fails before commit", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac47rollback")
			before := passwordHashOf(t, pool, li.u.Username)
			beforeSessions, beforeRefresh := liveCredentials(t, pool, li.u.ID)
			if beforeSessions == 0 || beforeRefresh == 0 {
				t.Fatalf("precondition: want live credentials, got %d/%d", beforeSessions, beforeRefresh)
			}

			// The revocation half fails, INSIDE the reset's transaction.
			restore := failOnWrite(t, pool, "refresh_tokens", "UPDATE")
			err := svc.AdminResetPassword(ctx, li.u.ID, newPassword)
			restore()

			if err == nil {
				t.Fatal("the reset reported success while its revocation failed")
			}
			// The whole transaction rolled back, so the password is
			// UNCHANGED. The alternative is the worst state available: the
			// user locked out of their own account while every credential
			// minted from the old password still works.
			if got := passwordHashOf(t, pool, li.u.Username); got != before {
				t.Error("the password changed even though the revocation failed")
			}
			if s, r := liveCredentials(t, pool, li.u.ID); s != beforeSessions || r != beforeRefresh {
				t.Errorf("credentials changed on a failed reset: sessions %d->%d refresh %d->%d",
					beforeSessions, s, beforeRefresh, r)
			}
			// And the old password still works, consistently with the above.
			if got := loginFor(t, url, li.u.Username, li.u.Password, nil); got.status != http.StatusOK {
				t.Errorf("old password after a rolled-back reset = %d, want 200", got.status)
			}
		})

		t.Run("concurrent login attempt", func(t *testing.T) {
			li := loginFresh(t, url, pool, "ac47concurrent")

			// Hold the row so the login blocks, then let the reset run to
			// completion before the login proceeds. The login must see the
			// reset whole: password changed AND credentials revoked.
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			var one int
			if err := tx.QueryRow(ctx,
				`SELECT 1 FROM users WHERE id=$1 FOR NO KEY UPDATE`, li.u.ID).Scan(&one); err != nil {
				t.Fatalf("hold lock: %v", err)
			}
			done := make(chan loginOutcome, 1)
			go func() { done <- loginFor(t, url, li.u.Username, li.u.Password, nil) }()
			if !waitForUserLockWaiter(t, pool) {
				t.Fatal("the login never reached the lock")
			}
			if _, err := tx.Exec(ctx,
				`UPDATE users SET password_hash = 'reset-by-admin', last_password_change_at = now() WHERE id = $1`, // pragma: allowlist secret
				li.u.ID); err != nil {
				t.Fatalf("reset in tx: %v", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}

			if got := <-done; got.status == http.StatusOK {
				t.Error("a login issued credentials from a password the reset had replaced")
			}
		})
	})
}

// @ac AC-49
// AC-49: at the HANDLER, OTP consumption and issuance share one
// transaction. The helper-level AC-40 cannot prove this: DBTX accepts
// both a pool and a transaction, so only driving the real route shows
// which one the handler passed.
func TestLogin_OTPAndIssuanceShareTheTransaction(t *testing.T) {
	t.Run("system-auth-identity/AC-49", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		svc := users.NewService(pool, nil)

		u := seedAuthUser(t, svc, "ac49user", false)
		_ = svc.AssignRole(ctx, u.ID, "viewer", nil)
		uri, err := identity.EnrollMFA(ctx, pool, u.ID, u.Username)
		if err != nil {
			t.Fatalf("enroll: %v", err)
		}
		secret := ssoExtractSecret(t, uri)
		// Confirm enrollment so login requires an OTP. Done directly, so
		// the OTP generated below is the FIRST one this test consumes.
		if _, err := pool.Exec(ctx,
			`UPDATE auth_mfa_secrets SET last_verified_at = now() WHERE user_id = $1`, u.ID); err != nil {
			t.Fatalf("confirm enrollment: %v", err)
		}

		code, err := totp.GenerateCode(secret, time.Now().UTC())
		if err != nil {
			t.Fatalf("generate otp: %v", err)
		}
		otpUses := func() int {
			var n int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM auth_mfa_otp_uses WHERE user_id = $1`, u.ID).Scan(&n); err != nil {
				t.Fatalf("count otp uses: %v", err)
			}
			return n
		}
		if otpUses() != 0 {
			t.Fatalf("precondition: want no consumed OTPs, got %d", otpUses())
		}

		// Issuance fails AFTER the OTP validates, inside the login's
		// transaction: the session insert is the first issuance write.
		restore := failOnWrite(t, pool, "sessions", "INSERT")
		got := loginFor(t, url, u.Username, u.Password, &code)
		restore()

		if got.status == http.StatusOK {
			t.Fatalf("login succeeded despite a failing session insert (status %d)", got.status)
		}
		if n := otpUses(); n != 0 {
			t.Errorf("consumed OTPs after a login that issued nothing = %d, want 0: the code was burned", n)
		}
		if s, r := liveCredentials(t, pool, u.ID); s != 0 || r != 0 {
			t.Errorf("the failed login issued credentials: sessions=%d refresh=%d", s, r)
		}

		// The user-visible point: the same code still works.
		if again := loginFor(t, url, u.Username, u.Password, &code); again.status != http.StatusOK {
			t.Errorf("retry with the SAME OTP = %d (%s), want 200", again.status, again.code)
		}
	})
}

// ssoExtractSecret pulls the TOTP secret out of an otpauth:// URI.
func ssoExtractSecret(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse provisioning uri: %v", err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatal("provisioning uri carries no secret")
	}
	return secret
}
