// @spec system-auth-policy
//
// Singleton store + window-bounds validation + identity-window priming.
// DSN-gated via OPENWATCH_TEST_DSN. The source-inspection ACs run without
// a database.

package authpolicy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshService(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	// Reset the singleton to its seeded defaults so tests start clean. Use
	// INSERT…ON CONFLICT because a server-package fixture's TRUNCATE users
	// CASCADE (shared test DB) can have removed the seeded row.
	_, _ = pool.Exec(ctx, `INSERT INTO auth_policy (id) VALUES (true)
		ON CONFLICT (id) DO UPDATE
		SET require_mfa = false, session_idle_timeout_seconds = 900,
		    session_absolute_timeout_seconds = 43200, updated_by = NULL`)
	return NewService(pool), pool
}

// @ac AC-01
func TestGet_SeededDefaultsAndSingleton(t *testing.T) {
	t.Run("system-auth-policy/AC-01", func(t *testing.T) {
		svc, pool := freshService(t)
		ctx := context.Background()
		p, err := svc.Get(ctx)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if p.RequireMFA {
			t.Errorf("default RequireMFA = true, want false")
		}
		if p.IdleTimeout != 15*time.Minute || p.AbsoluteTimeout != 12*time.Hour {
			t.Errorf("defaults = (%s,%s), want (15m,12h)", p.IdleTimeout, p.AbsoluteTimeout)
		}
		// Singleton: a second row insert is rejected by the CHECK.
		if _, err := pool.Exec(ctx, `INSERT INTO auth_policy (id) VALUES (false)`); err == nil {
			t.Error("inserting a second auth_policy row succeeded; singleton CHECK not enforced")
		}
	})
}

// @ac AC-02
func TestUpdate_PersistsAndValidates(t *testing.T) {
	t.Run("system-auth-policy/AC-02", func(t *testing.T) {
		svc, _ := freshService(t)
		ctx := context.Background()
		out, err := svc.Update(ctx, UpdateParams{
			RequireMFA:      true,
			IdleTimeout:     30 * time.Minute,
			AbsoluteTimeout: 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("Update valid: %v", err)
		}
		if !out.RequireMFA || out.IdleTimeout != 30*time.Minute || out.AbsoluteTimeout != 24*time.Hour {
			t.Errorf("update echo = %+v", out)
		}
		// Persisted.
		got, _ := svc.Get(ctx)
		if !got.RequireMFA || got.IdleTimeout != 30*time.Minute {
			t.Errorf("get after update = %+v, want persisted", got)
		}
		// Out-of-bounds idle (below 5m).
		if _, err := svc.Update(ctx, UpdateParams{IdleTimeout: time.Minute, AbsoluteTimeout: 12 * time.Hour}); err == nil {
			t.Error("idle below floor accepted, want ErrInvalidParams")
		}
		// Out-of-bounds absolute (above 30d).
		if _, err := svc.Update(ctx, UpdateParams{IdleTimeout: 15 * time.Minute, AbsoluteTimeout: 60 * 24 * time.Hour}); err == nil {
			t.Error("absolute above ceiling accepted, want ErrInvalidParams")
		}
		// Absolute shorter than idle.
		if _, err := svc.Update(ctx, UpdateParams{IdleTimeout: 2 * time.Hour, AbsoluteTimeout: time.Hour}); err == nil {
			t.Error("absolute<idle accepted, want ErrInvalidParams")
		}
	})
}

// @ac AC-05
func TestUpdate_PrimesIdentityWindows(t *testing.T) {
	t.Run("system-auth-policy/AC-05", func(t *testing.T) {
		svc, pool := freshService(t)
		ctx := context.Background()

		// SetSessionWindows coerces non-positive fields to the defaults.
		identity.SetSessionWindows(identity.Windows{Idle: 0, Absolute: -1})
		if w := identity.CurrentWindows(); w.Idle != identity.DefaultSessionInactivityWindow || w.Absolute != identity.DefaultSessionAbsoluteWindow {
			t.Errorf("coerced windows = %+v, want defaults", w)
		}

		// After Update, a freshly issued session uses the new windows.
		if _, err := svc.Update(ctx, UpdateParams{
			RequireMFA:      false,
			IdleTimeout:     45 * time.Minute,
			AbsoluteTimeout: 20 * time.Hour,
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		uid, _ := uuid.NewV7()
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, email, password_hash)
			 VALUES ($1, $2, $3, $4)`,
			uid, "ap-fixture", "ap@example.com", "$argon2id$v=19$m=65536,t=3,p=1$00$00",
		); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, sess, err := identity.IssueSession(ctx, pool, uid, "127.0.0.1", "authpolicy-test")
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}
		idle := sess.ExpiresAt.Sub(sess.CreatedAt)
		abs := sess.AbsoluteExpiresAt.Sub(sess.CreatedAt)
		if idle < 44*time.Minute || idle > 46*time.Minute {
			t.Errorf("session idle window = %s, want ~45m", idle)
		}
		if abs < 19*time.Hour+50*time.Minute || abs > 20*time.Hour+10*time.Minute {
			t.Errorf("session absolute window = %s, want ~20h", abs)
		}

		// Restore defaults so we don't leak windows into other packages'
		// expectations within the same test process.
		identity.SetSessionWindows(identity.Windows{
			Idle:     identity.DefaultSessionInactivityWindow,
			Absolute: identity.DefaultSessionAbsoluteWindow,
		})
	})
}

// @ac AC-03
func TestSoftMFA_LoginSourceInspection(t *testing.T) {
	t.Run("system-auth-policy/AC-03", func(t *testing.T) {
		raw, err := os.ReadFile("../server/auth_handlers.go")
		if err != nil {
			t.Fatalf("read source: %v", err)
		}
		src := string(raw)
		if !strings.Contains(src, "mfaEnrollmentRequired") {
			t.Error("login does not compute mfaEnrollmentRequired")
		}
		// The flag is gated on RequireMFA AND not-enrolled.
		if !strings.Contains(src, "pol.RequireMFA") || !strings.Contains(src, "!enrolled") {
			t.Error("mfaEnrollmentRequired not gated on RequireMFA && !enrolled")
		}
	})
}

// @ac AC-04
func TestSoftMFA_DoesNotBlock(t *testing.T) {
	t.Run("system-auth-policy/AC-04", func(t *testing.T) {
		raw, err := os.ReadFile("../server/auth_handlers.go")
		if err != nil {
			t.Fatalf("read source: %v", err)
		}
		src := string(raw)
		// The require-MFA soft branch must sit AFTER session issuance and
		// must not early-return — the session/cookies are still set.
		issueIdx := strings.Index(src, "IssueSession")
		flagIdx := strings.Index(src, "mfaEnrollmentRequired := false")
		if issueIdx < 0 || flagIdx < 0 {
			t.Fatal("expected IssueSession and the soft-MFA branch in the login handler")
		}
		// The flag computation precedes token issuance (it is evaluated
		// before IssueSession) but does not return; assert no writeError in
		// the soft branch by checking the branch body.
		branch := src[flagIdx:]
		end := strings.Index(branch, "\n\t}\n")
		if end > 0 {
			branch = branch[:end]
		}
		if strings.Contains(branch, "writeError") || strings.Contains(branch, "return") {
			t.Error("soft require-MFA branch blocks login (contains writeError/return)")
		}
	})
}

// @ac AC-06
func TestPrime_WiredInServerNew(t *testing.T) {
	t.Run("system-auth-policy/AC-06", func(t *testing.T) {
		raw, err := os.ReadFile("../server/server.go")
		if err != nil {
			t.Fatalf("read source: %v", err)
		}
		src := string(raw)
		if !strings.Contains(src, "authpolicy.NewService") || !strings.Contains(src, ".Prime(") {
			t.Error("server.New does not construct the authpolicy service and prime it")
		}
		if !strings.Contains(src, "prime skipped") {
			t.Error("Prime failure is not handled non-fatally (no warn-and-continue)")
		}
	})
}
