// @spec system-api-tokens
//
// Hashed store + bearer authentication. DSN-gated via OPENWATCH_TEST_DSN.

package apitoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshService(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run apitoken tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	pool, err := db.NewPool(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("migrations.Apply: %v", err)
	}
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE api_tokens")
	return NewService(pool), pool
}

// @ac AC-01
func TestCreate_HashedNotPlaintext(t *testing.T) {
	t.Run("system-api-tokens/AC-01", func(t *testing.T) {
		svc, pool := freshService(t)
		ctx := context.Background()
		raw, tok, err := svc.Create(ctx, CreateParams{Name: "ci", RoleID: auth.RoleAuditor})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !strings.HasPrefix(raw, auth.APITokenPrefix) {
			t.Errorf("raw token %q lacks prefix %q", raw, auth.APITokenPrefix)
		}
		if !strings.HasPrefix(tok.Prefix, auth.APITokenPrefix) || len(tok.Prefix) >= len(raw) {
			t.Errorf("display prefix wrong: %q", tok.Prefix)
		}
		// Stored hash equals sha256(raw) and is not the raw bytes.
		var hash []byte
		_ = pool.QueryRow(ctx, `SELECT token_hash FROM api_tokens WHERE id=$1`, tok.ID).Scan(&hash)
		want := sha256.Sum256([]byte(raw))
		if !bytes.Equal(hash, want[:]) {
			t.Error("stored hash != sha256(raw)")
		}
		if bytes.Contains(hash, []byte(raw)) {
			t.Error("stored hash contains the raw token")
		}
	})
}

// @ac AC-02
func TestAuthenticate_Succeeds(t *testing.T) {
	t.Run("system-api-tokens/AC-02", func(t *testing.T) {
		svc, pool := freshService(t)
		ctx := context.Background()
		raw, tok, _ := svc.Create(ctx, CreateParams{Name: "ci", RoleID: auth.RoleOpsLead})
		id, err := svc.AuthenticateToken(ctx, raw)
		if err != nil {
			t.Fatalf("AuthenticateToken: %v", err)
		}
		if id.RoleID != auth.RoleOpsLead || id.ID == "" {
			t.Errorf("identity = %+v, want ops_lead role + non-empty id", id)
		}
		// last_used_at stamped.
		var lastUsed *time.Time
		_ = pool.QueryRow(ctx, `SELECT last_used_at FROM api_tokens WHERE id=$1`, tok.ID).Scan(&lastUsed)
		if lastUsed == nil {
			t.Error("last_used_at not stamped after authentication")
		}
	})
}

// @ac AC-03
func TestAuthenticate_RejectsBadTokens(t *testing.T) {
	t.Run("system-api-tokens/AC-03", func(t *testing.T) {
		svc, _ := freshService(t)
		ctx := context.Background()
		// Unknown.
		if _, err := svc.AuthenticateToken(ctx, auth.APITokenPrefix+"nope"); err != ErrInvalidToken {
			t.Errorf("unknown token err = %v, want ErrInvalidToken", err)
		}
		// Revoked.
		raw, tok, _ := svc.Create(ctx, CreateParams{Name: "r", RoleID: auth.RoleViewer})
		if err := svc.Revoke(ctx, tok.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if _, err := svc.AuthenticateToken(ctx, raw); err != ErrInvalidToken {
			t.Errorf("revoked token err = %v, want ErrInvalidToken", err)
		}
		// Revoke is idempotent.
		if err := svc.Revoke(ctx, tok.ID); err != nil {
			t.Errorf("second revoke: %v", err)
		}
		if err := svc.Revoke(ctx, uuid.New()); err != nil {
			t.Errorf("revoke missing: %v", err)
		}
		// Expired.
		past := time.Now().Add(-time.Hour)
		rawExp, _, _ := svc.Create(ctx, CreateParams{Name: "e", RoleID: auth.RoleViewer, ExpiresAt: &past})
		if _, err := svc.AuthenticateToken(ctx, rawExp); err != ErrInvalidToken {
			t.Errorf("expired token err = %v, want ErrInvalidToken", err)
		}
	})
}

// @ac AC-05
func TestListAndInvalidParams(t *testing.T) {
	t.Run("system-api-tokens/AC-05", func(t *testing.T) {
		svc, _ := freshService(t)
		ctx := context.Background()
		_, _, _ = svc.Create(ctx, CreateParams{Name: "a", RoleID: auth.RoleViewer})
		_, _, _ = svc.Create(ctx, CreateParams{Name: "b", RoleID: auth.RoleAuditor})
		list, err := svc.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("List len = %d, want 2", len(list))
		}
		// Empty name rejected.
		if _, _, err := svc.Create(ctx, CreateParams{Name: "  ", RoleID: auth.RoleViewer}); err == nil {
			t.Error("empty name should be rejected")
		}
		// Unknown role rejected (FK).
		if _, _, err := svc.Create(ctx, CreateParams{Name: "x", RoleID: auth.RoleID("not_a_role")}); err == nil {
			t.Error("unknown role should be rejected")
		}
	})
}
