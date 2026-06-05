// @spec system-credential-store
//
// Credential store + resolver tests. Skipped without OPENWATCH_TEST_DSN.

package credential

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run credential tests")
	}
	return dsn
}

// freshService returns a Service against a clean migrated DB with the
// ephemeral DEK installed. Also seeds a single user to satisfy the
// created_by FK on the credentials table.
func freshService(t *testing.T) (*Service, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	dsn := testDSN(t)
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
	if err := secretkey.SetEphemeral(); err != nil {
		t.Fatalf("SetEphemeral: %v", err)
	}
	// Truncate credentials AND users so seeding a fresh user doesn't
	// hit unique-violation on previous runs. user_roles + sessions
	// cascade off users.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE credentials")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")

	// Seed a creator user.
	createdBy, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		createdBy, "credential-creator", "creator@example.com", hash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return NewService(pool), pool, createdBy
}

// seedHost inserts a minimal hosts row so tests that need host-scope
// credentials can satisfy the credentials.scope_id → hosts.id FK
// (migration 0008, DEFERRABLE INITIALLY DEFERRED). Returns the new id.
func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	hostID, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		hostID, "test-host-"+hostID.String()[:8], "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return hostID
}

// @ac AC-01
// AC-01: Migration creates credentials with all required columns + CHECK
// constraints. We can probe this by attempting an invalid insert and
// confirming the DB rejects it.
func TestCredentials_Migration(t *testing.T) {
	t.Run("system-credential-store/AC-01", func(t *testing.T) {
		_, pool, createdBy := freshService(t)
		id, _ := uuid.NewV7()
		// Attempt a scope='host' with NULL scope_id — CHECK should reject.
		_, err := pool.Exec(context.Background(),
			`INSERT INTO credentials (id, scope, scope_id, name, username, auth_method,
			                          encrypted_password, is_default, is_active, created_by)
			 VALUES ($1, 'host', NULL, 'badrow', 'u', 'password', '\x01'::bytea, false, true, $2)`,
			id, createdBy)
		if err == nil {
			t.Error("CHECK constraint missing: scope=host with NULL scope_id should be rejected")
		}
		// Attempt invalid scope.
		_, err = pool.Exec(context.Background(),
			`INSERT INTO credentials (id, scope, scope_id, name, username, auth_method,
			                          encrypted_password, is_default, is_active, created_by)
			 VALUES ($1, 'rubbish', NULL, 'badrow2', 'u', 'password', '\x01'::bytea, false, true, $2)`,
			id, createdBy)
		if err == nil {
			t.Error("CHECK constraint missing: scope='rubbish' should be rejected")
		}
	})
}

// @ac AC-02
// AC-02: NewCredential persists the row; encrypted_password column is
// NOT the plaintext bytes.
func TestNewCredential_EncryptsAtRest(t *testing.T) {
	t.Run("system-credential-store/AC-02", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		plainPw := "plaintext-password-which-must-be-encrypted"
		id, err := svc.NewCredential(context.Background(), NewParams{
			Scope:      ScopeSystem,
			Name:       "default ops",
			Username:   "admin",
			AuthMethod: AuthPassword,
			Password:   plainPw,
			IsDefault:  true,
			CreatedBy:  createdBy,
		})
		if err != nil {
			t.Fatalf("NewCredential: %v", err)
		}
		var enc []byte
		_ = pool.QueryRow(context.Background(),
			`SELECT encrypted_password FROM credentials WHERE id = $1`, id,
		).Scan(&enc)
		if len(enc) == 0 {
			t.Fatal("encrypted_password is empty")
		}
		if bytes.Contains(enc, []byte(plainPw)) {
			t.Error("plaintext password appears in encrypted_password column — encryption broken")
		}
	})
}

// @ac AC-03
// AC-03: scope=host with nil scope_id → ErrInvalidScope; no row inserted.
func TestNewCredential_HostRequiresScopeID(t *testing.T) {
	t.Run("system-credential-store/AC-03", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		_, err := svc.NewCredential(context.Background(), NewParams{
			Scope:      ScopeHost,
			ScopeID:    nil,
			Name:       "bad-host-scope",
			Username:   "x",
			AuthMethod: AuthPassword,
			Password:   "pw",
			CreatedBy:  createdBy,
		})
		if !errors.Is(err, ErrInvalidScope) {
			t.Errorf("err = %v, want ErrInvalidScope", err)
		}
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM credentials`).Scan(&count)
		if count != 0 {
			t.Errorf("rows = %d, want 0 (no row should be written)", count)
		}
	})
}

// @ac AC-04
// AC-04: scope=system with non-nil scope_id → ErrInvalidScope.
func TestNewCredential_SystemRejectsScopeID(t *testing.T) {
	t.Run("system-credential-store/AC-04", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		hid, _ := uuid.NewV7()
		_, err := svc.NewCredential(context.Background(), NewParams{
			Scope:      ScopeSystem,
			ScopeID:    &hid,
			Name:       "bad-system-scope",
			Username:   "x",
			AuthMethod: AuthPassword,
			Password:   "pw",
			CreatedBy:  createdBy,
		})
		if !errors.Is(err, ErrInvalidScope) {
			t.Errorf("err = %v, want ErrInvalidScope", err)
		}
	})
}

// @ac AC-05
// AC-05: auth_method=ssh_key without a private key → ErrMissingSecret.
func TestNewCredential_SSHKeyRequiresPrivateKey(t *testing.T) {
	t.Run("system-credential-store/AC-05", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		_, err := svc.NewCredential(context.Background(), NewParams{
			Scope:      ScopeSystem,
			Name:       "no-key",
			Username:   "x",
			AuthMethod: AuthSSHKey,
			CreatedBy:  createdBy,
		})
		if !errors.Is(err, ErrMissingSecret) {
			t.Errorf("err = %v, want ErrMissingSecret", err)
		}
	})
}

// @ac AC-06
// AC-06: auth_method=password without a password → ErrMissingSecret.
func TestNewCredential_PasswordRequiresPassword(t *testing.T) {
	t.Run("system-credential-store/AC-06", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		_, err := svc.NewCredential(context.Background(), NewParams{
			Scope:      ScopeSystem,
			Name:       "no-pw",
			Username:   "x",
			AuthMethod: AuthPassword,
			CreatedBy:  createdBy,
		})
		if !errors.Is(err, ErrMissingSecret) {
			t.Errorf("err = %v, want ErrMissingSecret", err)
		}
	})
}

// @ac AC-07
// AC-07: auth_method=both populates BOTH encrypted_password and
// encrypted_private_key.
func TestNewCredential_BothMethodPopulatesBoth(t *testing.T) {
	t.Run("system-credential-store/AC-07", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		id, err := svc.NewCredential(context.Background(), NewParams{
			Scope:      ScopeSystem,
			Name:       "both-method",
			Username:   "x",
			AuthMethod: AuthBoth,
			Password:   "pw",
			PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
			CreatedBy:  createdBy,
		})
		if err != nil {
			t.Fatalf("NewCredential: %v", err)
		}
		var pwLen, keyLen int
		_ = pool.QueryRow(context.Background(),
			`SELECT octet_length(encrypted_password), octet_length(encrypted_private_key)
			   FROM credentials WHERE id = $1`, id,
		).Scan(&pwLen, &keyLen)
		if pwLen == 0 || keyLen == 0 {
			t.Errorf("encrypted_password=%d, encrypted_private_key=%d — both required for AuthBoth", pwLen, keyLen)
		}
	})
}

// @ac AC-08
// AC-08: A second is_default=true on scope=system while another is active
// returns ErrMultipleSystemDefaults.
func TestNewCredential_OneSystemDefault(t *testing.T) {
	t.Run("system-credential-store/AC-08", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		_, err := svc.NewCredential(context.Background(), NewParams{
			Scope: ScopeSystem, Name: "first-default", Username: "u",
			AuthMethod: AuthPassword, Password: "pw", IsDefault: true, CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err = svc.NewCredential(context.Background(), NewParams{
			Scope: ScopeSystem, Name: "second-default", Username: "u",
			AuthMethod: AuthPassword, Password: "pw", IsDefault: true, CreatedBy: createdBy,
		})
		if !errors.Is(err, ErrMultipleSystemDefaults) {
			t.Errorf("err = %v, want ErrMultipleSystemDefaults", err)
		}
	})
}

// @ac AC-09
// AC-09: GetByID returns a Credential with decrypted secret fields.
func TestGetByID_DecryptsSecrets(t *testing.T) {
	t.Run("system-credential-store/AC-09", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		plainPw := "decrypt-me-please"
		id, err := svc.NewCredential(context.Background(), NewParams{
			Scope: ScopeSystem, Name: "decrypt-test", Username: "u",
			AuthMethod: AuthPassword, Password: plainPw, IsDefault: false, CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("NewCredential: %v", err)
		}
		got, err := svc.GetByID(context.Background(), id)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.Password != plainPw {
			t.Errorf("decrypted password = %q, want %q", got.Password, plainPw)
		}
		if got.Username != "u" {
			t.Errorf("username mismatch")
		}
	})
}

// @ac AC-10
// AC-10: Resolve returns the host-scope credential when one exists.
func TestResolve_HostScopeWins(t *testing.T) {
	t.Run("system-credential-store/AC-10", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		hostID := seedHost(t, pool, createdBy)
		// System default exists.
		_, err := svc.NewCredential(context.Background(), NewParams{
			Scope: ScopeSystem, Name: "sys-default", Username: "sys",
			AuthMethod: AuthPassword, Password: "system-pw", IsDefault: true, CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("system default: %v", err)
		}
		// Host-scope credential exists too.
		_, err = svc.NewCredential(context.Background(), NewParams{
			Scope: ScopeHost, ScopeID: &hostID, Name: "host-override", Username: "host",
			AuthMethod: AuthPassword, Password: "host-pw", CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("host-scope: %v", err)
		}
		got, err := svc.Resolve(context.Background(), hostID)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got.Username != "host" {
			t.Errorf("Resolve picked username = %q, want host (host-scope must win)", got.Username)
		}
		if got.Scope != ScopeHost {
			t.Errorf("Resolve scope = %q, want host", got.Scope)
		}
	})
}

// @ac AC-11
// AC-11: Resolve returns the system default when host has no
// host-scope credential.
func TestResolve_FallsBackToSystemDefault(t *testing.T) {
	t.Run("system-credential-store/AC-11", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		hostID, _ := uuid.NewV7()
		_, err := svc.NewCredential(context.Background(), NewParams{
			Scope: ScopeSystem, Name: "only-system", Username: "sys",
			AuthMethod: AuthPassword, Password: "system-pw", IsDefault: true, CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("system default: %v", err)
		}
		got, err := svc.Resolve(context.Background(), hostID)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got.Scope != ScopeSystem {
			t.Errorf("scope = %q, want system", got.Scope)
		}
		if got.Username != "sys" {
			t.Errorf("username = %q, want sys", got.Username)
		}
	})
}

// @ac AC-12
// AC-12: Resolve returns ErrNoCredential when neither host nor system
// default is available.
func TestResolve_NoCredentialAvailable(t *testing.T) {
	t.Run("system-credential-store/AC-12", func(t *testing.T) {
		svc, _, _ := freshService(t)
		hostID, _ := uuid.NewV7()
		_, err := svc.Resolve(context.Background(), hostID)
		if !errors.Is(err, ErrNoCredential) {
			t.Errorf("err = %v, want ErrNoCredential", err)
		}
	})
}
