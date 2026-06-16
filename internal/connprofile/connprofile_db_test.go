// @spec system-connection-profile
//
// Connection-profile store integration tests. Skipped without
// OPENWATCH_TEST_DSN.

package connprofile

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run connprofile store integration tests")
	}
	return dsn
}

func seedHost(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	userID, _ := uuid.NewV7()
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		userID, "cp-creator-"+userID.String(), "cp-"+userID.String()+"@example.com", "x",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	hostID, _ := uuid.NewV7()
	if _, err := pool.Exec(ctx,
		`INSERT INTO hosts (id, hostname, ip_address, created_by) VALUES ($1, $2, $3::inet, $4)`,
		hostID, "cp-host-"+hostID.String(), "192.0.2.10", userID,
	); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return hostID
}

func freshStore(t *testing.T) (*Store, *pgxpool.Pool) {
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
	return NewStore(pool), pool
}

// @ac AC-01
// AC-01: Get on a host with no recorded profile returns a zero Profile
// (both dimensions unknown) and no error.
func TestGet_AbsentIsZeroNoError(t *testing.T) {
	t.Run("system-connection-profile/AC-01", func(t *testing.T) {
		store, pool := freshStore(t)
		hostID := seedHost(t, pool)
		got, err := store.Get(context.Background(), hostID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.SSHAuthMethod != AuthUnknown || got.SudoMode != SudoUnknown {
			t.Errorf("absent profile = %+v, want zero", got)
		}
	})
}

// @ac AC-02
// AC-02: recording one dimension never clobbers the other (COALESCE
// upsert), and re-recording overwrites that dimension.
func TestRecord_PartialUpsertPreservesOtherDimension(t *testing.T) {
	t.Run("system-connection-profile/AC-02", func(t *testing.T) {
		store, pool := freshStore(t)
		ctx := context.Background()
		hostID := seedHost(t, pool)

		// Record SSH auth only; sudo stays unknown.
		if err := store.RecordSSHAuth(ctx, hostID, AuthKey); err != nil {
			t.Fatalf("RecordSSHAuth: %v", err)
		}
		got, _ := store.Get(ctx, hostID)
		if got.SSHAuthMethod != AuthKey || got.SudoMode != SudoUnknown {
			t.Fatalf("after RecordSSHAuth = %+v, want {key, unknown}", got)
		}

		// Record sudo only; SSH auth must be preserved.
		if err := store.RecordSudoMode(ctx, hostID, SudoPassword); err != nil {
			t.Fatalf("RecordSudoMode: %v", err)
		}
		got, _ = store.Get(ctx, hostID)
		if got.SSHAuthMethod != AuthKey || got.SudoMode != SudoPassword {
			t.Fatalf("after RecordSudoMode = %+v, want {key, password}", got)
		}

		// Overwrite a dimension (host reconfigured key->password).
		if err := store.RecordSSHAuth(ctx, hostID, AuthPassword); err != nil {
			t.Fatalf("RecordSSHAuth overwrite: %v", err)
		}
		got, _ = store.Get(ctx, hostID)
		if got.SSHAuthMethod != AuthPassword || got.SudoMode != SudoPassword {
			t.Fatalf("after overwrite = %+v, want {password, password}", got)
		}
	})
}

// @ac AC-03
// AC-03: recording an unknown value is a no-op (callers may call
// unconditionally) and never creates a row.
func TestRecord_UnknownIsNoOp(t *testing.T) {
	t.Run("system-connection-profile/AC-03", func(t *testing.T) {
		store, pool := freshStore(t)
		ctx := context.Background()
		hostID := seedHost(t, pool)
		if err := store.RecordSSHAuth(ctx, hostID, AuthUnknown); err != nil {
			t.Fatalf("RecordSSHAuth(unknown): %v", err)
		}
		if err := store.RecordSudoMode(ctx, hostID, SudoUnknown); err != nil {
			t.Fatalf("RecordSudoMode(unknown): %v", err)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM host_connection_profile WHERE host_id = $1`, hostID).Scan(&n)
		if n != 0 {
			t.Errorf("unknown records created %d rows, want 0", n)
		}
	})
}
