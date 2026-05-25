// @spec system-host-inventory
//
// Host CRUD + tag + soft-delete tests. Skipped without OPENWATCH_TEST_DSN.

package host

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run host tests")
	}
	return dsn
}

// freshService returns a Service against a clean migrated DB with a
// seeded creator user (FK on hosts.created_by requires it).
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
	// Hosts cascade clears credentials' host-scope rows (FK ON DELETE RESTRICT
	// prevents that), so we truncate credentials first.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE credentials")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")

	createdBy, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		createdBy, "host-creator", "creator@example.com", hash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return NewService(pool), pool, createdBy
}

// @ac AC-01
// AC-01: Migration creates hosts with all required columns. Probe via
// information_schema so a future schema drift is caught here, not at
// first run.
func TestHosts_MigrationShape(t *testing.T) {
	t.Run("system-host-inventory/AC-01", func(t *testing.T) {
		_, pool, _ := freshService(t)
		mustHave := map[string]string{
			"id":          "uuid",
			"hostname":    "text",
			"ip_address":  "inet",
			"port":        "integer",
			"environment": "text",
			"tags":        "ARRAY",
			"group_id":    "uuid",
			"created_by":  "uuid",
			"created_at":  "timestamp with time zone",
			"updated_at":  "timestamp with time zone",
			"deleted_at":  "timestamp with time zone",
		}
		rows, err := pool.Query(context.Background(), `
			SELECT column_name, data_type
			FROM information_schema.columns
			WHERE table_name = 'hosts'`)
		if err != nil {
			t.Fatalf("info schema: %v", err)
		}
		defer rows.Close()
		cols := map[string]string{}
		for rows.Next() {
			var name, dtype string
			_ = rows.Scan(&name, &dtype)
			cols[name] = dtype
		}
		for name, want := range mustHave {
			if got, ok := cols[name]; !ok {
				t.Errorf("column %q missing", name)
			} else if got != want {
				t.Errorf("column %s type = %q, want %q", name, got, want)
			}
		}
	})
}

// @ac AC-02
// AC-02: Migration adds FK on credentials.scope_id → hosts(id).
func TestHosts_CredentialsFK(t *testing.T) {
	t.Run("system-host-inventory/AC-02", func(t *testing.T) {
		_, pool, _ := freshService(t)
		var exists bool
		err := pool.QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conname = 'credentials_scope_id_host_fk'
				  AND contype = 'f'
			)`).Scan(&exists)
		if err != nil {
			t.Fatalf("constraint check: %v", err)
		}
		if !exists {
			t.Error("credentials_scope_id_host_fk constraint not present")
		}
	})
}

// @ac AC-03
// AC-03: CreateHost persists; created_by FK enforced.
func TestCreateHost_PersistsAndFKEnforced(t *testing.T) {
	t.Run("system-host-inventory/AC-03", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		h, err := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "ac03.example.com", IPAddress: "192.0.2.10",
			Environment: "production", CreatedBy: createdBy,
			Tags: []string{"web", "critical"},
		})
		if err != nil {
			t.Fatalf("CreateHost: %v", err)
		}
		if h.Hostname != "ac03.example.com" || h.IPAddress != "192.0.2.10" {
			t.Errorf("returned host fields wrong: %+v", h)
		}
		if h.Port != 22 {
			t.Errorf("Port = %d, want default 22", h.Port)
		}
		// Unknown created_by → ErrInvalidCreator.
		unknown, _ := uuid.NewV7()
		_, err = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "ac03b.example.com", IPAddress: "192.0.2.11",
			CreatedBy: unknown,
		})
		if !errors.Is(err, ErrInvalidCreator) {
			t.Errorf("unknown created_by err = %v, want ErrInvalidCreator", err)
		}
	})
}

// @ac AC-04
// AC-04: Empty hostname → ErrInvalidHost.
func TestCreateHost_ValidationErrors(t *testing.T) {
	t.Run("system-host-inventory/AC-04", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		_, err := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "", IPAddress: "192.0.2.20", CreatedBy: createdBy,
		})
		if !errors.Is(err, ErrInvalidHost) {
			t.Errorf("empty hostname err = %v, want ErrInvalidHost", err)
		}
		_, err = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "ok.example.com", IPAddress: "not-an-ip", CreatedBy: createdBy,
		})
		if !errors.Is(err, ErrInvalidHost) {
			t.Errorf("bad IP err = %v, want ErrInvalidHost", err)
		}
	})
}

// @ac AC-05
// AC-05: Duplicate (hostname, environment) blocked among active rows.
func TestCreateHost_DuplicateBlocked(t *testing.T) {
	t.Run("system-host-inventory/AC-05", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		_, err := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "dup.example.com", IPAddress: "192.0.2.30",
			Environment: "production", CreatedBy: createdBy,
		})
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "dup.example.com", IPAddress: "192.0.2.31",
			Environment: "production", CreatedBy: createdBy,
		})
		if !errors.Is(err, ErrDuplicateHost) {
			t.Errorf("dup err = %v, want ErrDuplicateHost", err)
		}
		// Different environment — allowed.
		_, err = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "dup.example.com", IPAddress: "192.0.2.32",
			Environment: "staging", CreatedBy: createdBy,
		})
		if err != nil {
			t.Errorf("staging dup blocked: %v (different environment should be allowed)", err)
		}
	})
}

// @ac AC-06
// AC-06: After SoftDelete the (hostname, environment) pair is reusable.
func TestSoftDelete_HostnameReuse(t *testing.T) {
	t.Run("system-host-inventory/AC-06", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		h, _ := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "reusable.example.com", IPAddress: "192.0.2.40",
			Environment: "production", CreatedBy: createdBy,
		})
		if err := svc.SoftDelete(context.Background(), h.ID); err != nil {
			t.Fatalf("SoftDelete: %v", err)
		}
		_, err := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "reusable.example.com", IPAddress: "192.0.2.41",
			Environment: "production", CreatedBy: createdBy,
		})
		if err != nil {
			t.Errorf("reuse after delete: %v", err)
		}
	})
}

// @ac AC-07
// AC-07: GetByID returns host when active; ErrHostNotFound otherwise.
func TestGetByID_NotFoundOnDeleted(t *testing.T) {
	t.Run("system-host-inventory/AC-07", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		h, _ := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "ac07.example.com", IPAddress: "192.0.2.50",
			CreatedBy: createdBy,
		})
		got, err := svc.GetByID(context.Background(), h.ID)
		if err != nil || got.ID != h.ID {
			t.Errorf("GetByID active: err=%v id=%v", err, got.ID)
		}
		_ = svc.SoftDelete(context.Background(), h.ID)
		_, err = svc.GetByID(context.Background(), h.ID)
		if !errors.Is(err, ErrHostNotFound) {
			t.Errorf("after delete err = %v, want ErrHostNotFound", err)
		}
		unknown, _ := uuid.NewV7()
		_, err = svc.GetByID(context.Background(), unknown)
		if !errors.Is(err, ErrHostNotFound) {
			t.Errorf("unknown err = %v, want ErrHostNotFound", err)
		}
	})
}

// @ac AC-08
// AC-08: UpdateHost mutates supplied fields; preserves immutable ones.
func TestUpdateHost_PreservesImmutable(t *testing.T) {
	t.Run("system-host-inventory/AC-08", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		h, _ := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "ac08.example.com", IPAddress: "192.0.2.60", Port: 22,
			CreatedBy: createdBy,
		})
		newDesc := "new description"
		newPort := 2222
		newTags := []string{"web", "edge"}
		got, err := svc.UpdateHost(context.Background(), h.ID, UpdateParams{
			Description: &newDesc, Port: &newPort, Tags: &newTags,
		})
		if err != nil {
			t.Fatalf("UpdateHost: %v", err)
		}
		if got.Description != newDesc || got.Port != newPort {
			t.Errorf("mutable fields not applied: %+v", got)
		}
		if got.ID != h.ID || got.CreatedBy != h.CreatedBy || !got.CreatedAt.Equal(h.CreatedAt) {
			t.Errorf("immutable fields changed: original=%+v updated=%+v", h, got)
		}
		if !got.UpdatedAt.After(h.UpdatedAt) {
			t.Errorf("updated_at not bumped: before=%v after=%v", h.UpdatedAt, got.UpdatedAt)
		}
	})
}

// @ac AC-09
// AC-09: List with no filters returns all active hosts; deleted excluded.
func TestList_NoFiltersExcludesDeleted(t *testing.T) {
	t.Run("system-host-inventory/AC-09", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		h1, _ := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "list1.example.com", IPAddress: "192.0.2.70", CreatedBy: createdBy,
		})
		h2, _ := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "list2.example.com", IPAddress: "192.0.2.71", CreatedBy: createdBy,
		})
		_ = svc.SoftDelete(context.Background(), h2.ID)

		got, err := svc.List(context.Background(), ListParams{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("list count = %d, want 1 (one active, one deleted)", len(got))
		}
		if len(got) > 0 && got[0].ID != h1.ID {
			t.Errorf("got wrong host: %v want %v", got[0].ID, h1.ID)
		}
	})
}

// @ac AC-10
// AC-10: List filters by environment.
func TestList_EnvironmentFilter(t *testing.T) {
	t.Run("system-host-inventory/AC-10", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		_, _ = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "p1.example.com", IPAddress: "192.0.2.80", Environment: "production", CreatedBy: createdBy,
		})
		_, _ = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "p2.example.com", IPAddress: "192.0.2.81", Environment: "production", CreatedBy: createdBy,
		})
		_, _ = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "s1.example.com", IPAddress: "192.0.2.82", Environment: "staging", CreatedBy: createdBy,
		})
		got, err := svc.List(context.Background(), ListParams{Environment: "production"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("production count = %d, want 2", len(got))
		}
		for _, h := range got {
			if h.Environment != "production" {
				t.Errorf("non-production host returned: %v", h.Environment)
			}
		}
	})
}

// @ac AC-11
// AC-11: List filtered by tag uses array-membership query.
func TestList_TagFilter(t *testing.T) {
	t.Run("system-host-inventory/AC-11", func(t *testing.T) {
		svc, _, createdBy := freshService(t)
		_, _ = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "c1.example.com", IPAddress: "192.0.2.90", Tags: []string{"critical", "web"}, CreatedBy: createdBy,
		})
		_, _ = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "c2.example.com", IPAddress: "192.0.2.91", Tags: []string{"web"}, CreatedBy: createdBy,
		})
		_, _ = svc.CreateHost(context.Background(), CreateParams{
			Hostname: "c3.example.com", IPAddress: "192.0.2.92", Tags: []string{"critical", "db"}, CreatedBy: createdBy,
		})
		got, err := svc.List(context.Background(), ListParams{Tag: "critical"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("critical count = %d, want 2", len(got))
		}
		for _, h := range got {
			found := false
			for _, tag := range h.Tags {
				if tag == "critical" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("host without 'critical' tag returned: %v", h.Tags)
			}
		}
	})
}

// @ac AC-12
// AC-12: SoftDelete keeps the physical row. Verifiable by raw COUNT(*).
func TestSoftDelete_PhysicalRowSurvives(t *testing.T) {
	t.Run("system-host-inventory/AC-12", func(t *testing.T) {
		svc, pool, createdBy := freshService(t)
		h, _ := svc.CreateHost(context.Background(), CreateParams{
			Hostname: "soft.example.com", IPAddress: "192.0.2.100", CreatedBy: createdBy,
		})
		if err := svc.SoftDelete(context.Background(), h.ID); err != nil {
			t.Fatalf("SoftDelete: %v", err)
		}
		// Physical row still there.
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM hosts WHERE id = $1`, h.ID).Scan(&count)
		if count != 1 {
			t.Errorf("physical row count = %d, want 1 (soft delete should not erase)", count)
		}
		// deleted_at populated.
		var deletedAt *time.Time
		_ = pool.QueryRow(context.Background(),
			`SELECT deleted_at FROM hosts WHERE id = $1`, h.ID).Scan(&deletedAt)
		if deletedAt == nil {
			t.Error("deleted_at not populated")
		}
		// Service-layer lookup returns ErrHostNotFound.
		_, err := svc.GetByID(context.Background(), h.ID)
		if !errors.Is(err, ErrHostNotFound) {
			t.Errorf("GetByID after delete err = %v, want ErrHostNotFound", err)
		}
	})
}
