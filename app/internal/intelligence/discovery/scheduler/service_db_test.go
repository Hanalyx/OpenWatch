// @spec system-discovery-scheduler
//
// AC traceability (this file):
//
//	AC-05  TestListDiscoveryTargets_FiltersHosts

package scheduler

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

// testDSN returns the DSN to test against, or skips when unset.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run discovery scheduler DB tests")
	}
	return dsn
}

// freshPool returns a pool against a migrated DB with hosts emptied.
func freshPool(t *testing.T) *pgxpool.Pool {
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
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	return pool
}

// seedUser inserts the FK target for hosts.created_by.
func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO users (id, username, email, password_hash)
		VALUES ($1, $2, $3, 'argon2-stub')`,
		id, "u-"+id.String()[:8], "u-"+id.String()[:8]+"@example.com")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// hostSeed describes one host row to insert.
type hostSeed struct {
	name             string
	osDiscoveredAt   *time.Time
	maintenanceMode  bool
	deletedAt        *time.Time
}

// seedHost inserts a single host row and returns its id.
func seedHost(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, seed hostSeed) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO hosts (id, hostname, ip_address, port, environment, created_by,
		                   os_discovered_at, maintenance_mode, deleted_at)
		VALUES ($1, $2, $3, 22, 'prod', $4, $5, $6, $7)`,
		id, seed.name, "192.0.2.1", userID, seed.osDiscoveredAt, seed.maintenanceMode, seed.deletedAt)
	if err != nil {
		t.Fatalf("seed host %s: %v", seed.name, err)
	}
	return id
}

// @ac AC-05
// AC-05: listDiscoveryTargets returns ONLY hosts that are
// non-deleted, non-maintenance, and either os_discovered_at NULL OR
// older than now() - IntervalSec. NULL-first ordering.
func TestListDiscoveryTargets_FiltersHosts(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		userID := seedUser(t, pool)

		now := time.Now().UTC()
		oldDiscovery := now.Add(-48 * time.Hour) // 48h old
		freshDiscovery := now.Add(-1 * time.Hour) // 1h old
		deletedAt := now.Add(-1 * time.Minute)

		h1 := seedHost(t, pool, userID, hostSeed{name: "h1-null"})
		h2 := seedHost(t, pool, userID, hostSeed{name: "h2-old", osDiscoveredAt: &oldDiscovery})
		_ = seedHost(t, pool, userID, hostSeed{name: "h3-fresh", osDiscoveredAt: &freshDiscovery})
		_ = seedHost(t, pool, userID, hostSeed{name: "h4-maint", maintenanceMode: true})
		_ = seedHost(t, pool, userID, hostSeed{name: "h5-deleted", deletedAt: &deletedAt})

		svc := NewService(pool)
		// IntervalSec = 24h → fresh (1h old) excluded, old (48h) included.
		got, err := svc.listDiscoveryTargets(context.Background(), 86400)
		if err != nil {
			t.Fatalf("listDiscoveryTargets: %v", err)
		}

		gotSet := map[uuid.UUID]bool{}
		for _, id := range got {
			gotSet[id] = true
		}

		if !gotSet[h1] {
			t.Errorf("h1 (NULL os_discovered_at) missing from results")
		}
		if !gotSet[h2] {
			t.Errorf("h2 (48h old os_discovered_at) missing from results")
		}
		if len(got) != 2 {
			t.Errorf("returned %d hosts, want exactly 2 (h1 + h2)", len(got))
		}
		// NULL-first ordering: h1 (NULL) before h2.
		if len(got) >= 2 && got[0] != h1 {
			t.Errorf("first result = %s, want h1 (NULL os_discovered_at sorts first)", got[0])
		}
	})
}
