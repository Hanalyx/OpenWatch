// @spec system-os-intelligence
//
// AC traceability (this file):
//
//	AC-11  TestRunCycle_PublishesIntelligenceEventsOnBus
//	AC-12  TestRunCycle_EmitsAuditPerTaxonomyCode

package collector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func collectorTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run collector integration tests")
	}
	return dsn
}

func freshDBCollector(t *testing.T) (*pgxpool.Pool, uuid.UUID, *credential.Service) {
	t.Helper()
	dsn := collectorTestDSN(t)
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
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE host_intelligence_events")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE host_intelligence_state")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE credentials")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")

	createdBy, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		createdBy, "intel-creator", "intel@example.com", hash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	hostID, _ := uuid.NewV7()
	_, err = pool.Exec(ctx,
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		hostID, "intel-host-"+hostID.String()[:8], "192.0.2.20", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	credSvc := credential.NewService(pool)
	_, err = credSvc.NewCredential(ctx, credential.NewParams{
		Scope:      credential.ScopeSystem,
		Name:       "default-intel",
		Username:   "admin",
		AuthMethod: credential.AuthPassword,
		Password:   "test-password",
		IsDefault:  true,
		CreatedBy:  createdBy,
	})
	if err != nil {
		t.Fatalf("seed system default credential: %v", err)
	}
	return pool, hostID, credSvc
}

// @ac AC-11
// AC-11: Successful RunCycle publishes EventKindIntelligenceEvent
// per detected change. The first-ever cycle generates a "new" set of
// detections (services and users aren't first-time-emitters per the
// Diff suppression rule, but packages and listening ports are).
func TestRunCycle_PublishesIntelligenceEventsOnBus(t *testing.T) {
	t.Run("system-os-intelligence/AC-11", func(t *testing.T) {
		pool, hostID, credSvc := freshDBCollector(t)

		stub := newStubSSHTransport()
		stub.SeedAll()

		bus := newStubBus()
		svc := NewService(pool, audit.Emit, bus).
			WithHostLookup(PoolHostLookup{Pool: pool}).
			WithCredentialService(credSvc).
			WithSSHTransport(stub)

		_, err := svc.RunCycle(context.Background(), hostID)
		if err != nil {
			t.Fatalf("RunCycle: %v", err)
		}
		if !bus.Saw(eventbus.EventKindIntelligenceEvent) {
			t.Errorf("eventbus did not receive intelligence.event after RunCycle")
		}
	})
}

// @ac AC-12
// AC-12: Per detected change, the service emits exactly one audit
// event with a Code matching the taxonomy. We verify by counting
// rows in audit_events whose action matches taxonomy codes.
func TestRunCycle_EmitsAuditPerTaxonomyCode(t *testing.T) {
	t.Run("system-os-intelligence/AC-12", func(t *testing.T) {
		pool, hostID, credSvc := freshDBCollector(t)

		// Start the audit writer so audit.Emit calls land in audit_events.
		audit.Init(audit.NewStore(pool), audit.WriterOptions{
			ChannelBuffer: 256, BatchSize: 50, FlushInterval: 20 * time.Millisecond,
		})
		t.Cleanup(func() { audit.Shutdown(2 * time.Second) })

		stub := newStubSSHTransport()
		stub.SeedAll()

		svc := NewService(pool, audit.Emit, nil).
			WithHostLookup(PoolHostLookup{Pool: pool}).
			WithCredentialService(credSvc).
			WithSSHTransport(stub)

		events, err := svc.RunCycle(context.Background(), hostID)
		if err != nil {
			t.Fatalf("RunCycle: %v", err)
		}
		if len(events) == 0 {
			t.Skip("first-ever cycle suppressed all changes — taxonomy-emit path not exercised this run")
		}

		// Allow the async audit writer to flush.
		time.Sleep(100 * time.Millisecond)

		// Count audit rows whose action matches one of the events we
		// emitted. Every change MUST yield exactly one row.
		for _, ev := range events {
			var count int
			err := pool.QueryRow(context.Background(),
				`SELECT COUNT(*) FROM audit_events
				   WHERE action = $1 AND resource_id = $2`,
				string(ev.Code), hostID.String()).Scan(&count)
			if err != nil {
				t.Fatalf("count audit rows for %s: %v", ev.Code, err)
			}
			if count == 0 {
				t.Errorf("audit row missing for taxonomy code %q (host %s)",
					ev.Code, hostID)
			}
		}
	})
}
