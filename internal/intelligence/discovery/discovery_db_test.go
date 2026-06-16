// @spec system-host-discovery
//
// AC traceability (this file):
//
//	AC-08  TestDiscover_HappyPath_PersistsAndPublishes

package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// freshDBHost spins up a clean DB, seeds a user + host + a host-scope
// SSH credential, and returns the host id + a usable credential.Service.
func freshDBHost(t *testing.T) (*pgxpool.Pool, uuid.UUID, *credential.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	if err := secretkey.SetEphemeral(); err != nil {
		t.Fatalf("SetEphemeral: %v", err)
	}
	// CASCADE — see scheduler/service_db_test.go for the rationale.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")

	createdBy, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		createdBy, "disc-creator", "disc@example.com", hash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	hostID, _ := uuid.NewV7()
	_, err = pool.Exec(ctx,
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		hostID, "test-host-"+hostID.String()[:8], "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	credSvc := credential.NewService(pool)
	_, err = credSvc.NewCredential(ctx, credential.NewParams{
		Scope:      credential.ScopeSystem,
		Name:       "default-disc",
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

// @ac AC-08
// AC-08: Discover end-to-end on a reachable host with a valid
// credential persists host_system_info, updates hosts.os_*, and returns
// the captured facts. The stub SSH transport stands in for a real host
// — the path through the service (lookup → resolve → dial → probe
// batch → persist → publish → audit) is otherwise the same as
// production.
func TestDiscover_HappyPath_PersistsAndPublishes(t *testing.T) {
	t.Run("system-host-discovery/AC-08", func(t *testing.T) {
		pool, hostID, credSvc := freshDBHost(t)

		stub := newStubSSHTransport()
		stub.SeedAll()

		emits := newAuditRecorder()
		bus := newStubBus()
		svc := NewService(pool, emits.Emit, bus).
			WithHostLookup(PoolHostLookup{Pool: pool}).
			WithCredentialService(credSvc).
			WithSSHTransport(stub)

		facts, err := svc.Discover(context.Background(), hostID)
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}

		// Sanity on returned facts.
		if facts.OSName == "" || facts.OSFamily == "" {
			t.Errorf("Discover returned empty OSName=%q OSFamily=%q — fixtures should have populated them", facts.OSName, facts.OSFamily)
		}
		// Spec C-08: row UPSERTed into host_system_info.
		var (
			osName string
			osFam  string
			collAt time.Time
		)
		err = pool.QueryRow(context.Background(),
			`SELECT os_name, os_family, collected_at
			   FROM host_system_info
			  WHERE host_id = $1`, hostID).Scan(&osName, &osFam, &collAt)
		if err != nil {
			t.Fatalf("read host_system_info: %v", err)
		}
		if osName == "" || osFam == "" {
			t.Errorf("host_system_info missing fields: os_name=%q os_family=%q", osName, osFam)
		}
		// Spec C-09: denormalized hosts.os_* columns also updated.
		var hostOSFam *string
		err = pool.QueryRow(context.Background(),
			`SELECT os_family FROM hosts WHERE id = $1`, hostID).Scan(&hostOSFam)
		if err != nil {
			t.Fatalf("read hosts.os_family: %v", err)
		}
		if hostOSFam == nil || *hostOSFam == "" {
			t.Errorf("hosts.os_family is empty after Discover — denormalized column not updated")
		}
		// AC-11 sanity: bus saw the event. (AC-11 has its own test too;
		// this is just defensive against silently dropping the publish.)
		if !bus.Saw("host.discovered") {
			t.Errorf("eventbus did not receive host.discovered")
		}
		// AC-12 sanity: audit emitted exactly once. (AC-12 also has its
		// own test; defensive duplication is cheap.)
		if got := emits.CountFor("host.discovery.completed"); got != 1 {
			t.Errorf("audit emits for host.discovery.completed = %d, want 1", got)
		}
	})
}
