// @spec system-scheduler
//
// AC traceability (this file):
//   AC-04  TestDispatch_SkipLocked_DisjointClaim
//          TestDispatch_FuturesNotClaimed
//   AC-05  TestDispatch_MaintenanceMode_RowSkipped
//   AC-13  TestDispatch_EmitsScheduleUpdated

package scheduler

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// freshPool returns a pool against a clean schedule + queue state.
// Applies all migrations (including 0011) and truncates the tables this
// package writes to.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()

	// Truncate everything the scheduler touches, in FK order.
	for _, stmt := range []string{
		"TRUNCATE TABLE host_backoff_state CASCADE",
		"TRUNCATE TABLE host_compliance_schedule CASCADE",
		"TRUNCATE TABLE job_queue CASCADE",
		"TRUNCATE TABLE groups CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
		"TRUNCATE TABLE audit_events CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			// Acceptable failure: table may not exist on some migration
			// states; the next test's migration apply re-creates them.
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

// seedUser inserts a minimal users row so hosts.created_by FK is
// satisfiable.
func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "scheduler-test-user", "stu@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// seedHost inserts a minimal hosts row so the FK on
// host_compliance_schedule.host_id is satisfied. Returns the new id.
// Uses the full UUID in the hostname so the hostname/environment/active
// unique index can't collide across rapidly-created seeds.
func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		id, "host-"+id.String(), "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// seedSchedule inserts a host_compliance_schedule row that is due now,
// not in maintenance.
func seedSchedule(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, opts ...func(*scheduleSeed)) {
	t.Helper()
	cfg := scheduleSeed{
		state:       StateCritical, // due-now and 1h interval makes the math obvious
		next:        time.Now().Add(-1 * time.Minute),
		maintenance: false,
	}
	for _, o := range opts {
		o(&cfg)
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_compliance_schedule
			(host_id, compliance_state, next_scheduled_scan, maintenance_mode)
		VALUES ($1, $2, $3, $4)`,
		hostID, string(cfg.state), cfg.next, cfg.maintenance)
	if err != nil {
		t.Fatalf("seed schedule: %v", err)
	}
}

type scheduleSeed struct {
	state       ComplianceState
	next        time.Time
	maintenance bool
}

func withNext(t time.Time) func(*scheduleSeed) { return func(c *scheduleSeed) { c.next = t } }

// setHostMaintenance flips hosts.maintenance_mode — the per-host flag the
// host-detail toggle writes and the dispatcher (via host_effective_maintenance)
// now honors.
func setHostMaintenance(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, on bool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE hosts SET maintenance_mode = $2 WHERE id = $1`, hostID, on)
	if err != nil {
		t.Fatalf("set host maintenance: %v", err)
	}
}

// seedManualMaintenanceGroup creates a manual group with maintenance=true and
// adds hostID as a member — the per-group maintenance path.
func seedManualMaintenanceGroup(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) {
	t.Helper()
	gid, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO groups (id, name, kind, membership, maintenance)
		 VALUES ($1, $2, 'site', 'manual', true)`, gid, "maint-"+gid.String())
	if err != nil {
		t.Fatalf("seed maintenance group: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO group_members (group_id, host_id) VALUES ($1, $2)`, gid, hostID); err != nil {
		t.Fatalf("seed group member: %v", err)
	}
}

// newTestService builds a Service ready for Dispatch with a deterministic
// clock pinned to a passed-in time. Uses an in-memory audit recorder so
// the test can assert on emissions. The recorder's append is guarded
// by emitMu so concurrent-Dispatch tests stay race-clean.
func newTestService(t *testing.T, pool *pgxpool.Pool, now time.Time, calls *[]emitCall) *Service {
	t.Helper()
	ladder := LoadIntervals(validTiers()).Ladder
	load := LoadResult{Ladder: ladder, PolicyVersion: "1.0.0"}

	emit := func(ctx context.Context, code audit.Code, ev audit.Event) {
		emitMu.Lock()
		defer emitMu.Unlock()
		*calls = append(*calls, emitCall{Code: code, Event: ev})
	}

	svc := NewService(pool, load, testKey(), emit)
	svc.Now = func() time.Time { return now }
	return svc
}

// emitMu serializes appends to the *[]emitCall recorder from concurrent
// Dispatch goroutines in AC-04's SKIP-LOCKED test.
var emitMu sync.Mutex

// withCorrelation seeds a correlation_id into the context (required by
// queue.Enqueue).
func withCorrelation(ctx context.Context, id string) context.Context {
	return correlation.Set(ctx, id)
}

// @ac AC-04
// AC-04: Two concurrent Dispatch calls claim DISJOINT host sets via
// FOR UPDATE SKIP LOCKED. The union of their claims equals the full set
// of due rows; no host appears in both, no host is missed.
func TestDispatch_SkipLocked_DisjointClaim(t *testing.T) {
	t.Run("system-scheduler/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		const N = 12
		var hostIDs []uuid.UUID
		for i := 0; i < N; i++ {
			h := seedHost(t, pool, user)
			seedSchedule(t, pool, h)
			hostIDs = append(hostIDs, h)
		}

		var calls []emitCall
		now := time.Now()
		svc := newTestService(t, pool, now, &calls)

		// Two concurrent Dispatch goroutines. Each gets its own ctx
		// (and its own correlation_id) so queue.Enqueue accepts.
		var (
			wg             sync.WaitGroup
			countA, countB int
			errA, errB     error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			ctx := withCorrelation(context.Background(), "tick-A")
			countA, errA = svc.Dispatch(ctx)
		}()
		go func() {
			defer wg.Done()
			ctx := withCorrelation(context.Background(), "tick-B")
			countB, errB = svc.Dispatch(ctx)
		}()
		wg.Wait()

		if errA != nil {
			t.Fatalf("tick A: %v", errA)
		}
		if errB != nil {
			t.Fatalf("tick B: %v", errB)
		}

		// Each ran exactly one tx; together they dispatched ALL N hosts
		// once each. No overlap.
		if countA+countB != N {
			t.Errorf("countA(%d) + countB(%d) = %d, want %d", countA, countB, countA+countB, N)
		}

		// Verify via DB: every host now has a future next_scheduled_scan
		// (advanced from the seeded past time).
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, h := range hostIDs {
			var nextScan time.Time
			err := pool.QueryRow(ctx,
				`SELECT next_scheduled_scan FROM host_compliance_schedule WHERE host_id = $1`,
				h).Scan(&nextScan)
			if err != nil {
				t.Fatalf("read schedule for %s: %v", h, err)
			}
			if !nextScan.After(now) {
				t.Errorf("host %s: next_scheduled_scan = %v, want > %v (was not advanced)", h, nextScan, now)
			}
		}

		// Verify queue: exactly N scan jobs enqueued, one per host.
		var jobCount int
		err := pool.QueryRow(ctx,
			`SELECT count(*) FROM job_queue WHERE job_type = 'scan'`).Scan(&jobCount)
		if err != nil {
			t.Fatalf("count job_queue: %v", err)
		}
		if jobCount != N {
			t.Errorf("job_queue scan count = %d, want %d (some hosts double-dispatched or missed)", jobCount, N)
		}
	})
}

// @ac AC-04
// AC-04 (negative case): rows with next_scheduled_scan in the future are
// NOT claimed by Dispatch. Confirms the time predicate works alongside
// SKIP LOCKED.
func TestDispatch_FuturesNotClaimed(t *testing.T) {
	t.Run("system-scheduler/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		future := time.Now().Add(2 * time.Hour)

		// 3 future hosts, 0 due hosts.
		for i := 0; i < 3; i++ {
			h := seedHost(t, pool, user)
			seedSchedule(t, pool, h, withNext(future))
		}

		var calls []emitCall
		svc := newTestService(t, pool, time.Now(), &calls)

		ctx := withCorrelation(context.Background(), "tick-future")
		dispatched, err := svc.Dispatch(ctx)
		if err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
		if dispatched != 0 {
			t.Errorf("dispatched = %d, want 0 (all hosts have future next_scheduled_scan)", dispatched)
		}
	})
}

// @ac AC-05
// AC-05: a host in effective maintenance is skipped by Dispatch even when
// due — whether the maintenance is per-host (hosts.maintenance_mode, set by
// the host-detail toggle) or per-group (a maintenance group it belongs to).
// Enforcement resolves through the host_effective_maintenance view; the
// skipped host's schedule row is left unadvanced so it resumes on the next
// tick after maintenance clears.
func TestDispatch_MaintenanceMode_RowSkipped(t *testing.T) {
	t.Run("system-scheduler/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hPerHost := seedHost(t, pool, user)  // per-host maintenance
		hPerGroup := seedHost(t, pool, user) // per-group maintenance
		hNormal := seedHost(t, pool, user)   // not in maintenance

		// All three due-now; two are placed in maintenance by different scopes.
		seedSchedule(t, pool, hPerHost)
		seedSchedule(t, pool, hPerGroup)
		seedSchedule(t, pool, hNormal)
		setHostMaintenance(t, pool, hPerHost, true)
		seedManualMaintenanceGroup(t, pool, hPerGroup)

		var calls []emitCall
		svc := newTestService(t, pool, time.Now(), &calls)

		ctx := withCorrelation(context.Background(), "tick-maint")
		dispatched, err := svc.Dispatch(ctx)
		if err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
		if dispatched != 1 {
			t.Errorf("dispatched = %d, want 1 (only hNormal should be claimed)", dispatched)
		}

		// Neither maintenance host's schedule was advanced (still in the past).
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, tc := range []struct {
			name   string
			hostID uuid.UUID
		}{{"per-host", hPerHost}, {"per-group", hPerGroup}} {
			var next time.Time
			if err := pool.QueryRow(ctx2,
				`SELECT next_scheduled_scan FROM host_compliance_schedule WHERE host_id = $1`,
				tc.hostID).Scan(&next); err != nil {
				t.Fatalf("read %s schedule: %v", tc.name, err)
			}
			if !next.Before(time.Now()) {
				t.Errorf("%s host next_scheduled_scan = %v; should be unchanged (dispatcher must skip it)", tc.name, next)
			}
		}
	})
}

// TestHostSchedule_MaintenanceFromEffectiveView is a regression test for the
// host-detail schedule projection: HostSchedule must read maintenance from
// host_effective_maintenance (per-host OR per-group, migration 0049), NOT the
// never-written host_compliance_schedule.maintenance_mode column. Before the
// fix that column always read false, so the "paused for maintenance" tile on
// the host-detail Auto-scan card was permanently unreachable.
func TestHostSchedule_MaintenanceFromEffectiveView(t *testing.T) {
	pool := freshPool(t)
	user := seedUser(t, pool)
	hNormal := seedHost(t, pool, user)
	hPerHost := seedHost(t, pool, user)
	hPerGroup := seedHost(t, pool, user)
	seedSchedule(t, pool, hNormal)
	seedSchedule(t, pool, hPerHost)
	seedSchedule(t, pool, hPerGroup)
	setHostMaintenance(t, pool, hPerHost, true)
	seedManualMaintenanceGroup(t, pool, hPerGroup)

	for _, tc := range []struct {
		name   string
		hostID uuid.UUID
		want   bool
	}{
		{"normal host not in maintenance", hNormal, false},
		{"per-host maintenance", hPerHost, true},
		{"per-group maintenance", hPerGroup, true},
	} {
		info, err := HostSchedule(context.Background(), pool, tc.hostID)
		if err != nil {
			t.Fatalf("%s: HostSchedule: %v", tc.name, err)
		}
		if !info.Found {
			t.Fatalf("%s: schedule row not found", tc.name)
		}
		if info.Maintenance != tc.want {
			t.Errorf("%s: Maintenance = %v, want %v", tc.name, info.Maintenance, tc.want)
		}
	}
}

// @ac AC-13
// AC-13: every UPDATE to host_compliance_schedule emits one
// scheduler.schedule.updated audit event with the expected detail keys.
func TestDispatch_EmitsScheduleUpdated(t *testing.T) {
	t.Run("system-scheduler/AC-13", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		h := seedHost(t, pool, user)
		seedSchedule(t, pool, h)

		var calls []emitCall
		svc := newTestService(t, pool, time.Now(), &calls)

		ctx := withCorrelation(context.Background(), "tick-audit")
		if _, err := svc.Dispatch(ctx); err != nil {
			t.Fatalf("Dispatch: %v", err)
		}

		// Count scheduler.schedule.updated events. Exactly one per
		// dispatched host; here that's 1.
		var schedUpdated int
		var seenTickDispatched bool
		for _, c := range calls {
			switch c.Code {
			case audit.SchedulerScheduleUpdated:
				schedUpdated++
				// Decode detail and assert expected keys.
				var detail map[string]any
				if err := decodeDetailJSON(c.Event.Detail, &detail); err != nil {
					t.Fatalf("decode detail: %v", err)
				}
				if detail["host_id"] != h.String() {
					t.Errorf("Detail.host_id = %v, want %v", detail["host_id"], h.String())
				}
				if detail["change_kind"] != "next_scan_advanced" {
					t.Errorf("Detail.change_kind = %v, want next_scan_advanced", detail["change_kind"])
				}
			case audit.SchedulerTickDispatched:
				seenTickDispatched = true
			}
		}
		if schedUpdated != 1 {
			t.Errorf("scheduler.schedule.updated emissions = %d, want 1", schedUpdated)
		}
		if !seenTickDispatched {
			t.Error("expected one scheduler.tick.dispatched per Dispatch call, got none")
		}
	})
}

// decodeDetailJSON unmarshals an audit.Event.Detail (json.RawMessage)
// into a generic map for test assertions.
func decodeDetailJSON(raw []byte, into any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, into)
}
