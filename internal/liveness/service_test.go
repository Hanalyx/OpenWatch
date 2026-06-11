// @spec system-liveness-loop
//
// AC traceability (this file):
//   AC-05  TestProbeHost_ConcurrencyGuard_SecondReturnsInFlight
//   AC-06  TestProbeHost_DifferentHosts_ParallelRaceClean
//   AC-09  TestProbeHost_FirstSuccess_EmitsAuditAndStatusReachable
//   AC-10  TestProbeHost_FirstFailureFromReachable_NoTransition
//   AC-11  TestProbeHost_NConsecutiveFailures_FlipsToUnreachable
//   AC-12  TestProbeHost_SuccessAfterUnreachable_FlipsBackToReachable
//   AC-13  TestMigration_HostLivenessTableExists
//   AC-15  TestMetrics_RoundTrip

package liveness

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run liveness integration tests")
	}
	return dsn
}

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	pool, err := db.NewPool(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("migrations.Apply: %v", err)
	}
	for _, stmt := range []string{
		"TRUNCATE TABLE host_liveness CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "live-user", "live@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

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

type emitCall struct {
	Code  audit.Code
	Event audit.Event
}

func fakeEmitter(mu *sync.Mutex, calls *[]emitCall) EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, emitCall{Code: code, Event: ev})
	}
}

func countEmissions(mu *sync.Mutex, calls *[]emitCall, code audit.Code) int {
	mu.Lock()
	defer mu.Unlock()
	n := 0
	for _, c := range *calls {
		if c.Code == code {
			n++
		}
	}
	return n
}

// alwaysReachable returns a ProbeFunc that fakes a successful probe.
func alwaysReachable(rtMS int) ProbeFunc {
	return func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
		return ProbeResult{
			Reachable:    true,
			ResponseTime: time.Duration(rtMS) * time.Millisecond,
			BannerSeen:   true,
			Banner:       []byte("SSH-2.0-fake"),
		}
	}
}

// alwaysFails returns a ProbeFunc that fakes a probe failure.
func alwaysFails(errMsg string) ProbeFunc {
	return func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
		return ProbeResult{
			Reachable:    false,
			ResponseTime: 100 * time.Millisecond,
			Error:        errors.New(errMsg),
		}
	}
}

// readLivenessRow returns the host_liveness columns for hostID.
type livenessRow struct {
	Status              string
	ConsecutiveFailures int
	LastResponseMS      *int
}

func readLivenessRow(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) (livenessRow, bool) {
	t.Helper()
	var r livenessRow
	err := pool.QueryRow(context.Background(),
		`SELECT reachability_status, consecutive_failures, last_response_ms
		   FROM host_liveness WHERE host_id = $1`, hostID).
		Scan(&r.Status, &r.ConsecutiveFailures, &r.LastResponseMS)
	if err != nil {
		return livenessRow{}, false
	}
	return r, true
}

// @ac AC-05
// AC-05: per-host concurrency guard — second concurrent ProbeHost
// returns ErrProbeInFlight without invoking the probe function.
func TestProbeHost_ConcurrencyGuard_SecondReturnsInFlight(t *testing.T) {
	t.Run("system-liveness-loop/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall

		// Probe func that blocks until release is signaled.
		release := make(chan struct{})
		var probeInvocations int
		var probeMu sync.Mutex
		blocking := func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
			probeMu.Lock()
			probeInvocations++
			probeMu.Unlock()
			<-release
			return ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond, BannerSeen: true}
		}
		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).WithProbeFunc(blocking)

		// Start first probe.
		started := make(chan struct{})
		firstDone := make(chan struct{})
		go func() {
			defer close(firstDone)
			close(started)
			_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		}()
		<-started
		time.Sleep(50 * time.Millisecond)

		// Second call should immediately bounce.
		_, err := svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		if !errors.Is(err, ErrProbeInFlight) {
			t.Errorf("second ProbeHost err = %v, want ErrProbeInFlight", err)
		}
		probeMu.Lock()
		inv := probeInvocations
		probeMu.Unlock()
		if inv != 1 {
			t.Errorf("probe func invocations = %d, want 1 (guard must skip invocation)", inv)
		}

		close(release)
		<-firstDone
	})
}

// @ac AC-06
// AC-06: 100 parallel ProbeHost calls against distinct hosts race-clean.
func TestProbeHost_DifferentHosts_ParallelRaceClean(t *testing.T) {
	t.Run("system-liveness-loop/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)

		const N = 100
		hosts := make([]uuid.UUID, N)
		for i := range hosts {
			hosts[i] = seedHost(t, pool, user)
		}

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).WithProbeFunc(alwaysReachable(15))

		var wg sync.WaitGroup
		for _, h := range hosts {
			wg.Add(1)
			go func(host uuid.UUID) {
				defer wg.Done()
				_, _ = svc.ProbeHost(context.Background(), host, "192.0.2.10:22")
			}(h)
		}
		wg.Wait()

		if got := svc.inFlightCount(); got != 0 {
			t.Errorf("inFlightCount after parallel probes = %d, want 0", got)
		}

		// All N rows present.
		var count int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM host_liveness`).Scan(&count)
		if count != N {
			t.Errorf("host_liveness rows = %d, want %d", count, N)
		}
	})
}

// @ac AC-09
// AC-09: first successful probe transitions unknown → reachable, emits
// host.connectivity.checked.
func TestProbeHost_FirstSuccess_EmitsAuditAndStatusReachable(t *testing.T) {
	t.Run("system-liveness-loop/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).WithProbeFunc(alwaysReachable(20))

		_, err := svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		if err != nil {
			t.Fatalf("ProbeHost: %v", err)
		}

		r, ok := readLivenessRow(t, pool, hostID)
		if !ok {
			t.Fatal("no host_liveness row after probe")
		}
		if r.Status != string(StatusReachable) {
			t.Errorf("status = %q, want %q", r.Status, StatusReachable)
		}
		if r.ConsecutiveFailures != 0 {
			t.Errorf("consecutive_failures = %d, want 0", r.ConsecutiveFailures)
		}

		if got := countEmissions(&mu, &calls, audit.HostConnectivityChecked); got != 1 {
			t.Errorf("host.connectivity.checked emissions = %d, want 1", got)
		}

		// Detail should say ssh_accessible: true.
		mu.Lock()
		var detail map[string]any
		for _, c := range calls {
			if c.Code == audit.HostConnectivityChecked {
				_ = json.Unmarshal(c.Event.Detail, &detail)
				break
			}
		}
		mu.Unlock()
		if v, _ := detail["ssh_accessible"].(bool); !v {
			t.Errorf("Detail.ssh_accessible = %v, want true", detail["ssh_accessible"])
		}
	})
}

// @ac AC-10
// AC-10: a single failure after a prior success does NOT flip the status;
// counter increments to 1 but status stays reachable; no audit.
func TestProbeHost_FirstFailureFromReachable_NoTransition(t *testing.T) {
	t.Run("system-liveness-loop/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).WithProbeFunc(alwaysReachable(20))

		// Initial reachable probe to seed status.
		if _, err := svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22"); err != nil {
			t.Fatalf("setup probe: %v", err)
		}
		startEmissions := countEmissions(&mu, &calls, audit.HostConnectivityChecked)

		// Now flip to a failing probe.
		svc = svc.WithProbeFunc(alwaysFails("read: connection reset"))
		if _, err := svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22"); err != nil {
			t.Fatalf("fail probe: %v", err)
		}

		r, _ := readLivenessRow(t, pool, hostID)
		if r.Status != string(StatusReachable) {
			t.Errorf("status after 1 failure = %q, want reachable (still in hysteresis window)", r.Status)
		}
		if r.ConsecutiveFailures != 1 {
			t.Errorf("consecutive_failures = %d, want 1", r.ConsecutiveFailures)
		}
		if got := countEmissions(&mu, &calls, audit.HostConnectivityChecked); got != startEmissions {
			t.Errorf("new emissions = %d, want 0 (no transition)", got-startEmissions)
		}
	})
}

// @ac AC-11
// AC-11: N consecutive failures (default 2) → unreachable + audit.
func TestProbeHost_NConsecutiveFailures_FlipsToUnreachable(t *testing.T) {
	t.Run("system-liveness-loop/AC-11", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).WithProbeFunc(alwaysReachable(20))

		// Seed reachable.
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")

		// Flip to failures.
		svc = svc.WithProbeFunc(alwaysFails("connection refused"))

		// First failure: hysteresis (count=1, still reachable).
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		// Second failure: hits threshold (default 2) → unreachable.
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")

		r, _ := readLivenessRow(t, pool, hostID)
		if r.Status != string(StatusUnreachable) {
			t.Errorf("status after 2 failures = %q, want unreachable", r.Status)
		}
		if r.ConsecutiveFailures != 2 {
			t.Errorf("consecutive_failures = %d, want 2", r.ConsecutiveFailures)
		}

		// One transition emission for reachable→reachable initial, plus
		// one for reachable→unreachable at threshold.
		if got := countEmissions(&mu, &calls, audit.HostConnectivityChecked); got != 2 {
			t.Errorf("transition emissions = %d, want 2", got)
		}
	})
}

// @ac AC-12
// AC-12: a successful probe after unreachable flips back to reachable,
// resets counter, and emits an audit event.
func TestProbeHost_SuccessAfterUnreachable_FlipsBackToReachable(t *testing.T) {
	t.Run("system-liveness-loop/AC-12", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).WithProbeFunc(alwaysFails("timeout"))

		// Two failures get us to unreachable.
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		r, _ := readLivenessRow(t, pool, hostID)
		if r.Status != string(StatusUnreachable) {
			t.Fatalf("pre-recovery status = %q, want unreachable (test fixture broken)", r.Status)
		}

		// Now successful probe.
		svc = svc.WithProbeFunc(alwaysReachable(15))
		startEmissions := countEmissions(&mu, &calls, audit.HostConnectivityChecked)
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")

		r, _ = readLivenessRow(t, pool, hostID)
		if r.Status != string(StatusReachable) {
			t.Errorf("post-recovery status = %q, want reachable", r.Status)
		}
		if r.ConsecutiveFailures != 0 {
			t.Errorf("post-recovery consecutive_failures = %d, want 0", r.ConsecutiveFailures)
		}
		if got := countEmissions(&mu, &calls, audit.HostConnectivityChecked); got != startEmissions+1 {
			t.Errorf("recovery emissions delta = %d, want 1", got-startEmissions)
		}
	})
}

// @ac AC-13
// AC-13: migration creates host_liveness with the FK to hosts(id) ON
// DELETE CASCADE. Verified by deleting a host and confirming the
// liveness row went with it.
func TestMigration_HostLivenessTableExists(t *testing.T) {
	t.Run("system-liveness-loop/AC-13", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		// Insert a liveness row directly.
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO host_liveness (host_id, reachability_status, last_probe_at)
			VALUES ($1, 'reachable', now())`, hostID); err != nil {
			t.Fatalf("insert host_liveness: %v", err)
		}

		// DELETE the host — liveness row should cascade.
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM hosts WHERE id = $1`, hostID); err != nil {
			t.Fatalf("delete host: %v", err)
		}

		var count int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM host_liveness WHERE host_id = $1`, hostID).Scan(&count)
		if count != 0 {
			t.Errorf("host_liveness rows after host DELETE = %d, want 0 (ON DELETE CASCADE)", count)
		}
	})
}

// @ac AC-15
// AC-15: Metrics counters increment + Snapshot round-trips.
func TestMetrics_RoundTrip(t *testing.T) {
	t.Run("system-liveness-loop/AC-15", func(t *testing.T) {
		m := NewMetrics()

		// Zero state.
		snap := m.Snapshot()
		if snap.ProbeCount != 0 || snap.ProbeSuccessCount != 0 ||
			snap.ProbeFailureCount != 0 || snap.StateTransitionCount != 0 {
			t.Errorf("zero-state has non-zero counter: %+v", snap)
		}
		if !snap.LastProbeAt.IsZero() {
			t.Errorf("zero-state LastProbeAt = %v, want zero", snap.LastProbeAt)
		}

		// Concurrent increments — Metrics must be race-free.
		var wg sync.WaitGroup
		const G = 50
		for i := 0; i < G; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.ProbeCount.Add(1)
				m.ProbeSuccessCount.Add(1)
				m.StateTransitionCount.Add(1)
			}()
		}
		wg.Wait()
		m.SetLastProbeAt(time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

		snap = m.Snapshot()
		if snap.ProbeCount != G || snap.ProbeSuccessCount != G || snap.StateTransitionCount != G {
			t.Errorf("after concurrent: %+v, want counts=%d", snap, G)
		}
		if snap.LastProbeAt.IsZero() {
			t.Error("LastProbeAt should not be zero after SetLastProbeAt")
		}
	})
}
