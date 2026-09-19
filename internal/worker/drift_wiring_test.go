// @spec system-drift-detector
//
// The worker side of the drift detector contract (1.3.0): the scan worker
// calls DetectForScan on every completed scan (C-11), a detector failure
// never fails the scan (C-12), and a redelivered scan may repeat the audit
// event while the alert router's dedup gate keeps one alert (C-13).
//
//	AC-23  TestScanWorker_DriftDetectedAfterCompletedScans
//	AC-24  TestScanWorker_DriftDetectorFailureIsNonFatal
//	AC-25  TestScanWorker_DedicatedWorkerRecordsDriftWithoutAlerting
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/drift"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
)

// scanOutcomes builds n passing rules with the first `failing` of them
// failing. Rule ids are stable across calls so a second scan of the same
// host produces transitions rather than first_seen rows.
func scanOutcomes(n, failing int) []kensa.RuleOutcome {
	out := make([]kensa.RuleOutcome, 0, n)
	for i := 0; i < n; i++ {
		st := kensa.StatusPass
		if i < failing {
			st = kensa.StatusFail
		}
		out = append(out, kensa.RuleOutcome{
			RuleID: "drift-rule-" + string(rune('a'+i)), Status: st, Severity: "high", Evidence: []byte(`{"k":"v"}`),
		})
	}
	return out
}

// scanBudget bounds one scan's trip through the worker: claim, stub scan,
// Apply, durable results, logbook, drift detection and the alert router's
// persist. Locally that is about a second; under the race detector on a
// shared hosted runner it exceeded 3 seconds once (go-ci run 35471479821,
// job still "processing" at the deadline), so the budget is generous. The
// loop exits as soon as the job completes, so a large budget costs nothing
// on a fast machine.
const scanBudget = 30 * time.Second

// runOneScan enqueues a job whose scan returns outcomes and drives the
// worker until the job completes. Returns the scan id (== job id).
func runOneScan(t *testing.T, pool *pgxpool.Pool, w *ScanWorker, hostID uuid.UUID, key []byte, current *atomic.Pointer[[]kensa.RuleOutcome], outcomes []kensa.RuleOutcome) uuid.UUID {
	t.Helper()
	current.Store(&outcomes)
	jobID := enqueueScanJob(t, pool, hostID, key)
	ctx, cancel := context.WithTimeout(context.Background(), scanBudget)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	deadline := time.Now().Add(scanBudget)
	for time.Now().Before(deadline) {
		if jobStatus(t, pool, jobID) == queue.StatusCompleted {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if st := jobStatus(t, pool, jobID); st != queue.StatusCompleted {
		t.Fatalf("job %s status = %q after %s, want completed", jobID, st, scanBudget)
	}
	return jobID
}

func countAlerts(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, alertType string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM alerts WHERE host_id = $1 AND alert_type = $2`, hostID, alertType).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

func waitForAlerts(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, alertType string, want int) int {
	t.Helper()
	deadline := time.Now().Add(scanBudget)
	for {
		n := countAlerts(t, pool, hostID, alertType)
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// @ac AC-23
// AC-23: two scans through the real worker (10 pass, then 9 pass 1 fail)
// produce exactly one compliance.drift.detected with drift_type=major and
// score_delta=-10, exactly one DriftDetected bus event, and one drift_major
// alerts row; an unchanged third scan produces nothing; re-running the
// detector for scan 2 (the redelivery shape) adds an audit event and no
// alert row.
func TestScanWorker_DriftDetectedAfterCompletedScans(t *testing.T) {
	t.Run("system-drift-detector/AC-23", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy-key")}
		var current atomic.Pointer[[]kensa.RuleOutcome]
		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				return &kensa.Result{HostID: hostID, Outcomes: *current.Load()}, "", nil
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		bus := eventbus.NewBus()
		defer bus.Shutdown()
		driftSub := bus.Subscribe(eventbus.SubscribeOptions{Kinds: []eventbus.EventKind{eventbus.EventKindDriftDetected}})

		// A real alert router with the real store, subscribed before any
		// producer publishes (system-daemon-orchestration C-03).
		router, err := alertrouter.NewRouter(bus, alertrouter.Config{})
		if err != nil {
			t.Fatalf("alertrouter: %v", err)
		}
		router.WithStore(alertrouter.NewPgxStore(pool))
		rctx, rcancel := context.WithCancel(context.Background())
		defer rcancel()
		router.Start(rctx)
		defer router.Stop()

		driftSvc := drift.NewService(pool, drift.EmitFunc(rec.Emit()), drift.DefaultThresholds(), bus)

		key := make([]byte, 32)
		w := NewScanWorker(Config{
			Pool: pool, Executor: exec, Writer: writer, QueueKey: key,
			PollInterval: 50 * time.Millisecond, Emit: rec.Emit(), Bus: bus, Drift: driftSvc,
		})

		// Scan 1: ten passing rules. First scan of the host: no prior, no drift.
		runOneScan(t, pool, w, hostID, key, &current, scanOutcomes(10, 0))
		if got := rec.Count(audit.ComplianceDriftDetected); got != 0 {
			t.Fatalf("after first scan compliance.drift.detected = %d, want 0 (no prior baseline)", got)
		}

		// Scan 2: one rule fails. 100 -> 90 is a 10 pp drop: major (C-05 inclusive).
		scan2 := runOneScan(t, pool, w, hostID, key, &current, scanOutcomes(10, 1))
		events := rec.Events(audit.ComplianceDriftDetected)
		if len(events) != 1 {
			t.Fatalf("compliance.drift.detected emitted %d times after the worsening scan, want 1", len(events))
		}
		var detail struct {
			DriftType  string  `json:"drift_type"`
			ScoreDelta float64 `json:"score_delta"`
			ScanID     string  `json:"scan_id"`
		}
		if err := json.Unmarshal(events[0].Detail, &detail); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		if detail.DriftType != "major" || detail.ScoreDelta != -10 || detail.ScanID != scan2.String() {
			t.Errorf("detail = %+v, want drift_type=major score_delta=-10 scan_id=%s", detail, scan2)
		}
		select {
		case ev := <-driftSub.Events():
			dd, ok := ev.(eventbus.DriftDetected)
			if !ok || dd.DriftType != "major" || dd.HostID != hostID || dd.ScanID != scan2 {
				t.Errorf("bus event = %#v, want DriftDetected major for host %s scan %s", ev, hostID, scan2)
			}
		case <-time.After(scanBudget):
			t.Fatal("no DriftDetected published on the bus after the worsening scan")
		}
		if n := waitForAlerts(t, pool, hostID, string(alertrouter.AlertTypeDriftMajor), 1); n != 1 {
			t.Fatalf("drift_major alert rows = %d, want 1", n)
		}

		// C-13 redelivery shape: the queue redelivers scan 2 before any newer
		// scan has moved host_rule_state on. The same scan id detected again
		// repeats the audit event; the router's dedup gate keeps one alert.
		if _, err := driftSvc.DetectForScan(context.Background(), hostID, scan2); err != nil {
			t.Fatalf("second DetectForScan: %v", err)
		}
		if got := rec.Count(audit.ComplianceDriftDetected); got != 2 {
			t.Errorf("compliance.drift.detected = %d after redelivery, want 2 (audit keeps both)", got)
		}
		select {
		case <-driftSub.Events():
		case <-time.After(scanBudget):
			t.Fatal("no DriftDetected on redelivery")
		}
		time.Sleep(300 * time.Millisecond)
		if n := countAlerts(t, pool, hostID, string(alertrouter.AlertTypeDriftMajor)); n != 1 {
			t.Errorf("drift_major alert rows after redelivery = %d, want 1 (dedup gate)", n)
		}

		// Scan 3: nothing changed. No transitions, stable, nothing emitted.
		runOneScan(t, pool, w, hostID, key, &current, scanOutcomes(10, 1))
		if got := rec.Count(audit.ComplianceDriftDetected); got != 2 {
			t.Errorf("compliance.drift.detected = %d after an unchanged scan, want still 2 (unchanged scan adds nothing)", got)
		}
		select {
		case ev := <-driftSub.Events():
			t.Errorf("unexpected bus event after an unchanged scan: %#v", ev)
		case <-time.After(300 * time.Millisecond):
		}
	})
}

type failingDetector struct{ calls atomic.Int32 }

func (f *failingDetector) DetectForScan(context.Context, uuid.UUID, uuid.UUID) (drift.Report, error) {
	f.calls.Add(1)
	return drift.Report{}, errors.New("detector exploded")
}

// @ac AC-24
// AC-24: a detector error leaves the job completed and ScanCompleted
// published; no scan.failed, no backoff row.
func TestScanWorker_DriftDetectorFailureIsNonFatal(t *testing.T) {
	t.Run("system-drift-detector/AC-24", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy-key")}
		var current atomic.Pointer[[]kensa.RuleOutcome]
		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				return &kensa.Result{HostID: hostID, Outcomes: *current.Load()}, "", nil
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		completedSub := bus.Subscribe(eventbus.SubscribeOptions{Kinds: []eventbus.EventKind{eventbus.EventKindScanCompleted}})

		det := &failingDetector{}
		key := make([]byte, 32)
		w := NewScanWorker(Config{
			Pool: pool, Executor: exec, Writer: writer, QueueKey: key,
			PollInterval: 50 * time.Millisecond, Emit: rec.Emit(), Bus: bus, Drift: det,
		})

		jobID := runOneScan(t, pool, w, hostID, key, &current, scanOutcomes(3, 1))
		if det.calls.Load() != 1 {
			t.Errorf("detector called %d times, want 1", det.calls.Load())
		}
		select {
		case ev := <-completedSub.Events():
			if sc, ok := ev.(eventbus.ScanCompleted); !ok || sc.ScanID != jobID {
				t.Errorf("ScanCompleted = %#v, want scan %s", ev, jobID)
			}
		case <-time.After(scanBudget):
			t.Fatal("ScanCompleted was not published after a detector failure")
		}
		if got := rec.Count(audit.ScanFailed); got != 0 {
			t.Errorf("scan.failed emitted %d times, want 0", got)
		}
		var backoff int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM host_backoff_state WHERE host_id = $1`, hostID).Scan(&backoff)
		if backoff != 0 {
			t.Errorf("host_backoff_state rows = %d, want 0", backoff)
		}
	})
}

// @ac AC-25
// AC-25: the dedicated-worker shape. The worker is built the way cmdWorker
// builds it: no bus, no router, a detector with a nil bus. A worsening scan
// emits exactly one compliance.drift.detected (major); nothing can carry a
// DriftDetected event, and no alerts row appears. This is the approved v0.8
// limitation (features/OW-057), proven rather than assumed.
func TestScanWorker_DedicatedWorkerRecordsDriftWithoutAlerting(t *testing.T) {
	t.Run("system-drift-detector/AC-25", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy-key")}
		var current atomic.Pointer[[]kensa.RuleOutcome]
		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				return &kensa.Result{HostID: hostID, Outcomes: *current.Load()}, "", nil
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		// Exactly what cmd/openwatch/worker.go wires: a nil-bus detector, and
		// a worker Config with no Bus. No alert router exists in this process.
		driftSvc := drift.NewService(pool, drift.EmitFunc(rec.Emit()), drift.DefaultThresholds(), nil)
		key := make([]byte, 32)
		w := NewScanWorker(Config{
			Pool: pool, Executor: exec, Writer: writer, QueueKey: key,
			PollInterval: 50 * time.Millisecond, Emit: rec.Emit(), Drift: driftSvc,
		})

		runOneScan(t, pool, w, hostID, key, &current, scanOutcomes(10, 0))
		if got := rec.Count(audit.ComplianceDriftDetected); got != 0 {
			t.Fatalf("first scan emitted %d drift events, want 0", got)
		}
		scan2 := runOneScan(t, pool, w, hostID, key, &current, scanOutcomes(10, 1))

		events := rec.Events(audit.ComplianceDriftDetected)
		if len(events) != 1 {
			t.Fatalf("compliance.drift.detected emitted %d times, want 1 (a dedicated worker still audits)", len(events))
		}
		var detail struct {
			DriftType string `json:"drift_type"`
			ScanID    string `json:"scan_id"`
		}
		if err := json.Unmarshal(events[0].Detail, &detail); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		if detail.DriftType != "major" || detail.ScanID != scan2.String() {
			t.Errorf("detail = %+v, want drift_type=major scan_id=%s", detail, scan2)
		}
		// The limitation, stated as an assertion: no alert row, and nothing
		// for a notification channel to have received.
		if n := countAlerts(t, pool, hostID, string(alertrouter.AlertTypeDriftMajor)); n != 0 {
			t.Errorf("drift_major alert rows = %d, want 0 (a dedicated worker has no alert router)", n)
		}
		var anyAlerts int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM alerts WHERE host_id = $1`, hostID).Scan(&anyAlerts); err != nil {
			t.Fatalf("count alerts: %v", err)
		}
		if anyAlerts != 0 {
			t.Errorf("alerts rows for the host = %d, want 0", anyAlerts)
		}
	})
}
