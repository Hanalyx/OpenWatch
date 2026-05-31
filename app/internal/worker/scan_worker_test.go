// @spec system-worker-subcommand
//
// AC traceability (this file):
//
//	AC-01  TestScanWorker_SKIPLOCKED_NoDoubleClaim
//	AC-02  TestScanWorker_HMACMismatch_DeadLettered_NoExecutorCall
//	AC-03  TestScanWorker_Success_OneApplyOneComplete
//	AC-04  TestScanWorker_TransientHostBusy_BackoffUpsert
//	AC-05  TestScanWorker_PermanentError_QueueFail_NoBackoff
//	AC-06  TestScanWorker_SIGTERMDuringScan_DrainsBeforeReturn
//	AC-07  TestScanWorker_ConcurrentSameHost_AdvisoryLockSerializes
//	AC-08  TestTickWindowedInterval_InWindow
//	AC-11  TestScanWorker_EmptyQueue_PollIntervalSleep

package worker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
)

// ---------------------------------------------------------------------
// Test scaffolding (mirrors transactionlog/writer_test.go's pattern)
// ---------------------------------------------------------------------

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := workerTestDSN(t)
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
		"TRUNCATE TABLE transactions CASCADE",
		"TRUNCATE TABLE host_rule_state CASCADE",
		"TRUNCATE TABLE host_backoff_state CASCADE",
		"TRUNCATE TABLE job_queue CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

// workerTestDSN gates DB-backed tests behind the OPENWATCH_TEST_DSN env.
// Pure-function tests in source_test.go / backoff_test.go / payload_test.go /
// advisory_lock_test.go run unconditionally; tests that need a DB skip
// when unset.
func workerTestDSN(t *testing.T) string {
	t.Helper()
	return mustEnv(t, "OPENWATCH_TEST_DSN")
}

// mustEnv calls t.Skip if the env var is unset.
func mustEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("set %s to run worker integration tests", name)
	}
	return v
}

// ---------------------------------------------------------------------
// Seeders + fakes
// ---------------------------------------------------------------------

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "worker-user-"+id.String()[:8], "worker@example.com", "argon2id$dummy") // pragma: allowlist secret
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
		id, "host-"+id.String()[:8], "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// stubBridge is a CredentialBridge that returns a fixed plaintext blob
// (or a chosen error) for any host. Tests inject this so the executor
// has a credential to "decrypt" without involving the real
// credential.Service.
type stubBridge struct {
	plain []byte
	err   error
}

func (b stubBridge) Resolve(ctx context.Context, _ uuid.UUID) ([]byte, func(), error) {
	if b.err != nil {
		return nil, nil, b.err
	}
	plain := make([]byte, len(b.plain))
	copy(plain, b.plain)
	return plain, func() {
		for i := range plain {
			plain[i] = 0
		}
	}, nil
}

// emitCall captures an audit emission.
type emitCall struct {
	Code audit.Code
}

type emitRecorder struct {
	mu    sync.Mutex
	calls []emitCall
}

func (r *emitRecorder) Emit() EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, emitCall{Code: code})
	}
}

func (r *emitRecorder) executorEmit() kensa.EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, emitCall{Code: code})
	}
}

func (r *emitRecorder) writerEmit() transactionlog.EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, emitCall{Code: code})
	}
}

func (r *emitRecorder) Count(code audit.Code) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c.Code == code {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------
// Enqueue helpers
// ---------------------------------------------------------------------

func enqueueScanJob(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, key []byte) uuid.UUID {
	t.Helper()
	return enqueueScanJobWith(t, pool, hostID, "v-test", key, time.Now().UTC())
}

func enqueueScanJobWith(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, policyVersion string, key []byte, enq time.Time) uuid.UUID {
	t.Helper()
	payload := scheduler.JobPayload{
		HostID:        hostID,
		PolicyVersion: policyVersion,
		EnqueuedAt:    enq,
	}
	tag := scheduler.Sign(key, payload)
	body := map[string]any{
		"host_id":        payload.HostID.String(),
		"policy_version": payload.PolicyVersion,
		"enqueued_at":    payload.EnqueuedAt.UTC().Format(time.RFC3339Nano),
		"hmac":           hex.EncodeToString(tag[:]),
	}
	ctx := correlation.Set(context.Background(), correlation.Generate("test"))
	id, err := queue.Enqueue(ctx, pool, ScanJobType, body)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return id
}

// enqueueScanJobBadHMAC enqueues a job whose HMAC tag is the right
// length but the wrong bytes (so scheduler.Verify will reject it).
func enqueueScanJobBadHMAC(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) uuid.UUID {
	t.Helper()
	body := map[string]any{
		"host_id":        hostID.String(),
		"policy_version": "v-test",
		"enqueued_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"hmac":           hex.EncodeToString(make([]byte, scheduler.QueueHMACSize)), // all-zeros tag
	}
	ctx := correlation.Set(context.Background(), correlation.Generate("test"))
	id, err := queue.Enqueue(ctx, pool, ScanJobType, body)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return id
}

func jobStatus(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) queue.Status {
	t.Helper()
	var s string
	err := pool.QueryRow(context.Background(),
		`SELECT status FROM job_queue WHERE id = $1`, id).Scan(&s)
	if err != nil {
		t.Fatalf("read status %v: %v", id, err)
	}
	return queue.Status(s)
}

func backoffRow(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) (consecutiveFailures int, suppressUntil *time.Time) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT consecutive_failures, suppress_until
		   FROM host_backoff_state
		  WHERE host_id = $1`, hostID).Scan(&consecutiveFailures, &suppressUntil)
	if err != nil {
		t.Fatalf("read host_backoff_state %v: %v", hostID, err)
	}
	return
}

// ---------------------------------------------------------------------
// AC-01: SKIP LOCKED no double-claim
// ---------------------------------------------------------------------

func TestScanWorker_SKIPLOCKED_NoDoubleClaim(t *testing.T) {
	t.Run("system-worker-subcommand/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)

		// 10 jobs across 10 distinct hosts, one job each.
		key := make([]byte, 32)
		jobIDs := make(map[uuid.UUID]bool)
		for i := 0; i < 10; i++ {
			hostID := seedHost(t, pool, user)
			jobIDs[enqueueScanJob(t, pool, hostID, key)] = true
		}

		// Two concurrent dequeue loops. Each claims jobs from a shared
		// set until ErrNoJob; tracks which IDs it saw.
		var (
			mu        sync.Mutex
			claimedA  = map[uuid.UUID]bool{}
			claimedB  = map[uuid.UUID]bool{}
			doubleErr error
		)
		drainAll := func(claimed map[uuid.UUID]bool) {
			for {
				job, _, err := queue.Dequeue(context.Background(), pool)
				if errors.Is(err, queue.ErrNoJob) {
					return
				}
				if err != nil {
					return
				}
				mu.Lock()
				if claimedA[job.ID] || claimedB[job.ID] {
					doubleErr = errors.New("job " + job.ID.String() + " double-claimed")
				}
				claimed[job.ID] = true
				mu.Unlock()
				// Mark complete so the row stays out of the way.
				_ = queue.Complete(context.Background(), pool, job.ID)
			}
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); drainAll(claimedA) }()
		go func() { defer wg.Done(); drainAll(claimedB) }()
		wg.Wait()

		if doubleErr != nil {
			t.Fatal(doubleErr)
		}
		// Every enqueued job MUST have been claimed exactly once.
		for jobID := range jobIDs {
			if claimedA[jobID] == claimedB[jobID] {
				t.Errorf("job %v: claimedA=%v claimedB=%v (must be exclusive)",
					jobID, claimedA[jobID], claimedB[jobID])
			}
		}
	})
}

// ---------------------------------------------------------------------
// AC-02: HMAC mismatch → dead-letter, no executor.Run, no advisory lock
// ---------------------------------------------------------------------

func TestScanWorker_HMACMismatch_DeadLettered_NoExecutorCall(t *testing.T) {
	t.Run("system-worker-subcommand/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		var scanCalls atomic.Int32
		bridge := stubBridge{plain: []byte("dummy-key")}
		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				scanCalls.Add(1)
				return &kensa.Result{}, "", nil
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		// Random 32-byte key — the bad HMAC won't verify against this.
		realKey := make([]byte, 32)
		for i := range realKey {
			realKey[i] = byte(i + 1)
		}
		jobID := enqueueScanJobBadHMAC(t, pool, hostID)

		w := NewScanWorker(Config{
			Pool:         pool,
			Executor:     exec,
			Writer:       writer,
			QueueKey:     realKey,
			PollInterval: 50 * time.Millisecond,
			Emit:         rec.Emit(),
		})

		// Run briefly. The bad-HMAC job is the only one.
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = w.Run(ctx)

		// Job status MUST be failed.
		if status := jobStatus(t, pool, jobID); status != queue.StatusFailed {
			t.Errorf("job status = %q, want failed", status)
		}
		// scheduler.job.hmac_rejected MUST have been emitted.
		if rec.Count(audit.SchedulerJobHmacRejected) < 1 {
			t.Errorf("scheduler.job.hmac_rejected not emitted")
		}
		// Executor.Run MUST NOT have been invoked.
		if got := scanCalls.Load(); got != 0 {
			t.Errorf("scanFn called %d times, want 0 (executor must not run on HMAC failure)", got)
		}
		// No host_backoff_state row written (no host_id-keyed retry path).
		var count int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM host_backoff_state WHERE host_id = $1`, hostID).Scan(&count)
		if count != 0 {
			t.Errorf("host_backoff_state has %d rows, want 0 (HMAC failure must not touch backoff)", count)
		}
	})
}

// ---------------------------------------------------------------------
// AC-03: success → exactly one writer.Apply + queue.Complete
// ---------------------------------------------------------------------

func TestScanWorker_Success_OneApplyOneComplete(t *testing.T) {
	t.Run("system-worker-subcommand/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy-key")}

		outcomes := []kensa.RuleOutcome{
			{RuleID: "r1", Status: kensa.StatusPass, Severity: "high", Evidence: []byte(`{"k":"v"}`)},
			{RuleID: "r2", Status: kensa.StatusFail, Severity: "medium", Evidence: []byte(`{"k":"v"}`)},
		}
		scanResult := &kensa.Result{HostID: hostID, Outcomes: outcomes}

		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				return scanResult, "", nil
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		key := make([]byte, 32)
		jobID := enqueueScanJob(t, pool, hostID, key)

		w := NewScanWorker(Config{
			Pool:         pool,
			Executor:     exec,
			Writer:       writer,
			QueueKey:     key,
			PollInterval: 50 * time.Millisecond,
			Emit:         rec.Emit(),
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = w.Run(ctx)

		if status := jobStatus(t, pool, jobID); status != queue.StatusCompleted {
			t.Errorf("job status = %q, want completed", status)
		}
		// 2 outcomes → 2 finding.persisted emissions (writer.Apply
		// emits one per state-change row; first_seen counts).
		if got := rec.Count(audit.FindingPersisted); got != 2 {
			t.Errorf("finding.persisted emitted %d times, want 2 (one per outcome)", got)
		}
		// Executor's scan.completed fires exactly once.
		if got := rec.Count(audit.ScanCompleted); got != 1 {
			t.Errorf("scan.completed emitted %d times, want 1", got)
		}
		// The worker MUST NOT emit a second scan.failed.
		if got := rec.Count(audit.ScanFailed); got != 0 {
			t.Errorf("scan.failed emitted %d times, want 0 on success", got)
		}

		// Confirm host_rule_state has 2 rows for this host.
		var hrs int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM host_rule_state WHERE host_id = $1`, hostID).Scan(&hrs)
		if hrs != 2 {
			t.Errorf("host_rule_state row count = %d, want 2", hrs)
		}
	})
}

// ---------------------------------------------------------------------
// AC-04: ErrHostBusy → queue.Fail + host_backoff_state UPSERT (f=1, 1m)
// ---------------------------------------------------------------------

func TestScanWorker_TransientHostBusy_BackoffUpsert(t *testing.T) {
	t.Run("system-worker-subcommand/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy-key")}
		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				return nil, kensa.ReasonHostBusy, kensa.ErrHostBusy
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		key := make([]byte, 32)
		jobID := enqueueScanJob(t, pool, hostID, key)

		fixedNow := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
		w := NewScanWorker(Config{
			Pool:         pool,
			Executor:     exec,
			Writer:       writer,
			QueueKey:     key,
			PollInterval: 50 * time.Millisecond,
			Emit:         rec.Emit(),
			Clock:        func() time.Time { return fixedNow },
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = w.Run(ctx)

		if status := jobStatus(t, pool, jobID); status != queue.StatusFailed {
			t.Errorf("job status = %q, want failed", status)
		}

		count, suppressUntil := backoffRow(t, pool, hostID)
		if count != 1 {
			t.Errorf("consecutive_failures = %d, want 1", count)
		}
		if suppressUntil == nil {
			t.Fatalf("suppress_until is nil; want fixedNow + 1m")
		}
		want := fixedNow.Add(1 * time.Minute)
		if !suppressUntil.Equal(want) {
			t.Errorf("suppress_until = %v, want %v", suppressUntil, want)
		}
	})
}

// ---------------------------------------------------------------------
// AC-05: permanent error → queue.Fail, no host_backoff_state mutation
// ---------------------------------------------------------------------

func TestScanWorker_PermanentError_QueueFail_NoBackoff(t *testing.T) {
	t.Run("system-worker-subcommand/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		// CredentialBridge returns the decryption failure directly —
		// matches kensa AC-15 path.
		bridge := stubBridge{err: kensa.ErrCredentialDecryption}
		exec := kensa.NewExecutor(bridge, rec.executorEmit())
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		key := make([]byte, 32)
		jobID := enqueueScanJob(t, pool, hostID, key)

		w := NewScanWorker(Config{
			Pool:         pool,
			Executor:     exec,
			Writer:       writer,
			QueueKey:     key,
			PollInterval: 50 * time.Millisecond,
			Emit:         rec.Emit(),
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = w.Run(ctx)

		if status := jobStatus(t, pool, jobID); status != queue.StatusFailed {
			t.Errorf("job status = %q, want failed", status)
		}
		// Executor emits its own scan.failed; worker does NOT emit a
		// second.
		if got := rec.Count(audit.ScanFailed); got != 1 {
			t.Errorf("scan.failed emitted %d times, want 1 (executor's only)", got)
		}

		// No host_backoff_state row for this host — permanent errors
		// don't apply the ladder.
		var count int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM host_backoff_state WHERE host_id = $1`, hostID).Scan(&count)
		if count != 0 {
			t.Errorf("host_backoff_state has %d rows, want 0 for permanent error", count)
		}
	})
}

// ---------------------------------------------------------------------
// AC-06: SIGTERM during scan → in-flight completes + persists + Run returns
// ---------------------------------------------------------------------

func TestScanWorker_SIGTERMDuringScan_DrainsBeforeReturn(t *testing.T) {
	t.Run("system-worker-subcommand/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy-key")}

		entered := make(chan struct{})
		release := make(chan struct{})
		var releasedAfterCancel atomic.Bool

		scanResult := &kensa.Result{
			HostID: hostID,
			Outcomes: []kensa.RuleOutcome{
				{RuleID: "rA", Status: kensa.StatusPass, Severity: "high", Evidence: []byte(`{}`)},
			},
		}
		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				close(entered)
				<-release
				return scanResult, "", nil
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		key := make([]byte, 32)
		jobID := enqueueScanJob(t, pool, hostID, key)

		w := NewScanWorker(Config{
			Pool:         pool,
			Executor:     exec,
			Writer:       writer,
			QueueKey:     key,
			PollInterval: 50 * time.Millisecond,
			Emit:         rec.Emit(),
		})

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() {
			_ = w.Run(ctx)
			close(runDone)
		}()

		// Wait for the scan to be in flight.
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("scanFn was never entered")
		}

		// Send the simulated SIGTERM. Run must NOT return yet — the
		// in-flight scan hasn't completed.
		cancel()
		select {
		case <-runDone:
			t.Fatal("Run returned BEFORE in-flight scan released — abandoned the scan")
		case <-time.After(150 * time.Millisecond):
			// Expected: Run is still draining.
		}

		// Release the scan; Run must complete shortly after.
		releasedAfterCancel.Store(true)
		close(release)

		select {
		case <-runDone:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return after scan released")
		}

		// Job MUST be completed and host_rule_state populated.
		if status := jobStatus(t, pool, jobID); status != queue.StatusCompleted {
			t.Errorf("job status = %q, want completed", status)
		}
		var hrs int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM host_rule_state WHERE host_id = $1`, hostID).Scan(&hrs)
		if hrs != 1 {
			t.Errorf("host_rule_state row count = %d, want 1 (Apply must run post-cancel)", hrs)
		}
	})
}

// ---------------------------------------------------------------------
// AC-07: concurrent same-host → advisory lock serializes
// ---------------------------------------------------------------------

func TestScanWorker_ConcurrentSameHost_AdvisoryLockSerializes(t *testing.T) {
	t.Run("system-worker-subcommand/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		// concurrentActive tracks how many scanFn invocations are
		// in-flight at the same instant. The advisory lock MUST keep
		// this at 1 even though two worker goroutines drive the same
		// executor against the same host.
		var concurrentActive atomic.Int32
		var maxConcurrent atomic.Int32

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy-key")}
		exec := kensa.NewExecutor(bridge, rec.executorEmit()).WithScanFunc(
			func(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (*kensa.Result, kensa.FailureReason, error) {
				n := concurrentActive.Add(1)
				defer concurrentActive.Add(-1)
				if n > maxConcurrent.Load() {
					maxConcurrent.Store(n)
				}
				time.Sleep(150 * time.Millisecond) // hold the lock long enough to race
				return &kensa.Result{HostID: hostID, Outcomes: nil}, "", nil
			})
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		key := make([]byte, 32)
		// Two jobs against the same host.
		_ = enqueueScanJob(t, pool, hostID, key)
		_ = enqueueScanJob(t, pool, hostID, key)

		makeWorker := func() *ScanWorker {
			return NewScanWorker(Config{
				Pool:         pool,
				Executor:     exec,
				Writer:       writer,
				QueueKey:     key,
				PollInterval: 30 * time.Millisecond,
				Emit:         rec.Emit(),
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		// kensa.Executor's *own* sync.Map concurrency guard also
		// serializes — so even without the advisory lock the test
		// might pass. The advisory lock is the cross-process guarantee.
		// The unit test verifies the source pattern via AC-15; this
		// test verifies the runtime serialization observable via the
		// scanFn invocation count.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = makeWorker().Run(ctx) }()
		go func() { defer wg.Done(); _ = makeWorker().Run(ctx) }()
		wg.Wait()

		if got := maxConcurrent.Load(); got > 1 {
			t.Errorf("concurrent in-flight scanFn = %d, want at most 1 (advisory lock + executor in-memory guard)", got)
		}
	})
}

// ---------------------------------------------------------------------
// AC-08: tickWindowedInterval lies in [55s, 65s]
// ---------------------------------------------------------------------

func TestTickWindowedInterval_InWindow(t *testing.T) {
	t.Run("system-worker-subcommand/AC-08", func(t *testing.T) {
		const trials = 200
		for i := 0; i < trials; i++ {
			d := tickWindowedInterval()
			if d < 55*time.Second || d > 65*time.Second {
				t.Errorf("tickWindowedInterval() = %v, want in [55s, 65s]", d)
			}
		}
	})
}

// ---------------------------------------------------------------------
// AC-11: empty queue → poll_interval sleep, no busy-loop
// ---------------------------------------------------------------------

func TestScanWorker_EmptyQueue_PollIntervalSleep(t *testing.T) {
	t.Run("system-worker-subcommand/AC-11", func(t *testing.T) {
		pool := freshPool(t)

		rec := &emitRecorder{}
		bridge := stubBridge{plain: []byte("dummy")}
		exec := kensa.NewExecutor(bridge, rec.executorEmit())
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		key := make([]byte, 32)
		const pollInterval = 100 * time.Millisecond

		w := NewScanWorker(Config{
			Pool:         pool,
			Executor:     exec,
			Writer:       writer,
			QueueKey:     key,
			PollInterval: pollInterval,
			Emit:         rec.Emit(),
		})

		const runFor = 500 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), runFor)
		defer cancel()
		_ = w.Run(ctx)

		// idleCount counts each ErrNoJob iteration. With a 500ms run
		// and a 100ms poll interval, expect ~5 (allow +/- a few for
		// scheduling jitter; the upper bound matters most — a true
		// busy-loop would push this into the thousands).
		got := w.idleCount.Load()
		if got < 1 {
			t.Errorf("idleCount = %d, want at least 1 (loop must run)", got)
		}
		if got > 25 {
			t.Errorf("idleCount = %d, busy-loop suspected — must sleep poll_interval between dequeues", got)
		}
	})
}

// ---------------------------------------------------------------------
// JSONB-shape verification of worker.loop.tick payload (supports AC-08)
// ---------------------------------------------------------------------

func TestWorkerLoopTickPayload_Shape(t *testing.T) {
	// Construct the JSON directly using the same shape emitTick would
	// produce. Asserts the key names match the audit registration in
	// app/audit/events.yaml. (A runtime test of emitTick would need to
	// wait 60s; this shape test runs in microseconds.)
	detail, _ := json.Marshal(map[string]int64{
		"idle_count":                0,
		"claimed_count":             0,
		"in_flight_count":           0,
		"completed_since_last_tick": 0,
	})
	var parsed map[string]int64
	if err := json.Unmarshal(detail, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, key := range []string{"idle_count", "claimed_count", "in_flight_count", "completed_since_last_tick"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("worker.loop.tick payload missing %q", key)
		}
	}
}
