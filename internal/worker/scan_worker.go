// Package worker — production scan-job consumer.
//
// ScanWorker is the long-lived loop that backs the `openwatch worker`
// subcommand. It:
//
//  1. Claims one scan job at a time via queue.Dequeue (SKIP LOCKED).
//  2. HMAC-verifies the payload via scheduler.Verify before any side effect.
//  3. Takes a pg_advisory_xact_lock keyed on the host (per-host concurrency).
//  4. Calls executor.Run with the host_id + policy_version (no framework arg —
//     v2.0.0 framework-at-query-time architecture).
//  5. On success: persists per-rule outcomes via transactionlog.Writer.Apply,
//     resets host_backoff_state, queue.Complete.
//  6. On transient executor errors: queue.Fail + UPSERT host_backoff_state
//     with the ladder backoff (system-worker-subcommand C-05).
//  7. On permanent executor errors: queue.Fail; the executor has already
//     emitted scan.failed with the typed reason — the worker does NOT
//     emit a second.
//  8. On HMAC mismatch or malformed payload: queue.Fail + scheduler.job.hmac_rejected.
//
// SIGTERM contract (C-07): ctx cancellation stops new Dequeue calls; the
// in-flight executor.Run completes (the executor owns its per-scan timeout);
// its result is persisted; then Run returns.
//
// Spec: app/specs/system/worker-subcommand.spec.yaml
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/scanresult"
	"github.com/Hanalyx/openwatch/internal/scanruns"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
)

// ScanJobType is the queue.Job.JobType value scheduler.Service emits.
// Locked here so other job_types (diagnostics.test_job, future bulk ops)
// can coexist on the same queue without the scan worker grabbing them.
const ScanJobType = "scan"

// DefaultPollInterval is the empty-queue sleep between Dequeue attempts.
// system-worker-subcommand C-10 / AC-11: 1s default, max 5s, no busy-spin.
const DefaultPollInterval = 1 * time.Second

// MaxPollInterval is the upper bound on the configurable poll_interval.
// Operators picking a longer value mistakenly increase scan-pickup
// latency without a corresponding benefit; we cap rather than let them
// pick 10m by accident.
const MaxPollInterval = 5 * time.Second

// TickInterval is the nominal cadence of worker.loop.tick audit emission.
// System-worker-subcommand C-08 / AC-08: 55..65s range (60s + jitter).
const TickInterval = 60 * time.Second

// tickJitter is the +/- jitter applied to TickInterval so multiple
// workers in the same fleet don't synchronize their tick emissions.
const tickJitter = 5 * time.Second

// ScanWorker is the production worker. One per process. Constructed at
// boot in cmd/openwatch/worker.go via NewScanWorker; held until SIGTERM.
type ScanWorker struct {
	pool        *pgxpool.Pool
	executor    *kensa.Executor
	writer      *transactionlog.Writer
	scanResults *scanresult.Writer // nil = durable per-scan results not recorded (legacy tests)
	queueKey    []byte
	bus         *eventbus.Bus      // nil = no scan.completed publication (dedicated worker process)
	sched       *scheduler.Service // nil = no post-scan schedule update (legacy tests)
	remProc     *RemediationWorker // nil = "remediation" jobs fail (legacy tests)

	pollInterval time.Duration

	// Counters for worker.loop.tick audit. Atomic for safe access from
	// the loop goroutine; not contested in practice (one writer per
	// process).
	idleCount      atomic.Int64
	claimedCount   atomic.Int64
	inFlightCount  atomic.Int64
	completedCount atomic.Int64

	clock func() time.Time
	emit  EmitFunc
}

// EmitFunc matches audit.Emit's signature; production wires audit.Emit
// directly. Tests pass a recorder.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Config is the constructor argument bundle. All fields except clock are
// required.
type Config struct {
	Pool         *pgxpool.Pool
	Executor     *kensa.Executor
	Writer       *transactionlog.Writer
	QueueKey     []byte // scheduler.DeriveQueueKey output
	PollInterval time.Duration
	Emit         EmitFunc

	// ScanResults, when non-nil, durably records every rule's outcome +
	// evidence for every scan (the /api/v1/scans audit memory). It is
	// written alongside Writer, never instead of it. nil disables the
	// durable write (legacy tests that only assert transaction-log
	// behavior leave it unset).
	ScanResults *scanresult.Writer

	// Bus, when non-nil, receives scan.completed events after outcomes
	// persist. The serve process passes its SSE bus; the dedicated
	// worker subcommand passes nil (its in-memory bus would have no
	// subscribers — cross-process delivery is a known non-goal).
	Bus *eventbus.Bus

	// Sched, when non-nil, receives PersistAfterScan after every
	// completed scan so host_compliance_schedule tracks the fresh
	// compliance state and next_scheduled_scan. Spec system-scheduler
	// v3.0.0: both scheduler-dispatched and on-demand scans update the
	// schedule on completion.
	Sched *scheduler.Service

	// RemediationProcessor, when non-nil, handles "remediation" job_type
	// rows this worker claims. queue.Dequeue is not type-filtered, so the
	// dedicated worker subcommand routes remediation jobs to it rather than
	// dead-lettering them. Spec api-remediation.
	RemediationProcessor *RemediationWorker

	// clock allows tests to inject a controllable time source.
	// Production passes time.Now.
	Clock func() time.Time
}

// NewScanWorker wires a ScanWorker. The dependencies are constructed at
// boot in cmd/openwatch/worker.go and held for the process lifetime.
func NewScanWorker(cfg Config) *ScanWorker {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.PollInterval > MaxPollInterval {
		cfg.PollInterval = MaxPollInterval
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Emit == nil {
		cfg.Emit = audit.Emit
	}
	return &ScanWorker{
		pool:         cfg.Pool,
		executor:     cfg.Executor,
		writer:       cfg.Writer,
		scanResults:  cfg.ScanResults,
		queueKey:     cfg.QueueKey,
		bus:          cfg.Bus,
		sched:        cfg.Sched,
		remProc:      cfg.RemediationProcessor,
		pollInterval: cfg.PollInterval,
		clock:        cfg.Clock,
		emit:         cfg.Emit,
	}
}

// Run is the worker loop. Returns nil on clean shutdown (ctx cancelled
// and any in-flight job completed). Returns a non-nil error only if the
// loop encountered a fatal problem (none today — every per-job error is
// classified and handled).
//
// Spec C-07 / AC-06: ctx cancellation stops new Dequeue calls; an
// in-flight job is allowed to finish (the executor owns its per-scan
// timeout), its result is applied, then Run returns.
func (w *ScanWorker) Run(ctx context.Context) error {
	nextTick := w.clock().Add(tickWindowedInterval())

	for {
		// Check for shutdown BEFORE attempting Dequeue. This is the
		// only point where SIGTERM short-circuits — once we've claimed
		// a job, we run it to completion.
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Emit worker.loop.tick if due. Idempotent on schedule.
		if now := w.clock(); !now.Before(nextTick) {
			w.emitTick(ctx)
			nextTick = now.Add(tickWindowedInterval())
		}

		// Dequeue with parent ctx — SIGTERM cancels new claims here.
		job, jobCtx, err := queue.Dequeue(ctx, w.pool)
		if err != nil {
			if errors.Is(err, queue.ErrNoJob) {
				w.idleCount.Add(1)
				// Sleep poll_interval before next attempt. C-10 / AC-11.
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(w.pollInterval):
				}
				continue
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			slog.WarnContext(ctx, "worker dequeue failed", slog.String("error", err.Error()))
			// Don't busy-loop on persistent dequeue errors.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(w.pollInterval):
			}
			continue
		}

		w.claimedCount.Add(1)
		w.inFlightCount.Add(1)
		// processJob uses jobCtx (fresh, decoupled from parent ctx)
		// so SIGTERM does NOT abort the in-flight scan. The executor's
		// per-scan timeout is the bound on how long this takes.
		w.ProcessJob(jobCtx, job)
		w.inFlightCount.Add(-1)
		w.completedCount.Add(1)
	}
}

// ProcessJob runs the full per-job pipeline. Recovers from panics so a
// rogue scan does not take down the worker; emits a typed audit on the
// panic path.
func (w *ScanWorker) ProcessJob(ctx context.Context, j *queue.Job) {
	defer func() {
		if r := recover(); r != nil {
			slog.ErrorContext(ctx, "worker panic during scan",
				slog.String("job_id", j.ID.String()),
				slog.Any("panic", r))
			_ = queue.Fail(ctx, w.pool, j.ID, fmt.Sprintf("worker panic: %v", r))
			w.markRunFailed(ctx, j.ID, "worker_panic")
		}
	}()

	// Dispatch by job type: this one worker drains the queue (queue.Dequeue
	// is not type-filtered) and routes by JobType. Remediation jobs go to the
	// remediation processor when wired; anything else that isn't a scan fails
	// fast — no executor invocation, no advisory lock.
	if j.JobType == RemediationJobType {
		if w.remProc == nil {
			_ = queue.Fail(ctx, w.pool, j.ID, "remediation processor not registered on this worker")
			return
		}
		w.remProc.ProcessJob(ctx, j)
		return
	}
	if j.JobType != ScanJobType {
		_ = queue.Fail(ctx, w.pool, j.ID, fmt.Sprintf("unsupported job_type %q (scan worker)", j.JobType))
		return
	}

	// Parse + HMAC-verify BEFORE any side effect (C-02).
	payload, tag, err := parseScanPayload(j.Payload)
	if err != nil {
		w.emitHMACRejected(ctx, j.ID, payload.HostID, err)
		_ = queue.Fail(ctx, w.pool, j.ID, fmt.Sprintf("hmac_rejected: %v", err))
		w.markRunFailed(ctx, j.ID, "hmac_rejected")
		return
	}
	if !scheduler.Verify(w.queueKey, payload, tag) {
		w.emitHMACRejected(ctx, j.ID, payload.HostID, errors.New("hmac mismatch"))
		_ = queue.Fail(ctx, w.pool, j.ID, "hmac_rejected: signature does not match payload")
		w.markRunFailed(ctx, j.ID, "hmac_rejected")
		return
	}

	// Scan-run logbook: the run is now in a worker's hands. UPSERT so a
	// job enqueued without an Insert (hand-enqueued) still gets a row.
	// Spec system-scan-runs AC-02.
	if err := scanruns.MarkRunning(ctx, w.pool, j.ID, payload.HostID, payload.PolicyVersion); err != nil {
		slog.WarnContext(ctx, "worker scan_runs mark running failed",
			slog.String("scan_id", j.ID.String()),
			slog.String("error", err.Error()))
		// Non-fatal: the logbook is observability, not the scan itself.
	}

	// Per-host concurrency guard via pg_advisory_xact_lock (C-09).
	tx, err := acquireHostLock(ctx, w.pool, payload.HostID)
	if err != nil {
		// Failing to acquire is treated as transient — the DB is in
		// trouble and the scheduler should back off.
		slog.WarnContext(ctx, "worker advisory lock failed",
			slog.String("host_id", payload.HostID.String()),
			slog.String("error", err.Error()))
		w.recordTransientFailure(ctx, j.ID, payload.HostID, kensa.ReasonTimeout)
		return
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Execute. The executor owns its per-scan timeout (system-kensa-executor
	// C-04). v2.0.0 signature: NO framework parameter.
	result, scanErr := w.executor.Run(ctx, payload.HostID, payload.PolicyVersion)

	if scanErr != nil {
		w.classifyAndHandle(ctx, j.ID, payload.HostID, scanErr)
		return
	}

	// Success: persist outcomes atomically. ScanID == job.ID for traceability.
	batch := transactionlog.ApplyBatch{
		ScanID:  j.ID,
		HostID:  payload.HostID,
		Results: toTransactionLogResults(result.Outcomes),
	}
	if err := w.writer.Apply(ctx, batch); err != nil {
		// Persistence failure after a successful scan is treated as
		// transient — the host still has its compliance state; we just
		// failed to record it. The scheduler will retry the scan after
		// suppress_until passes.
		slog.WarnContext(ctx, "worker writer.Apply failed",
			slog.String("scan_id", j.ID.String()),
			slog.String("host_id", payload.HostID.String()),
			slog.String("error", err.Error()))
		w.recordTransientFailure(ctx, j.ID, payload.HostID, kensa.ReasonKensaError)
		return
	}

	// Durable audit memory: record EVERY rule's outcome + evidence for
	// this scan so the historical scan stays browsable/OSCAL-exportable
	// (the transaction log above keeps only current state + changes).
	// Written before MarkCompleted so a run is not marked completed until
	// its durable record lands. Both writers are scan_id-idempotent, so a
	// transient failure here retries the whole scan and self-heals.
	if w.scanResults != nil {
		if err := w.scanResults.Persist(ctx, scanresult.PersistBatch{
			ScanID:  j.ID,
			HostID:  payload.HostID,
			Results: toScanResultResults(result.Outcomes),
		}); err != nil {
			slog.WarnContext(ctx, "worker scanResults.Persist failed",
				slog.String("scan_id", j.ID.String()),
				slog.String("host_id", payload.HostID.String()),
				slog.String("error", err.Error()))
			w.recordTransientFailure(ctx, j.ID, payload.HostID, kensa.ReasonKensaError)
			return
		}
	}

	// Scan-run logbook: completed, with per-outcome counts.
	// Spec system-scan-runs AC-03.
	counts := outcomeCounts(result.Outcomes)
	if err := scanruns.MarkCompleted(ctx, w.pool, j.ID, counts); err != nil {
		slog.WarnContext(ctx, "worker scan_runs mark completed failed",
			slog.String("scan_id", j.ID.String()),
			slog.String("error", err.Error()))
	}

	// Adaptive schedule update: classify the fresh result into a
	// compliance state and re-anchor next_scheduled_scan. Runs for
	// BOTH scheduler-dispatched and on-demand scans — a manual scan
	// postpones the next auto scan rather than stacking onto it.
	// Spec system-scheduler v3.0.0 AC-08.
	if w.sched != nil {
		score := 0.0
		if total := len(result.Outcomes); total > 0 {
			score = float64(counts.Pass) / float64(total) * 100
		}
		hasCritical := false
		for _, o := range result.Outcomes {
			if o.Status == kensa.StatusFail && o.Severity == "critical" {
				hasCritical = true
				break
			}
		}
		if _, err := w.sched.PersistAfterScan(ctx, payload.HostID, score, hasCritical, w.clock().UTC()); err != nil {
			slog.WarnContext(ctx, "worker schedule update failed",
				slog.String("host_id", payload.HostID.String()),
				slog.String("error", err.Error()))
			// Non-fatal: the scan itself succeeded and persisted.
		}
	}

	// Announce on the event bus so SSE clients refresh compliance
	// surfaces without polling. Spec api-host-scan / frontend-live-events.
	// The post-publish metrics snapshot makes silent drops (no
	// subscriber registered / buffer full) visible in the log.
	if w.bus != nil {
		w.bus.Publish(ctx, eventbus.ScanCompleted{
			ScanID:      j.ID,
			HostID:      payload.HostID,
			Pass:        counts.Pass,
			Fail:        counts.Fail,
			Skipped:     counts.Skipped,
			Errored:     counts.Error,
			CompletedAt: w.clock().UTC(),
		})
		m := w.bus.Metrics().Snapshot()
		slog.InfoContext(ctx, "scan completed; scan.completed published",
			slog.String("scan_id", j.ID.String()),
			slog.String("host_id", payload.HostID.String()),
			slog.Int("pass", counts.Pass), slog.Int("fail", counts.Fail),
			slog.Int64("bus_published", m.PublishedCount),
			slog.Int64("bus_delivered", m.DeliveredCount),
			slog.Int64("bus_no_subscribers", m.NoSubscribersCount),
			slog.Int64("bus_dropped", m.DroppedCount))
	} else {
		slog.InfoContext(ctx, "scan completed; no event bus wired (dedicated worker)",
			slog.String("scan_id", j.ID.String()))
	}

	// Reset backoff streak on success.
	if err := w.executor.RecordSuccess(ctx, w.pool, payload.HostID); err != nil {
		slog.WarnContext(ctx, "worker backoff reset failed",
			slog.String("host_id", payload.HostID.String()),
			slog.String("error", err.Error()))
		// Non-fatal: backoff state is best-effort housekeeping.
	}

	if err := queue.Complete(ctx, w.pool, j.ID); err != nil {
		slog.WarnContext(ctx, "worker queue.Complete failed",
			slog.String("job_id", j.ID.String()),
			slog.String("error", err.Error()))
	}
}

// classifyAndHandle routes the executor's error to either the transient
// path (queue.Fail + host_backoff_state UPSERT, ladder backoff) or the
// permanent path (queue.Fail only; the executor already emitted
// scan.failed with the typed reason).
//
// Spec C-05 / C-06.
func (w *ScanWorker) classifyAndHandle(ctx context.Context, jobID uuid.UUID, hostID uuid.UUID, scanErr error) {
	switch {
	// Permanent: identity / configuration problems with this host or
	// credential. Backoff does NOT apply — re-running won't help; the
	// operator must intervene. The executor has already emitted
	// scan.failed with the typed reason.
	case errors.Is(scanErr, kensa.ErrCredentialDecryption):
		_ = queue.Fail(ctx, w.pool, jobID, "credential_decryption_failed")
		w.markRunFailed(ctx, jobID, "credential_decryption_failed")
	case errors.Is(scanErr, kensa.ErrEvidenceOversize):
		_ = queue.Fail(ctx, w.pool, jobID, "evidence_oversize")
		w.markRunFailed(ctx, jobID, "evidence_oversize")
	case errors.Is(scanErr, kensa.ErrHostKeyUnknown):
		_ = queue.Fail(ctx, w.pool, jobID, "host_key_unknown")
		w.markRunFailed(ctx, jobID, "host_key_unknown")
	case errors.Is(scanErr, kensa.ErrNoCredential):
		_ = queue.Fail(ctx, w.pool, jobID, "no_credential")
		w.markRunFailed(ctx, jobID, "no_credential")

	// Transient: host_busy, kensa internal (planner error, timeout),
	// context cancellation. Apply the backoff ladder.
	case errors.Is(scanErr, kensa.ErrHostBusy):
		w.recordTransientFailure(ctx, jobID, hostID, kensa.ReasonHostBusy)
	case errors.Is(scanErr, kensa.ErrKensaInternal):
		w.recordTransientFailure(ctx, jobID, hostID, kensa.ReasonKensaError)
	case errors.Is(scanErr, context.DeadlineExceeded):
		w.recordTransientFailure(ctx, jobID, hostID, kensa.ReasonTimeout)
	case errors.Is(scanErr, context.Canceled):
		// Worker SIGTERM during executor.Run shouldn't really happen
		// since we pass jobCtx (decoupled). But if it does, treat as
		// transient.
		w.recordTransientFailure(ctx, jobID, hostID, kensa.ReasonTimeout)

	default:
		// Unknown error class — treat as transient (kensa_error). The
		// alternative would be a silent permanent fail, which could
		// suppress a recoverable problem.
		slog.WarnContext(ctx, "worker unclassified scan error",
			slog.String("host_id", hostID.String()),
			slog.String("error", scanErr.Error()))
		w.recordTransientFailure(ctx, jobID, hostID, kensa.ReasonKensaError)
	}
}

// recordTransientFailure UPSERTs host_backoff_state via the kensa Executor's
// RecordFailure helper with the worker's own ladder, then queue.Fails the
// job. The ladder is configured via a synthetic BackoffPolicy whose
// computeSuppressUntil result is overridden by our own transientBackoff
// ladder — the kensa policy's doubling math doesn't match this spec's
// flat ladder. We accomplish this by recording the failure first to get
// the new consecutive_failures count, then computing suppress_until
// independently and overwriting.
func (w *ScanWorker) recordTransientFailure(ctx context.Context, jobID uuid.UUID, hostID uuid.UUID, reason kensa.FailureReason) {
	// Use the kensa helper to UPSERT consecutive_failures += 1. We pass
	// a no-op-ladder BackoffPolicy (threshold = 999) so it does NOT set
	// suppress_until; the worker's ladder applies instead.
	noop := kensa.BackoffPolicy{
		FailureThreshold:    999,
		MaxSuppressDuration: MaxBackoff,
		BaseInterval:        1 * time.Second,
	}
	newCount, _, err := w.executor.RecordFailure(ctx, w.pool, hostID, noop, reason)
	if err != nil {
		slog.WarnContext(ctx, "worker backoff RecordFailure failed",
			slog.String("host_id", hostID.String()),
			slog.String("error", err.Error()))
		// Still queue.Fail the job — backoff is housekeeping; the job
		// outcome is the primary persistence concern.
		_ = queue.Fail(ctx, w.pool, jobID, string(reason))
		w.markRunFailed(ctx, jobID, string(reason))
		return
	}

	// Apply the worker's flat ladder.
	suppressUntil := w.clock().Add(transientBackoff(newCount))
	if _, err := w.pool.Exec(ctx, `
		UPDATE host_backoff_state
		   SET suppress_until = $1, updated_at = $2
		 WHERE host_id = $3`,
		suppressUntil, w.clock(), hostID); err != nil {
		slog.WarnContext(ctx, "worker update suppress_until failed",
			slog.String("host_id", hostID.String()),
			slog.String("error", err.Error()))
	}

	if err := queue.Fail(ctx, w.pool, jobID, string(reason)); err != nil {
		slog.WarnContext(ctx, "worker queue.Fail failed",
			slog.String("job_id", jobID.String()),
			slog.String("error", err.Error()))
	}
	w.markRunFailed(ctx, jobID, string(reason))
}

// markRunFailed records the failure in the scan_runs logbook with its
// typed reason. Best-effort: logbook writes never affect the job
// outcome. Spec system-scan-runs AC-04.
func (w *ScanWorker) markRunFailed(ctx context.Context, jobID uuid.UUID, reason string) {
	if err := scanruns.MarkFailed(ctx, w.pool, jobID, reason); err != nil {
		slog.WarnContext(ctx, "worker scan_runs mark failed errored",
			slog.String("scan_id", jobID.String()),
			slog.String("error", err.Error()))
	}
}

// outcomeCounts tallies a completed scan's outcomes per status for the
// scan_runs row. Spec system-scan-runs AC-03.
func outcomeCounts(outcomes []kensa.RuleOutcome) scanruns.Counts {
	var c scanruns.Counts
	for _, o := range outcomes {
		switch o.Status {
		case kensa.StatusPass:
			c.Pass++
		case kensa.StatusFail:
			c.Fail++
		case kensa.StatusSkipped:
			c.Skipped++
		case kensa.StatusError:
			c.Error++
		}
	}
	return c
}

// emitHMACRejected fires scheduler.job.hmac_rejected. The event was
// registered for the scheduler dispatcher's enqueue path but the spec
// explicitly reuses the same audit code on the worker's verify-on-claim
// path (C-02, AC-02).
func (w *ScanWorker) emitHMACRejected(ctx context.Context, jobID uuid.UUID, hostID uuid.UUID, cause error) {
	failure := "hmac_mismatch"
	if errors.Is(cause, errMissingHMAC) {
		failure = "payload_missing_hmac"
	}
	detail, _ := json.Marshal(map[string]string{
		"job_id":  jobID.String(),
		"host_id": hostID.String(),
		"failure": failure,
	})
	w.emit(ctx, audit.SchedulerJobHmacRejected, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})
}

// emitTick fires worker.loop.tick with the current counters and resets
// completedCount for the next window.
func (w *ScanWorker) emitTick(ctx context.Context) {
	completed := w.completedCount.Swap(0)
	detail, _ := json.Marshal(map[string]int64{
		"idle_count":                w.idleCount.Load(),
		"claimed_count":             w.claimedCount.Load(),
		"in_flight_count":           w.inFlightCount.Load(),
		"completed_since_last_tick": completed,
	})
	w.emit(ctx, audit.WorkerLoopTick, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})
}

// tickWindowedInterval returns a jittered duration in [55s, 65s] so
// multiple workers in the same fleet don't synchronize tick emission.
// Spec C-08 / AC-08.
//
// math/rand/v2 is intentional here: this is timing jitter (scheduling
// noise), NOT a security-sensitive secret. Crypto-strong randomness
// would just burn entropy for no defensive benefit.
func tickWindowedInterval() time.Duration {
	// rand.Int64N is range [0, n); we want [-tickJitter, +tickJitter].
	jitter := time.Duration(rand.Int64N(int64(2*tickJitter))) - tickJitter // #nosec G404 -- scheduling jitter, not a secret
	return TickInterval + jitter
}

// toTransactionLogResults converts kensa.RuleOutcome values to
// transactionlog.Result values. The shapes mirror each other but the
// type identities are distinct so the boundary stays clear: kensa
// produces; transactionlog consumes.
func toTransactionLogResults(outcomes []kensa.RuleOutcome) []transactionlog.Result {
	out := make([]transactionlog.Result, len(outcomes))
	for i, o := range outcomes {
		out[i] = transactionlog.Result{
			RuleID:        o.RuleID,
			Status:        transactionlog.Status(o.Status),
			Severity:      o.Severity,
			Evidence:      o.Evidence,
			FrameworkRefs: o.FrameworkRefs,
			SkipReason:    o.SkipReason,
		}
	}
	return out
}

// toScanResultResults converts kensa.RuleOutcome values to
// scanresult.Result values for the durable per-scan store. Mirrors
// toTransactionLogResults; the two consume the SAME kensa.Evidence bytes
// so their evidence caps must agree (see scanresult.MaxEvidenceBytes).
func toScanResultResults(outcomes []kensa.RuleOutcome) []scanresult.Result {
	out := make([]scanresult.Result, len(outcomes))
	for i, o := range outcomes {
		out[i] = scanresult.Result{
			RuleID:        o.RuleID,
			Status:        scanresult.Status(o.Status),
			Severity:      o.Severity,
			Evidence:      o.Evidence,
			FrameworkRefs: o.FrameworkRefs,
			SkipReason:    o.SkipReason,
		}
	}
	return out
}
