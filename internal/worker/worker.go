// Package worker is the Stage-0 in-process job consumer. It polls the
// job_queue table on a short interval, drains diagnostics.test_job rows
// by emitting a diagnostics.test_job_completed audit event, and marks
// each job completed.
//
// Stage 2 replaces this with a per-job-type dispatcher; the in-process
// loop here exists only to demonstrate the queue + correlation contract
// end-to-end (DoD step 16).
//
// Spec: app/specs/release/stage-0-signoff.spec.yaml AC-10, C-02.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/scanruns"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PollInterval is how often the loop checks for pending jobs when the
// queue is empty. Short enough that DoD step 16 sees a result within 2s.
const PollInterval = 200 * time.Millisecond

// HostDiscoveryRunner is the seam the worker uses to invoke the OS
// Discovery flow when it drains a host.discovery job. The real
// implementation is internal/intelligence/discovery.Service.RunDiscovery
// (the error-only adapter over Discover). Interface lives here so the
// worker doesn't import intelligence (which would otherwise create a
// cycle via internal/credential's transitive imports).
type HostDiscoveryRunner interface {
	RunDiscovery(ctx context.Context, hostID uuid.UUID) error
}

// Worker drains pending jobs from job_queue. One Worker per process is
// enough for Stage 0; multi-worker setups are Stage 2.
type Worker struct {
	pool      *pgxpool.Pool
	stop      chan struct{}
	wg        sync.WaitGroup
	discovery HostDiscoveryRunner
	scanProc  *ScanWorker
}

// New constructs a Worker bound to the given pool. Call Start to begin
// the drain loop and Stop to exit cleanly.
func New(pool *pgxpool.Pool) *Worker {
	return &Worker{
		pool: pool,
		stop: make(chan struct{}),
	}
}

// WithDiscovery registers the OS Discovery runner. When set, the
// worker processes host.discovery jobs by calling Discover; nil keeps
// the legacy behavior (host.discovery fails as unsupported).
// Spec system-host-discovery C-05.
func (w *Worker) WithDiscovery(d HostDiscoveryRunner) *Worker {
	w.discovery = d
	return w
}

// WithScanProcessor registers a ScanWorker whose ProcessJob handles
// "scan" jobs claimed by THIS worker's loop. queue.Dequeue is not
// type-filtered, so the in-process worker must route scan jobs rather
// than fail them as unsupported — otherwise a serve-process claim of
// an on-demand scan would dead-end the job. The single-binary
// deployment processes scans in-process; a dedicated `openwatch
// worker` process can run alongside (both are capable; first claim
// wins). Spec api-host-scan / system-scan-runs.
func (w *Worker) WithScanProcessor(sw *ScanWorker) *Worker {
	w.scanProc = sw
	return w
}

// Start kicks off the drain loop on a background goroutine. Returns
// immediately. Safe to call once per Worker.
func (w *Worker) Start(ctx context.Context) {
	w.wg.Add(1)
	go w.loop(ctx)
}

// Stop signals the loop to exit and waits for the in-flight drain (if
// any) to complete.
func (w *Worker) Stop() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	w.wg.Wait()
}

func (w *Worker) loop(parentCtx context.Context) {
	defer w.wg.Done()
	t := time.NewTicker(PollInterval)
	defer t.Stop()
	for {
		select {
		case <-parentCtx.Done():
			return
		case <-w.stop:
			return
		case <-t.C:
			w.drainOnce(parentCtx)
		}
	}
}

// drainOnce claims and processes pending jobs until the queue is empty
// or an unrecoverable error occurs. Each job's correlation_id rides
// onto a fresh worker context; the caller-loop ctx is not used as
// parent (per system-job-queue AC-04 / C-02).
func (w *Worker) drainOnce(parentCtx context.Context) {
	for {
		// parentCtx is used only for cancellation propagation on the
		// Dequeue call itself, NOT as the parent of the worker ctx.
		job, workerCtx, err := queue.Dequeue(parentCtx, w.pool)
		if err != nil {
			if errors.Is(err, queue.ErrNoJob) {
				return // empty queue; let the ticker fire again
			}
			slog.WarnContext(parentCtx, "worker dequeue failed",
				slog.String("err", err.Error()))
			return
		}
		w.process(workerCtx, job)
	}
}

// process handles one job. Stage 0 supports diagnostics.test_job;
// PR 1.1 added host.discovery routing through the registered runner.
// Any other job type is failed with an unsupported error.
func (w *Worker) process(ctx context.Context, j *queue.Job) {
	switch j.JobType {
	case "diagnostics.test_job":
		w.processTestJob(ctx, j)
	case "host.discovery":
		w.processHostDiscovery(ctx, j)
	case ScanJobType:
		if w.scanProc == nil {
			_ = queue.Fail(ctx, w.pool, j.ID, "scan processor not registered on this worker")
			// Logbook integrity: a misconfigured worker must not strand
			// the scan_runs row in queued/running. Spec system-scan-runs
			// AC-04 (every scan-job failure pairs with MarkFailed).
			if err := scanruns.MarkFailed(ctx, w.pool, j.ID, "scan_processor_not_registered"); err != nil {
				slog.WarnContext(ctx, "scan_runs mark failed errored",
					slog.String("scan_id", j.ID.String()),
					slog.String("error", err.Error()))
			}
			return
		}
		w.scanProc.ProcessJob(ctx, j)
	default:
		_ = queue.Fail(ctx, w.pool, j.ID, "unsupported job_type for Stage 0 worker: "+j.JobType)
	}
}

// processHostDiscovery dispatches a host.discovery job to the
// registered Discovery runner. The runner emits its own audit /
// eventbus events on success; the worker just marks the queue row.
// Spec system-host-discovery C-05.
func (w *Worker) processHostDiscovery(ctx context.Context, j *queue.Job) {
	if w.discovery == nil {
		_ = queue.Fail(ctx, w.pool, j.ID,
			"host.discovery runner not registered on this worker")
		return
	}
	// Decode payload — same shape the API handler enqueues.
	var payload struct {
		HostID uuid.UUID `json:"host_id"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		_ = queue.Fail(ctx, w.pool, j.ID,
			fmt.Sprintf("host.discovery: payload decode: %v", err))
		return
	}
	if payload.HostID == uuid.Nil {
		_ = queue.Fail(ctx, w.pool, j.ID, "host.discovery: payload host_id missing")
		return
	}
	if err := w.discovery.RunDiscovery(ctx, payload.HostID); err != nil {
		_ = queue.Fail(ctx, w.pool, j.ID,
			fmt.Sprintf("host.discovery: %v", err))
		return
	}
	if err := queue.Complete(ctx, w.pool, j.ID); err != nil {
		slog.WarnContext(ctx, "worker complete failed",
			slog.String("job_id", j.ID.String()),
			slog.String("err", err.Error()))
	}
}

func (w *Worker) processTestJob(ctx context.Context, j *queue.Job) {
	detail, _ := json.Marshal(map[string]any{
		"job_id":   j.ID.String(),
		"job_type": j.JobType,
	})
	audit.Emit(ctx, audit.DiagnosticsTestJobCompleted, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})
	if err := queue.Complete(ctx, w.pool, j.ID); err != nil {
		slog.WarnContext(ctx, "worker complete failed",
			slog.String("job_id", j.ID.String()),
			slog.String("err", err.Error()))
	}
}
