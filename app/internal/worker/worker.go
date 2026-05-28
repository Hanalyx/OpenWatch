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
	"log/slog"
	"sync"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PollInterval is how often the loop checks for pending jobs when the
// queue is empty. Short enough that DoD step 16 sees a result within 2s.
const PollInterval = 200 * time.Millisecond

// Worker drains pending jobs from job_queue. One Worker per process is
// enough for Stage 0; multi-worker setups are Stage 2.
type Worker struct {
	pool *pgxpool.Pool
	stop chan struct{}
	wg   sync.WaitGroup
}

// New constructs a Worker bound to the given pool. Call Start to begin
// the drain loop and Stop to exit cleanly.
func New(pool *pgxpool.Pool) *Worker {
	return &Worker{
		pool: pool,
		stop: make(chan struct{}),
	}
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

// process handles one job. For Stage 0 only diagnostics.test_job is
// supported; any other job type is failed with an unsupported error.
func (w *Worker) process(ctx context.Context, j *queue.Job) {
	switch j.JobType {
	case "diagnostics.test_job":
		w.processTestJob(ctx, j)
	default:
		_ = queue.Fail(ctx, w.pool, j.ID, "unsupported job_type for Stage 0 worker: "+j.JobType)
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
