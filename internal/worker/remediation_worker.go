// Package worker — production remediation-job consumer.
//
// RemediationWorker mirrors ScanWorker for the queued single-rule remediation
// path (Phase 7, Tier A free-core). It:
//
//  1. Parses + HMAC-verifies the remediation payload BEFORE any side effect.
//  2. Loads the approved (execute) / executed (rollback) request and guards
//     its state via the remediation service's row-locked transitions.
//  3. Calls executor.Remediate / executor.Rollback — which share the host's
//     per-host inFlight guard with scans (a host is never scanned + remediated
//     at the same instant).
//  4. Writes the remediation_transactions journal and transitions the request
//     to its terminal state (executed | failed | rolled_back).
//  5. On a committed execute, flips THAT one rule to pass in host_rule_state
//     via the transaction-log Writer (Kensa ran Validate before Commit, so the
//     rule now passes — no full re-scan needed) so the compliance score moves.
//  6. Publishes remediation.completed on the event bus, emits the audit event,
//     and marks the queue row complete.
//
// The worker owns the *kensa.Executor and the transaction-log Writer; the
// remediation service stays host-free and import-cycle-free (the worker maps
// kensa.RemediationTxn -> remediation.ExecTxn at this boundary).
//
// Spec: api-remediation, system-worker-subcommand.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/remediation"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
)

// RemediationWorker processes "remediation" queue jobs. One per process,
// constructed at boot and held until shutdown. It is dispatched to by both the
// in-process Worker.process and the dedicated ScanWorker.ProcessJob (each
// routes by JobType so one worker drains the queue).
type RemediationWorker struct {
	pool     *pgxpool.Pool
	executor *kensa.Executor
	svc      *remediation.Service
	writer   *transactionlog.Writer
	queueKey []byte
	bus      *eventbus.Bus // nil = no remediation.completed publication (dedicated worker)
	emit     EmitFunc
	clock    func() time.Time
}

// RemediationConfig is the constructor bundle. All fields except Bus/Clock/Emit
// are required.
type RemediationConfig struct {
	Pool     *pgxpool.Pool
	Executor *kensa.Executor
	Service  *remediation.Service
	Writer   *transactionlog.Writer
	QueueKey []byte
	Bus      *eventbus.Bus
	Emit     EmitFunc
	Clock    func() time.Time
}

// NewRemediationWorker wires a RemediationWorker.
func NewRemediationWorker(cfg RemediationConfig) *RemediationWorker {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Emit == nil {
		cfg.Emit = audit.Emit
	}
	return &RemediationWorker{
		pool:     cfg.Pool,
		executor: cfg.Executor,
		svc:      cfg.Service,
		writer:   cfg.Writer,
		queueKey: cfg.QueueKey,
		bus:      cfg.Bus,
		emit:     cfg.Emit,
		clock:    cfg.Clock,
	}
}

// ProcessJob runs the full remediation pipeline for one job. Recovers from
// panics so a rogue remediation does not take down the worker.
func (w *RemediationWorker) ProcessJob(ctx context.Context, j *queue.Job) {
	defer func() {
		if r := recover(); r != nil {
			slog.ErrorContext(ctx, "worker panic during remediation",
				slog.String("job_id", j.ID.String()),
				slog.Any("panic", r))
			_ = queue.Fail(ctx, w.pool, j.ID, fmt.Sprintf("worker panic: %v", r))
		}
	}()

	if j.JobType != RemediationJobType {
		_ = queue.Fail(ctx, w.pool, j.ID, fmt.Sprintf("unsupported job_type %q (remediation worker)", j.JobType))
		return
	}

	// Parse + HMAC-verify BEFORE any side effect.
	payload, tag, err := parseRemediationPayload(j.Payload)
	if err != nil {
		w.emitHMACRejected(ctx, j.ID, payload, err)
		_ = queue.Fail(ctx, w.pool, j.ID, fmt.Sprintf("hmac_rejected: %v", err))
		return
	}
	if !verifyRemediation(w.queueKey, payload, tag) {
		w.emitHMACRejected(ctx, j.ID, payload, errors.New("hmac mismatch"))
		_ = queue.Fail(ctx, w.pool, j.ID, "hmac_rejected: signature does not match payload")
		return
	}

	// The user who invoked the action rides on the queue row's correlation
	// chain; the audit actor is the request's requester/reviewer context.
	// We attribute the system action to the request's host for traceability;
	// the HTTP layer already emitted the intent. Actor is uuid.Nil here
	// (system), with the request id in detail.
	switch payload.Action {
	case RemediationActionExecute:
		w.processExecute(ctx, j, payload)
	case RemediationActionRollback:
		w.processRollback(ctx, j, payload)
	default:
		_ = queue.Fail(ctx, w.pool, j.ID, "unknown remediation action: "+payload.Action)
	}
}

// remediationBusyBackoff is how long a remediation job waits before being
// retried when its target host is busy with another remediation. Only one rule
// is applied on a host at a time (they share a single SSH session via the
// executor's per-host guard), so concurrent "Fix" clicks serialize instead of
// failing. Kept short — the running remediation, not the wait, is the bottleneck.
const remediationBusyBackoff = 3 * time.Second

// processExecute drives approved -> executing -> executed|failed. When the host
// is already being remediated, it backs off and requeues (serialize per host)
// instead of failing the request.
func (w *RemediationWorker) processExecute(ctx context.Context, j *queue.Job, p RemediationPayload) {
	// Serialize per host: if another remediation is already executing on this
	// host, requeue with a backoff rather than colliding on the per-host SSH
	// guard (which would fail this request). The request stays 'approved'.
	if busy, err := w.svc.HostHasExecuting(ctx, p.HostID); err == nil && busy {
		w.requeueBusy(ctx, j, p)
		return
	}

	// Guard + transition approved -> executing (row-locked). A duplicate
	// enqueue or a request not in 'approved' fails here without touching the
	// host.
	rq, err := w.svc.MarkExecuting(ctx, p.RequestID)
	if err != nil {
		if errors.Is(err, remediation.ErrWrongState) || errors.Is(err, remediation.ErrNotFound) {
			_ = queue.Fail(ctx, w.pool, j.ID, "execute precondition: "+err.Error())
			return
		}
		slog.WarnContext(ctx, "remediation MarkExecuting failed",
			slog.String("request_id", p.RequestID.String()),
			slog.String("error", err.Error()))
		_ = queue.Fail(ctx, w.pool, j.ID, "execute mark: "+err.Error())
		return
	}

	// Apply the rule on the host (Capture/Apply/Validate/Commit). The
	// executor owns the per-host concurrency guard.
	result, remErr := w.executor.Remediate(ctx, p.HostID, p.RuleID)
	if remErr != nil {
		// A lost race for the per-host guard is TRANSIENT, not a host-side
		// failure: revert executing -> approved and requeue so it retries once
		// the host frees, rather than marking the request failed.
		if errors.Is(remErr, kensa.ErrHostBusy) {
			if _, rerr := w.svc.RevertToApproved(ctx, p.RequestID); rerr != nil {
				slog.WarnContext(ctx, "remediation revert-to-approved failed",
					slog.String("request_id", p.RequestID.String()),
					slog.String("error", rerr.Error()))
			}
			w.requeueBusy(ctx, j, p)
			return
		}
		// Real host-side failure: record an empty journal + transition to failed.
		w.finishExecute(ctx, j, rq, p, nil, false)
		slog.WarnContext(ctx, "remediation execute failed on host",
			slog.String("request_id", p.RequestID.String()),
			slog.String("host_id", p.HostID.String()),
			slog.String("error", remErr.Error()))
		return
	}

	txns := mapExecTxns(result.Transactions)
	committed := anyCommitted(txns)
	w.finishExecute(ctx, j, rq, p, txns, committed)
}

// requeueBusy completes the current job and re-enqueues the same signed action
// after remediationBusyBackoff, so a worker retries it once the host frees up.
// Dequeue skips the not-yet-available row, so this does not busy-loop the
// drain. A failure to re-enqueue falls back to failing the job (visible) rather
// than silently dropping the action.
func (w *RemediationWorker) requeueBusy(ctx context.Context, j *queue.Job, p RemediationPayload) {
	body := MarshalRemediationJob(w.queueKey, p)
	if _, err := queue.EnqueueAfter(ctx, w.pool, RemediationJobType, body, remediationBusyBackoff); err != nil {
		slog.WarnContext(ctx, "remediation requeue (host busy) failed",
			slog.String("request_id", p.RequestID.String()),
			slog.String("error", err.Error()))
		_ = queue.Fail(ctx, w.pool, j.ID, "requeue (host busy) failed: "+err.Error())
		return
	}
	_ = queue.Complete(ctx, w.pool, j.ID)
}

// finishExecute writes the journal, transitions to executed|failed, flips the
// rule to pass on a committed execute, publishes + audits, completes the job.
func (w *RemediationWorker) finishExecute(ctx context.Context, j *queue.Job,
	rq remediation.Request, p RemediationPayload, txns []remediation.ExecTxn, committed bool) {

	final, err := w.svc.RecordExecution(ctx, p.RequestID, p.RuleID, txns)
	if err != nil {
		slog.WarnContext(ctx, "remediation RecordExecution failed",
			slog.String("request_id", p.RequestID.String()),
			slog.String("error", err.Error()))
		_ = queue.Fail(ctx, w.pool, j.ID, "record execution: "+err.Error())
		return
	}

	// On a committed execute, flip THIS one rule to pass in host_rule_state so
	// the compliance score moves. Kensa's Validate ran before Commit, so the
	// rule passes now — no full re-scan needed. The transaction-log Writer is
	// scan_id-idempotent; we key on the request id as a synthetic scan id.
	if committed {
		if err := w.flipRuleToPass(ctx, p); err != nil {
			slog.WarnContext(ctx, "remediation host_rule_state flip failed",
				slog.String("request_id", p.RequestID.String()),
				slog.String("rule_id", p.RuleID),
				slog.String("error", err.Error()))
			// Non-fatal: the request is recorded executed; the next scan will
			// reconcile host_rule_state. We do not fail the job for this.
		}
	}

	w.svc.EmitExecuted(ctx, final, uuid.Nil, committed)
	w.publishCompleted(ctx, eventbus.RemediationCompleted{
		RequestID:   final.ID,
		HostID:      final.HostID,
		RuleID:      final.RuleID,
		Action:      RemediationActionExecute,
		FinalStatus: string(final.Status),
		RuleFlipped: committed,
		CompletedAt: w.clock().UTC(),
	})

	if err := queue.Complete(ctx, w.pool, j.ID); err != nil {
		slog.WarnContext(ctx, "remediation queue.Complete failed",
			slog.String("job_id", j.ID.String()),
			slog.String("error", err.Error()))
	}
	_ = rq // rq (pre-transition) retained for symmetry / future detail use
}

// processRollback drives executed -> rolled_back.
func (w *RemediationWorker) processRollback(ctx context.Context, j *queue.Job, p RemediationPayload) {
	// The request must be 'executed'. We do not transition up-front (no
	// 'rolling_back' state); MarkRolledBack at the end guards executed ->
	// rolled_back. Validate the precondition by reading the request.
	rq, err := w.svc.Get(ctx, p.RequestID)
	if err != nil {
		_ = queue.Fail(ctx, w.pool, j.ID, "rollback precondition: "+err.Error())
		return
	}
	if rq.Status != remediation.StatusExecuted {
		_ = queue.Fail(ctx, w.pool, j.ID, "rollback precondition: request not in executed state")
		return
	}

	// Serialize per host: a rollback shares the per-host SSH guard with execute,
	// so if another remediation is executing on this host, back off and requeue.
	if busy, herr := w.svc.HostHasExecuting(ctx, p.HostID); herr == nil && busy {
		w.requeueBusy(ctx, j, p)
		return
	}

	// Resolve the rollback handle: the payload's txn id, or the first
	// committed transaction recorded for the request.
	txnID := p.TxnID
	if txnID == uuid.Nil {
		resolved, ok, ferr := w.svc.FirstCommittedTxn(ctx, p.RequestID)
		if ferr != nil || !ok {
			_ = queue.Fail(ctx, w.pool, j.ID, "rollback: no committed transaction to revert")
			return
		}
		txnID = resolved
	}

	res, rbErr := w.executor.Rollback(ctx, p.HostID, txnID)
	// A lost race for the per-host guard is transient: requeue and retry rather
	// than recording a failed rollback (the request stays 'executed').
	if errors.Is(rbErr, kensa.ErrHostBusy) {
		w.requeueBusy(ctx, j, p)
		return
	}
	status := "failed"
	if rbErr == nil && res != nil {
		status = res.Status
	}

	// Only a clean rollback flips the lifecycle to rolled_back.
	if rbErr == nil && res != nil && res.Status == "rolled_back" {
		final, terr := w.svc.MarkRolledBack(ctx, p.RequestID)
		if terr != nil {
			slog.WarnContext(ctx, "remediation MarkRolledBack failed",
				slog.String("request_id", p.RequestID.String()),
				slog.String("error", terr.Error()))
			_ = queue.Fail(ctx, w.pool, j.ID, "rollback mark: "+terr.Error())
			return
		}
		w.svc.EmitRolledBack(ctx, final, uuid.Nil, status)
		w.publishCompleted(ctx, eventbus.RemediationCompleted{
			RequestID:   final.ID,
			HostID:      final.HostID,
			RuleID:      final.RuleID,
			Action:      RemediationActionRollback,
			FinalStatus: string(final.Status),
			CompletedAt: w.clock().UTC(),
		})
		if err := queue.Complete(ctx, w.pool, j.ID); err != nil {
			slog.WarnContext(ctx, "remediation rollback queue.Complete failed",
				slog.String("job_id", j.ID.String()),
				slog.String("error", err.Error()))
		}
		return
	}

	// Rollback did not cleanly restore: leave the request 'executed', audit
	// the outcome, fail the job so the operator sees it did not revert.
	w.svc.EmitRolledBack(ctx, rq, uuid.Nil, status)
	detail := status
	if rbErr != nil {
		detail = rbErr.Error()
	}
	_ = queue.Fail(ctx, w.pool, j.ID, "rollback did not restore: "+detail)
}

// flipRuleToPass writes a single-rule transaction-log batch marking p.RuleID
// pass on the host. Keyed on the request id as a synthetic scan id so the
// Writer's scan_id idempotency makes a re-delivered job a no-op.
func (w *RemediationWorker) flipRuleToPass(ctx context.Context, p RemediationPayload) error {
	return w.writer.Apply(ctx, transactionlog.ApplyBatch{
		ScanID: p.RequestID, // synthetic scan id == request id (idempotent)
		HostID: p.HostID,
		Results: []transactionlog.Result{{
			RuleID: p.RuleID,
			Status: transactionlog.StatusPass,
			Evidence: mustEvidence(map[string]any{
				"source":     "remediation",
				"request_id": p.RequestID.String(),
				"note":       "rule passed post-remediation (Kensa Validate before Commit)",
			}),
		}},
	})
}

// publishCompleted publishes remediation.completed when a bus is wired.
func (w *RemediationWorker) publishCompleted(ctx context.Context, ev eventbus.RemediationCompleted) {
	if w.bus == nil {
		return
	}
	w.bus.Publish(ctx, ev)
}

// emitHMACRejected fires scheduler.job.hmac_rejected for a rejected
// remediation payload (the same audit code the scan path reuses on verify).
func (w *RemediationWorker) emitHMACRejected(ctx context.Context, jobID uuid.UUID, p RemediationPayload, cause error) {
	failure := "hmac_mismatch"
	if errors.Is(cause, errRemMissingHMAC) {
		failure = "payload_missing_hmac"
	}
	detail, _ := json.Marshal(map[string]string{
		"job_id":     jobID.String(),
		"request_id": p.RequestID.String(),
		"host_id":    p.HostID.String(),
		"failure":    failure,
		"job_type":   RemediationJobType,
	})
	w.emit(ctx, audit.SchedulerJobHmacRejected, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})
}

// mapExecTxns converts kensa transaction outcomes into the neutral remediation
// journal shape (so internal/remediation never imports internal/kensa).
func mapExecTxns(in []kensa.RemediationTxn) []remediation.ExecTxn {
	out := make([]remediation.ExecTxn, 0, len(in))
	for _, t := range in {
		out = append(out, remediation.ExecTxn{
			TxnID:    t.TxnID,
			Status:   t.Status,
			Evidence: t.Evidence,
			Err:      t.Err,
		})
	}
	return out
}

func anyCommitted(txns []remediation.ExecTxn) bool {
	for _, t := range txns {
		if t.Committed() {
			return true
		}
	}
	return false
}

func mustEvidence(v map[string]any) []byte {
	b, _ := json.Marshal(v)
	return b
}
