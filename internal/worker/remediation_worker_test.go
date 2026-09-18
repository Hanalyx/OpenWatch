// @spec api-remediation
//
// Worker execution-path AC (DSN-gated):
//
//	AC-07  TestRemediationWorker_Execute_Committed_FlipsRuleToPass
//	AC-07  TestRemediationWorker_Execute_Errored_Failed_NoFlip
//	AC-07  TestRemediationWorker_HMACMismatch_DeadLettered_NoExecutorCall

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/remediation"
	"github.com/Hanalyx/openwatch/internal/scheduler"
	"github.com/Hanalyx/openwatch/internal/transactionlog"
)

// seedApprovedRequest creates a remediation request via the service and
// approves it (requester != reviewer), returning the approved request id.
func seedApprovedRequest(t *testing.T, pool *pgxpool.Pool, svc *remediation.Service,
	hostID uuid.UUID, ruleID string) uuid.UUID {
	t.Helper()
	requester := seedUniqueUser(t, pool)
	reviewer := seedUniqueUser(t, pool)
	ctx := context.Background()
	rq, err := svc.Request(ctx, hostID, ruleID, nil, requester, true)
	if err != nil {
		t.Fatalf("seed request: %v", err)
	}
	if _, err := svc.Approve(ctx, rq.ID, reviewer, "ok"); err != nil {
		t.Fatalf("approve request: %v", err)
	}
	return rq.ID
}

// remUserSeq guarantees unique usernames/emails across seedUniqueUser calls —
// shared seedUser builds its name from a UUIDv7 prefix that collides when two
// users are seeded in the same millisecond.
var remUserSeq atomic.Int64

func seedUniqueUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	n := remUserSeq.Add(1)
	uname := fmt.Sprintf("rem-user-%d-%s", n, id.String())
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, uname, uname+"@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// enqueueRemediationJob signs + enqueues an execute remediation job.
func enqueueRemediationJob(t *testing.T, pool *pgxpool.Pool, key []byte,
	requestID, hostID uuid.UUID, ruleID string) uuid.UUID {
	t.Helper()
	body := MarshalRemediationJob(key, RemediationPayload{
		RequestID: requestID,
		HostID:    hostID,
		RuleID:    ruleID,
		Action:    RemediationActionExecute,
	})
	ctx := correlation.Set(context.Background(), correlation.Generate("test"))
	id, err := queue.Enqueue(ctx, pool, RemediationJobType, body)
	if err != nil {
		t.Fatalf("enqueue remediation: %v", err)
	}
	return id
}

func requestStatus(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM remediation_requests WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("read request status: %v", err)
	}
	return s
}

func ruleStateStatus(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID string) (string, bool) {
	t.Helper()
	var s string
	err := pool.QueryRow(context.Background(),
		`SELECT current_status FROM host_rule_state WHERE host_id = $1 AND rule_id = $2`,
		hostID, ruleID).Scan(&s)
	if err != nil {
		return "", false
	}
	return s, true
}

func journalCount(t *testing.T, pool *pgxpool.Pool, requestID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM remediation_transactions WHERE request_id = $1`, requestID).Scan(&n); err != nil {
		t.Fatalf("count journal: %v", err)
	}
	return n
}

// fakeRemediate returns a RemediateFunc producing one transaction with the
// given status, and counts invocations.
func fakeRemediate(status string, calls *atomic.Int64) kensa.RemediateFunc {
	return func(ctx context.Context, hostID uuid.UUID, ruleID string) (*kensa.RemediationRunResult, kensa.FailureReason, error) {
		calls.Add(1)
		txnID, _ := uuid.NewV7()
		ev, _ := json.Marshal(map[string]string{"phase": status})
		return &kensa.RemediationRunResult{
			HostID:      hostID,
			RuleID:      ruleID,
			StartedAt:   time.Now().UTC(),
			CompletedAt: time.Now().UTC(),
			Transactions: []kensa.RemediationTxn{{
				TxnID:    txnID,
				Status:   status,
				Evidence: ev,
			}},
		}, "", nil
	}
}

func noopRollback() kensa.RollbackFunc {
	return func(ctx context.Context, hostID uuid.UUID, txnID uuid.UUID) (*kensa.RollbackRunResult, kensa.FailureReason, error) {
		return &kensa.RollbackRunResult{Status: "rolled_back"}, "", nil
	}
}

// recordingSvc wires a remediation.Service whose audit emit records into rec
// (so EmitExecuted / EmitRolledBack are observable). The named-type signatures
// match, so a thin adapter closure bridges worker.EmitFunc -> the service's.
func recordingSvc(pool *pgxpool.Pool, rec *emitRecorder) *remediation.Service {
	emit := rec.Emit()
	return remediation.NewService(pool, func(ctx context.Context, code audit.Code, ev audit.Event) {
		emit(ctx, code, ev)
	})
}

func remediationKey(t *testing.T) []byte {
	t.Helper()
	key, err := scheduler.DeriveQueueKey([]byte("test-dek-32-bytes-remediation-aa"))
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	return key
}

// @ac AC-07
// A committed execute drives approved -> executing -> executed, writes one
// journal row (phase_result=committed), and flips the rule to pass in
// host_rule_state so the compliance score moves.
func TestRemediationWorker_Execute_Committed_FlipsRuleToPass(t *testing.T) {
	t.Run("api-remediation/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		const ruleID = "sshd-permit-root-no"

		rec := &emitRecorder{}
		svc := recordingSvc(pool, rec)
		reqID := seedApprovedRequest(t, pool, svc, hostID, ruleID)

		var calls atomic.Int64
		exec := kensa.NewExecutor(stubBridge{plain: []byte("x")}, rec.executorEmit()).
			WithRemediateFunc(fakeRemediate("committed", &calls), noopRollback())
		writer := transactionlog.NewWriter(pool, rec.writerEmit())
		key := remediationKey(t)

		rw := NewRemediationWorker(RemediationConfig{
			Pool:     pool,
			Executor: exec,
			Service:  svc,
			Writer:   writer,
			QueueKey: key,
			Emit:     rec.Emit(),
		})

		jobID := enqueueRemediationJob(t, pool, key, reqID, hostID, ruleID)
		job, jobCtx, err := queue.Dequeue(context.Background(), pool)
		if err != nil {
			t.Fatalf("dequeue: %v", err)
		}
		rw.ProcessJob(jobCtx, job)

		if calls.Load() != 1 {
			t.Errorf("remediate calls = %d, want 1", calls.Load())
		}
		if st := requestStatus(t, pool, reqID); st != "executed" {
			t.Errorf("request status = %q, want executed", st)
		}
		if n := journalCount(t, pool, reqID); n != 1 {
			t.Errorf("journal rows = %d, want 1", n)
		}
		if st, ok := ruleStateStatus(t, pool, hostID, ruleID); !ok || st != "pass" {
			t.Errorf("host_rule_state = (%q, %v), want (pass, true)", st, ok)
		}
		if js := jobStatus(t, pool, jobID); js != queue.StatusCompleted {
			t.Errorf("job status = %q, want completed", js)
		}
		if rec.Count(audit.RemediationExecuted) != 1 {
			t.Errorf("remediation.executed audits = %d, want 1", rec.Count(audit.RemediationExecuted))
		}
	})
}

// @ac AC-07
// An errored transaction transitions the request to failed and writes NO flip
// (host_rule_state untouched for the rule).
func TestRemediationWorker_Execute_Errored_Failed_NoFlip(t *testing.T) {
	t.Run("api-remediation/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		const ruleID = "auditd-enabled"

		rec := &emitRecorder{}
		svc := recordingSvc(pool, rec)
		reqID := seedApprovedRequest(t, pool, svc, hostID, ruleID)

		var calls atomic.Int64
		exec := kensa.NewExecutor(stubBridge{plain: []byte("x")}, rec.executorEmit()).
			WithRemediateFunc(fakeRemediate("errored", &calls), noopRollback())
		writer := transactionlog.NewWriter(pool, rec.writerEmit())
		key := remediationKey(t)

		rw := NewRemediationWorker(RemediationConfig{
			Pool: pool, Executor: exec, Service: svc, Writer: writer,
			QueueKey: key, Emit: rec.Emit(),
		})

		enqueueRemediationJob(t, pool, key, reqID, hostID, ruleID)
		job, jobCtx, err := queue.Dequeue(context.Background(), pool)
		if err != nil {
			t.Fatalf("dequeue: %v", err)
		}
		rw.ProcessJob(jobCtx, job)

		if st := requestStatus(t, pool, reqID); st != "failed" {
			t.Errorf("request status = %q, want failed", st)
		}
		if _, ok := ruleStateStatus(t, pool, hostID, ruleID); ok {
			t.Errorf("host_rule_state row exists for rule; want none (no flip on errored)")
		}
	})
}

// @ac AC-07
// A job whose payload HMAC does not verify is dead-lettered (queue.Fail) with
// scheduler.job.hmac_rejected and the executor is never invoked.
func TestRemediationWorker_HMACMismatch_DeadLettered_NoExecutorCall(t *testing.T) {
	t.Run("api-remediation/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		const ruleID = "rule-z"

		rec := &emitRecorder{}
		svc := recordingSvc(pool, rec)
		reqID := seedApprovedRequest(t, pool, svc, hostID, ruleID)

		var calls atomic.Int64
		exec := kensa.NewExecutor(stubBridge{plain: []byte("x")}, rec.executorEmit()).
			WithRemediateFunc(fakeRemediate("committed", &calls), noopRollback())
		writer := transactionlog.NewWriter(pool, rec.writerEmit())
		goodKey := remediationKey(t)

		// Sign with a DIFFERENT key so the worker's verify fails.
		badKey, _ := scheduler.DeriveQueueKey([]byte("WRONG-dek-32-bytes-remediation-b"))
		body := MarshalRemediationJob(badKey, RemediationPayload{
			RequestID: reqID, HostID: hostID, RuleID: ruleID, Action: RemediationActionExecute,
		})
		ctx := correlation.Set(context.Background(), correlation.Generate("test"))
		jobID, err := queue.Enqueue(ctx, pool, RemediationJobType, body)
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}

		rw := NewRemediationWorker(RemediationConfig{
			Pool: pool, Executor: exec, Service: svc, Writer: writer,
			QueueKey: goodKey, Emit: rec.Emit(),
		})
		job, jobCtx, derr := queue.Dequeue(context.Background(), pool)
		if derr != nil {
			t.Fatalf("dequeue: %v", derr)
		}
		rw.ProcessJob(jobCtx, job)

		if calls.Load() != 0 {
			t.Errorf("remediate calls = %d, want 0 (HMAC rejected before executor)", calls.Load())
		}
		if js := jobStatus(t, pool, jobID); js != queue.StatusFailed {
			t.Errorf("job status = %q, want failed", js)
		}
		if st := requestStatus(t, pool, reqID); st != "approved" {
			t.Errorf("request status = %q, want approved (untouched)", st)
		}
		if rec.Count(audit.SchedulerJobHmacRejected) != 1 {
			t.Errorf("hmac_rejected audits = %d, want 1", rec.Count(audit.SchedulerJobHmacRejected))
		}
	})
}

// terminalDetail decodes the detail of the single event with the given code,
// failing if there is not exactly one.
func terminalDetail(t *testing.T, rec *emitRecorder, code audit.Code) (audit.Event, map[string]any) {
	t.Helper()
	evs := rec.Events(code)
	if len(evs) != 1 {
		t.Fatalf("%s events = %d, want exactly 1", code, len(evs))
	}
	var detail map[string]any
	if err := json.Unmarshal(evs[0].Detail, &detail); err != nil {
		t.Fatalf("%s detail is not JSON: %v", code, err)
	}
	return evs[0], detail
}

// runExecute drives one execute job through the real worker path with the
// Kensa executor stubbed to return the given transaction status, and returns
// the recorder. actor is placed in the signed payload; uuid.Nil means none.
func runExecute(t *testing.T, kensaStatus string, actor uuid.UUID) (*emitRecorder, uuid.UUID, *pgxpool.Pool) {
	t.Helper()
	pool := freshPool(t)
	user := seedUser(t, pool)
	hostID := seedHost(t, pool, user)
	const ruleID = "audit-sudo-log"

	rec := &emitRecorder{}
	svc := recordingSvc(pool, rec)
	reqID := seedApprovedRequest(t, pool, svc, hostID, ruleID)

	var calls atomic.Int64
	exec := kensa.NewExecutor(stubBridge{plain: []byte("x")}, rec.executorEmit()).
		WithRemediateFunc(fakeRemediate(kensaStatus, &calls), noopRollback())
	writer := transactionlog.NewWriter(pool, rec.writerEmit())
	key := remediationKey(t)
	rw := NewRemediationWorker(RemediationConfig{
		Pool: pool, Executor: exec, Service: svc, Writer: writer, QueueKey: key, Emit: rec.Emit(),
	})

	body := MarshalRemediationJob(key, RemediationPayload{
		RequestID: reqID, HostID: hostID, RuleID: ruleID,
		Action: RemediationActionExecute, ActorID: actor,
	})
	ctx := correlation.Set(context.Background(), correlation.Generate("test"))
	if _, err := queue.Enqueue(ctx, pool, RemediationJobType, body); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	job, jobCtx, err := queue.Dequeue(context.Background(), pool)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	rw.ProcessJob(jobCtx, job)
	if calls.Load() != 1 {
		t.Fatalf("remediate calls = %d, want 1", calls.Load())
	}
	return rec, reqID, pool
}

// @ac AC-16
// The terminal audit outcome mirrors the six-outcome status. On v0.8.0-rc.2
// a staged remediation on an immutable-audit host was audited as
// {"status":"staged","outcome":"failed"} because the emitter collapsed the
// outcome to a boolean (CP bugs/OW-042). C-09 says staged is never a failure.
func TestRemediationWorker_TerminalAuditOutcomeMirrorsStatus(t *testing.T) {
	t.Run("api-remediation/AC-16", func(t *testing.T) {
		actor := uuid.New()
		for _, tc := range []struct{ kensa, wantOutcome, wantStatus string }{
			{"staged", "staged", "staged"},
			{"committed", "executed", "executed"},
			{"errored", "failed", "failed"},
		} {
			t.Run(tc.kensa, func(t *testing.T) {
				rec, reqID, pool := runExecute(t, tc.kensa, actor)
				if st := requestStatus(t, pool, reqID); st != tc.wantStatus {
					t.Fatalf("request status = %q, want %q", st, tc.wantStatus)
				}
				_, detail := terminalDetail(t, rec, audit.RemediationExecuted)
				if detail["outcome"] != tc.wantOutcome {
					t.Errorf("remediation.executed outcome = %v, want %q (status %v)",
						detail["outcome"], tc.wantOutcome, detail["status"])
				}
				if detail["status"] != tc.wantStatus {
					t.Errorf("remediation.executed status = %v, want %q", detail["status"], tc.wantStatus)
				}
				if tc.kensa == "staged" && detail["outcome"] == "failed" {
					t.Error("a staged transaction was audited as failed")
				}
			})
		}

		// A clean rollback of a staged change: one rolled_back event, outcome
		// rolled_back. The rollback job resolves the transaction from the
		// journal the execute wrote.
		t.Run("rollback", func(t *testing.T) {
			rec, reqID, pool := runExecute(t, "staged", actor)
			hostID, ruleID := requestHostAndRule(t, pool, reqID)
			svc := recordingSvc(pool, rec)
			exec := kensa.NewExecutor(stubBridge{plain: []byte("x")}, rec.executorEmit()).
				WithRemediateFunc(fakeRemediate("staged", new(atomic.Int64)), noopRollback())
			key := remediationKey(t)
			rw := NewRemediationWorker(RemediationConfig{
				Pool: pool, Executor: exec, Service: svc,
				Writer: transactionlog.NewWriter(pool, rec.writerEmit()), QueueKey: key, Emit: rec.Emit(),
			})
			body := MarshalRemediationJob(key, RemediationPayload{
				RequestID: reqID, HostID: hostID, RuleID: ruleID,
				Action: RemediationActionRollback, ActorID: actor,
			})
			ctx := correlation.Set(context.Background(), correlation.Generate("test"))
			if _, err := queue.Enqueue(ctx, pool, RemediationJobType, body); err != nil {
				t.Fatalf("enqueue rollback: %v", err)
			}
			job, jobCtx, err := queue.Dequeue(context.Background(), pool)
			if err != nil {
				t.Fatalf("dequeue rollback: %v", err)
			}
			rw.ProcessJob(jobCtx, job)
			if st := requestStatus(t, pool, reqID); st != "rolled_back" {
				t.Fatalf("request status after rollback = %q, want rolled_back", st)
			}
			_, detail := terminalDetail(t, rec, audit.RemediationRolledBack)
			if detail["outcome"] != "rolled_back" {
				t.Errorf("remediation.rolled_back outcome = %v, want rolled_back", detail["outcome"])
			}
		})
	})
}

// @ac AC-17
// User-initiated terminal events retain the initiating actor; system work
// is not attributed to a user. Both terminal events on v0.8.0-rc.2 carried
// the nil UUID as a "user" actor (CP bugs/OW-042).
func TestRemediationWorker_TerminalAuditRetainsInitiatingActor(t *testing.T) {
	t.Run("api-remediation/AC-17", func(t *testing.T) {
		actor := uuid.New()
		for _, kensaStatus := range []string{"committed", "staged", "errored"} {
			t.Run("user/"+kensaStatus, func(t *testing.T) {
				rec, _, _ := runExecute(t, kensaStatus, actor)
				ev, _ := terminalDetail(t, rec, audit.RemediationExecuted)
				if ev.ActorType != "user" || ev.ActorID != actor.String() {
					t.Errorf("terminal actor = (%q, %q), want (user, %s)", ev.ActorType, ev.ActorID, actor)
				}
			})
		}
		t.Run("system/no actor in payload", func(t *testing.T) {
			rec, _, _ := runExecute(t, "committed", uuid.Nil)
			ev, _ := terminalDetail(t, rec, audit.RemediationExecuted)
			if ev.ActorType != "system" {
				t.Errorf("actor type = %q, want system for work no user initiated", ev.ActorType)
			}
			if ev.ActorID != "" {
				t.Errorf("actor id = %q, want empty; an actor must not be invented", ev.ActorID)
			}
			if ev.ActorID == uuid.Nil.String() {
				t.Error("the nil UUID was recorded as an actor")
			}
		})
	})
}

// requestHostAndRule reads a request's host and rule for a follow-on job.
func requestHostAndRule(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	var hostID uuid.UUID
	var ruleID string
	if err := pool.QueryRow(context.Background(),
		`SELECT host_id, rule_id FROM remediation_requests WHERE id = $1`, id).Scan(&hostID, &ruleID); err != nil {
		t.Fatalf("request lookup: %v", err)
	}
	return hostID, ruleID
}
