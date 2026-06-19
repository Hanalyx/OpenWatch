// Remediation execution lifecycle (Phase 7, Tier A free-core). These methods
// drive the approved -> executing -> executed | failed transitions and the
// executed -> rolled_back transition, and write the remediation_transactions
// journal. They are called ONLY by the remediation worker after Kensa has
// applied (or rolled back) the rule on the host — this package still NEVER
// contacts a host itself; the worker owns the *kensa.Executor.
//
// Spec: api-remediation v1.1.0.
package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MarkExecuting transitions an 'approved' request to 'executing' under a row
// lock, so a duplicate enqueue (or a concurrent worker) cannot double-execute.
// Returns ErrWrongState when the request is not 'approved', ErrNotFound when
// the id is unknown.
func (s *Service) MarkExecuting(ctx context.Context, id uuid.UUID) (Request, error) {
	return s.transition(ctx, id, StatusApproved, StatusExecuting)
}

// MarkRolledBack transitions an 'executed' request to 'rolled_back'. Returns
// ErrWrongState when the request is not 'executed'.
func (s *Service) MarkRolledBack(ctx context.Context, id uuid.UUID) (Request, error) {
	return s.transition(ctx, id, StatusExecuted, StatusRolledBack)
}

// transition performs a guarded fromState -> toState update under FOR UPDATE.
// Unlike review() it does not touch reviewed_by/reviewed_at — execution
// transitions are system-driven, not a human review.
func (s *Service) transition(ctx context.Context, id uuid.UUID, fromState, toState Status) (Request, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, fmt.Errorf("remediation: transition begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	err = tx.QueryRow(ctx, `
		SELECT status FROM remediation_requests
		 WHERE id = $1 FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	if err != nil {
		return Request{}, fmt.Errorf("remediation: transition lock: %w", err)
	}
	if Status(status) != fromState {
		return Request{}, ErrWrongState
	}

	row := tx.QueryRow(ctx, `
		UPDATE remediation_requests
		   SET status = $2, updated_at = now()
		 WHERE id = $1
		RETURNING `+selectCols, id, string(toState))
	rq, err := scanRequest(row)
	if err != nil {
		return Request{}, fmt.Errorf("remediation: transition update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Request{}, fmt.Errorf("remediation: transition commit: %w", err)
	}
	return rq, nil
}

// RecordExecution writes the per-transaction journal rows for an executing
// request and transitions it to its final state ('executed' when at least one
// transaction committed and none errored, 'failed' otherwise), atomically.
// The request MUST be in 'executing' (set via MarkExecuting) — RecordExecution
// is idempotent on the journal: if rows already exist for this request it
// re-reads the current row rather than double-writing.
//
// finalStatus is computed from the transactions; the caller does not pass it.
// Returns the updated Request.
func (s *Service) RecordExecution(ctx context.Context, id uuid.UUID, ruleID string, txns []ExecTxn) (Request, error) {
	final := StatusFailed
	anyCommitted := false
	anyErrored := false
	failReason := ""
	for _, t := range txns {
		if t.Committed() {
			anyCommitted = true
		}
		if t.Status == "errored" || t.Err != "" {
			anyErrored = true
			if failReason == "" && t.Err != "" {
				failReason = t.Err
			}
		}
	}
	if anyCommitted && !anyErrored {
		final = StatusExecuted
	}
	// A failed execute with no per-transaction error (e.g. the host was
	// unreachable, so the journal is empty) still gets a usable reason.
	if final == StatusFailed && failReason == "" {
		failReason = "Remediation did not complete. No host change was committed."
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, fmt.Errorf("remediation: record begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Guard: the row must be 'executing'. Lock it so the final transition is
	// race-free against a concurrent rollback/duplicate.
	var status string
	err = tx.QueryRow(ctx, `
		SELECT status FROM remediation_requests
		 WHERE id = $1 FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	if err != nil {
		return Request{}, fmt.Errorf("remediation: record lock: %w", err)
	}
	if Status(status) != StatusExecuting {
		return Request{}, ErrWrongState
	}

	// Idempotency: a re-delivered job must not double-write the journal.
	var existing int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM remediation_transactions WHERE request_id = $1`,
		id).Scan(&existing); err != nil {
		return Request{}, fmt.Errorf("remediation: record idempotency: %w", err)
	}

	if existing == 0 {
		for i, t := range txns {
			phase := phaseResult(t.Status)
			ev := t.Evidence
			if len(ev) == 0 {
				ev = []byte("{}")
			}
			txnID := uuid.Must(uuid.NewV7())
			if _, err := tx.Exec(ctx, `
				INSERT INTO remediation_transactions
					(id, request_id, ordinal, rule_id, kensa_txn_id,
					 phase_result, evidence, dry_run, applied_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,false,now())`,
				txnID, id, i, ruleID, t.TxnID.String(), phase, ev); err != nil {
				return Request{}, fmt.Errorf("remediation: insert journal: %w", err)
			}
		}
	}

	// On failure, surface the reason in review_note so the UI shows it
	// ("Failed (reason)"); on success leave the approver's note intact.
	row := tx.QueryRow(ctx, `
		UPDATE remediation_requests
		   SET status = $2,
		       review_note = CASE WHEN $3 <> '' THEN $3 ELSE review_note END,
		       updated_at = now()
		 WHERE id = $1
		RETURNING `+selectCols, id, string(final), failReason)
	rq, err := scanRequest(row)
	if err != nil {
		return Request{}, fmt.Errorf("remediation: record final update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Request{}, fmt.Errorf("remediation: record commit: %w", err)
	}
	return rq, nil
}

// FirstCommittedTxn returns the first committed transaction id for a request,
// or false when none committed. The worker uses it to find the rollback
// handle when a rollback is requested.
func (s *Service) FirstCommittedTxn(ctx context.Context, id uuid.UUID) (uuid.UUID, bool, error) {
	var raw string
	err := s.pool.QueryRow(ctx, `
		SELECT kensa_txn_id FROM remediation_transactions
		 WHERE request_id = $1 AND phase_result = 'committed' AND kensa_txn_id IS NOT NULL
		 ORDER BY ordinal ASC, created_at ASC LIMIT 1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("remediation: first committed txn: %w", err)
	}
	txnID, perr := uuid.Parse(raw)
	if perr != nil {
		return uuid.Nil, false, nil
	}
	return txnID, true, nil
}

// EmitExecuted records the remediation.executed audit event. The worker calls
// this (rather than the service emitting internally) so the actor — the user
// who invoked :execute — is carried through from the HTTP request.
func (s *Service) EmitExecuted(ctx context.Context, rq Request, actor uuid.UUID, committed bool) {
	if s.emit == nil {
		return
	}
	outcome := "failed"
	if committed {
		outcome = "executed"
	}
	detail, _ := json.Marshal(map[string]any{
		"request_id": rq.ID.String(),
		"host_id":    rq.HostID.String(),
		"rule_id":    rq.RuleID,
		"outcome":    outcome,
		"status":     string(rq.Status),
	})
	s.emitAudit(ctx, auditRemediationExecuted, rq, actor, detail)
}

// EmitRolledBack records the remediation.rolled_back audit event.
func (s *Service) EmitRolledBack(ctx context.Context, rq Request, actor uuid.UUID, status string) {
	if s.emit == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"request_id": rq.ID.String(),
		"host_id":    rq.HostID.String(),
		"rule_id":    rq.RuleID,
		"outcome":    status,
		"status":     string(rq.Status),
	})
	s.emitAudit(ctx, auditRemediationRolledBack, rq, actor, detail)
}

// phaseResult maps a kensa transaction status to the remediation_transactions
// phase_result CHECK enum (committed | rolled_back | skipped). Anything that is
// not a clean commit or rollback is recorded as 'skipped' (the journal's catch
// -all for partially_applied / errored), with the raw status preserved in the
// evidence envelope.
func phaseResult(status string) string {
	switch status {
	case "committed":
		return "committed"
	case "rolled_back":
		return "rolled_back"
	default:
		return "skipped"
	}
}
