// Remediation execution lifecycle (Phase 7, Tier A free-core). These methods
// drive the approved -> executing -> executed | failed transitions and the
// executed -> rolled_back transition, and write the remediation_transactions
// journal. They are called ONLY by the remediation worker after Kensa has
// applied (or rolled back) the rule on the host — this package still NEVER
// contacts a host itself; the worker owns the *kensa.Executor.
//
// Spec: api-remediation v1.2.0.
package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

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

// MarkRolledBack transitions a rollback-eligible request to 'rolled_back'.
// Eligible means 'executed' OR 'staged' (Status.RollbackEligible): a staged
// change is a real host mutation with captured pre-state, so it must be
// reversible. Returns ErrWrongState otherwise.
func (s *Service) MarkRolledBack(ctx context.Context, id uuid.UUID) (Request, error) {
	return s.transitionFrom(ctx, id, Status.RollbackEligible, StatusRolledBack)
}

// RevertToApproved transitions an 'executing' request back to 'approved'. The
// remediation worker calls this when it has marked a request executing but the
// host turned out to be busy (lost a race for the per-host guard): the request
// returns to approved so the requeued job can run it once the host frees up.
func (s *Service) RevertToApproved(ctx context.Context, id uuid.UUID) (Request, error) {
	return s.transition(ctx, id, StatusExecuting, StatusApproved)
}

// HostHasExecuting reports whether the host already has a remediation request
// in the 'executing' state. The worker uses this to serialize per-host
// remediation: only one rule is applied on a host at a time (they share one
// SSH session via the executor's per-host guard), so a second concurrent
// request backs off and requeues instead of colliding.
func (s *Service) HostHasExecuting(ctx context.Context, hostID uuid.UUID) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM remediation_requests
			 WHERE host_id = $1 AND status = 'executing'
		)`, hostID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("remediation: host-executing check: %w", err)
	}
	return exists, nil
}

// transition performs a guarded fromState -> toState update under FOR UPDATE.
// Unlike review() it does not touch reviewed_by/reviewed_at — execution
// transitions are system-driven, not a human review.
func (s *Service) transition(ctx context.Context, id uuid.UUID, fromState, toState Status) (Request, error) {
	return s.transitionFrom(ctx, id, func(cur Status) bool { return cur == fromState }, toState)
}

// transitionFrom is transition() over a SET of acceptable source states,
// expressed as a predicate. Rollback needs it because two different statuses
// are rollback-eligible ('executed' and 'staged'), and hard-coding a single
// source state is what made a staged host change unreversible.
func (s *Service) transitionFrom(ctx context.Context, id uuid.UUID, eligible func(Status) bool, toState Status) (Request, error) {
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
	if !eligible(Status(status)) {
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
	final, failReason := rollUpOutcome(ctx, txns)

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
			phase := phaseResult(t)
			ev := t.Evidence
			if len(ev) == 0 {
				ev = []byte("{}")
			}
			steps := t.Steps
			if len(steps) == 0 {
				steps = []byte("[]")
			}
			pre := t.PreState
			if len(pre) == 0 {
				pre = []byte("[]")
			}
			txnID := uuid.Must(uuid.NewV7())
			if _, err := tx.Exec(ctx, `
				INSERT INTO remediation_transactions
					(id, request_id, ordinal, rule_id, kensa_txn_id,
					 mechanism, phase_result, evidence, steps, pre_state,
					 kensa_version, dry_run, applied_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,false,now())`,
				txnID, id, i, ruleID, t.TxnID.String(), nullIfEmpty(t.Mechanism),
				phase, ev, steps, pre, nullIfEmpty(t.KensaVersion)); err != nil {
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

// FirstReversibleTxn returns the first REVERSIBLE transaction id for a request,
// or false when none exists. The worker uses it to find the rollback handle.
//
// 'staged' counts as reversible alongside 'committed' (api-remediation AC-09).
// A staged transaction wrote a real change to the host and Kensa captured its
// pre-state, so `kensa rollback` reverses it byte-perfect. Matching only
// 'committed' here was half of why a staged change could not be undone through
// the UI; the other half was the executed-only precondition in the worker.
func (s *Service) FirstReversibleTxn(ctx context.Context, id uuid.UUID) (uuid.UUID, bool, error) {
	var raw string
	err := s.pool.QueryRow(ctx, `
		SELECT kensa_txn_id FROM remediation_transactions
		 WHERE request_id = $1
		   AND phase_result IN ('committed', 'staged')
		   AND kensa_txn_id IS NOT NULL
		 ORDER BY ordinal ASC, created_at ASC LIMIT 1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("remediation: first reversible txn: %w", err)
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

// rollUpOutcome reduces a request's transactions to one terminal status plus an
// operator-facing reason.
//
// Cardinality note: Kensa's Remediate runs a transaction per FAILING rule and
// OpenWatch passes exactly one rule, so this is 1 transaction in practice today
// and the roll-up is lossless. The mixed case is defined anyway rather than left
// emergent, because bulk remediation (Enterprise) will exercise it: when
// transactions disagree the honest answer is partially_applied, "go look at this
// host", not an arbitrary precedence winner.
//
// api-remediation AC-09, AC-10, AC-11.
func rollUpOutcome(ctx context.Context, txns []ExecTxn) (Status, string) {
	if len(txns) == 0 {
		// No journal at all, e.g. the host was unreachable so nothing ran.
		// Nothing was attempted, so the old message is accurate here.
		return StatusFailed, "Remediation did not complete. No host change was committed."
	}

	seen := make(map[Status]bool, len(txns))
	reason := ""
	// Already-compliant needs its own sentence. It maps to not_applied, which
	// otherwise reads as "the engine declined" -- true but unhelpful when the
	// actual news is that the host already satisfied the rule. Without this an
	// operator sees "Not applied" and cannot tell whether something went wrong.
	allAlreadyCompliant := true
	for _, t := range txns {
		if !t.AlreadyCompliant {
			allAlreadyCompliant = false
		}
	}
	for _, t := range txns {
		st, known := OutcomeOf(t)
		if !known {
			// AC-11: never absorb an unknown terminal state silently. This is
			// the guard that Kensa v0.8.0's `staged` defeated.
			slog.WarnContext(ctx, "remediation: unrecognised kensa transaction status; failing closed",
				slog.String("kensa_status", t.Status),
				slog.String("txn_id", t.TxnID.String()),
				slog.String("action", "add the status to remediation.OutcomeOf and the phase_result CHECK"))
		}
		seen[st] = true
		if reason == "" && t.Err != "" {
			reason = t.Err
		}
	}

	final := StatusFailed
	switch {
	case len(seen) == 1:
		for st := range seen {
			final = st
		}
	case seen[StatusFailed] || seen[StatusPartiallyApplied]:
		// Something broke or stranded amid other work: host state is unknown.
		final = StatusPartiallyApplied
	default:
		// Several non-failing outcomes disagree (e.g. one committed, one
		// staged). The host is partly converged and partly pending a reboot.
		final = StatusPartiallyApplied
	}

	if reason == "" {
		if final == StatusNotApplied && allAlreadyCompliant {
			reason = "The host already satisfied this rule. Nothing was changed, " +
				"so there is nothing to roll back."
		} else {
			reason = outcomeReason(final)
		}
	}
	return final, reason
}

// outcomeReason is the operator-facing sentence for a terminal status when the
// engine gave no error string of its own. Each one names the host's actual
// state, because the single worst thing the old code did was tell an operator
// nothing had changed on a host that had just been modified.
func outcomeReason(s Status) string {
	switch s {
	case StatusExecuted:
		return "Fix applied and validated on the host."
	case StatusStaged:
		return "Change written and staged. It takes effect after the host reboots; a re-scan reports this rule as still failing until then. You can roll it back."
	case StatusReverted:
		return "Validation failed, so the host was restored to its previous state. Nothing was left changed."
	case StatusNotApplied:
		return "No change made. The engine declined to apply this rule."
	case StatusPartiallyApplied:
		return "Remediation did not complete cleanly and some steps cannot be reversed automatically. Inspect this host."
	default:
		return "Remediation did not complete. No host change was committed."
	}
}

// phaseResult maps a kensa transaction to the remediation_transactions
// phase_result enum, widened by migration 0054 so the journal records the true
// outcome. It no longer collapses everything unknown into 'skipped'; 'skipped'
// is retained only for historical rows written before 0054.
func phaseResult(t ExecTxn) string {
	st, _ := OutcomeOf(t)
	switch st {
	case StatusExecuted:
		return "committed"
	case StatusStaged:
		return "staged"
	case StatusReverted:
		return "reverted"
	case StatusNotApplied:
		return "not_applied"
	case StatusPartiallyApplied:
		return "partially_applied"
	default:
		return "skipped"
	}
}

// nullIfEmpty keeps mechanism NULL rather than an empty string when a
// transaction produced no steps, so "we did not record it" stays
// distinguishable from "it had no mechanism".
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
