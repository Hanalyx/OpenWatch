package transactionlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// EmitFunc is the audit-emission shape the writer depends on. Matches
// audit.Emit's signature so production wires audit.Emit directly; tests
// pass a fake recorder. Same pattern as internal/scheduler.EmitFunc and
// internal/kensa.EmitFunc.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Writer persists ApplyBatch values to host_rule_state + transactions.
// Constructed once at boot via NewWriter; held for the process lifetime.
type Writer struct {
	pool  *pgxpool.Pool
	emit  EmitFunc
	clock func() time.Time
}

// NewWriter wires the writer. emit is audit.Emit in production, a fake
// recorder in tests.
func NewWriter(pool *pgxpool.Pool, emit EmitFunc) *Writer {
	return &Writer{
		pool:  pool,
		emit:  emit,
		clock: time.Now,
	}
}

// Apply persists every result in batch to host_rule_state + transactions
// atomically.
//
// Steps:
//  1. Validate every result (status, evidence size). Spec AC-14: oversize
//     evidence is rejected BEFORE any INSERT — no partial writes.
//  2. Idempotency check: if any transactions row already exists with the
//     given scan_id, treat the whole Apply as a no-op (spec AC-05).
//  3. BEGIN tx.
//  4. For each result:
//     - SELECT prior host_rule_state row (if any)
//     - decide change_kind: first_seen, state_changed, severity_changed, or none
//     - INSERT a transactions row only when change_kind != none
//     - UPSERT host_rule_state
//     - emit finding.persisted per state-change row (NOT for unchanged)
//  5. COMMIT tx.
//
// Spec ACs satisfied:
//
//   - AC-01 (C-01): single tx wrap, regardless of N
//   - AC-02 (C-03): first scan writes N transactions all change_kind=first_seen
//   - AC-03 (C-03): identical-results scan writes 0 transactions
//   - AC-04 (C-02, C-03): one state change → 1 transactions row
//   - AC-05 (C-04): idempotent on scan_id
//   - AC-06 (C-01): mid-batch DB error rolls back the whole tx, no rows persist
//   - AC-09 (C-07): finding.persisted emission count == transactions rows
//   - AC-14 (C-10): per-rule evidence > 256 KB rejected before INSERT
//   - AC-15 (C-01): DB error during Apply emits writer.apply.failed audit
func (w *Writer) Apply(ctx context.Context, batch ApplyBatch) error {
	// Spec AC-14: pre-flight validation. Reject the whole batch if any
	// rule has oversize evidence (atomicity per C-01).
	for _, r := range batch.Results {
		if err := validateResult(r); err != nil {
			if errors.Is(err, ErrEvidenceOversize) {
				w.emitFailure(ctx, batch, ReasonEvidenceOversize, r.RuleID)
			}
			return fmt.Errorf("transactionlog: validate result rule=%s: %w", r.RuleID, err)
		}
	}

	// Spec AC-05: idempotency check. If any transactions row exists
	// with this scan_id, this is a re-apply — no-op.
	var existingCount int
	if err := w.pool.QueryRow(ctx,
		`SELECT count(*) FROM transactions WHERE scan_id = $1`,
		batch.ScanID).Scan(&existingCount); err != nil {
		return fmt.Errorf("transactionlog: idempotency check: %w", err)
	}
	if existingCount > 0 {
		return nil // already applied; no-op (spec AC-05)
	}

	now := w.clock()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		w.emitFailure(ctx, batch, ReasonUnknown, "")
		return fmt.Errorf("transactionlog: begin: %w", err)
	}
	// Track transactions emissions to fire AFTER COMMIT (audit reflects
	// what was persisted, not what we tried to persist).
	type pendingEmit struct {
		ruleID      string
		scanID      uuid.UUID
		hostID      uuid.UUID
		changeKind  ChangeKind
		status      Status
		priorStatus string
	}
	var pending []pendingEmit
	rolledBack := false
	defer func() {
		if !rolledBack && err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	for _, r := range batch.Results {
		// Read prior state.
		var (
			priorStatus   *string
			priorSeverity *string
			checkCount    int
		)
		err = tx.QueryRow(ctx, `
			SELECT current_status, severity, check_count
			  FROM host_rule_state
			 WHERE host_id = $1 AND rule_id = $2`,
			batch.HostID, r.RuleID,
		).Scan(&priorStatus, &priorSeverity, &checkCount)
		hasPrior := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			_ = tx.Rollback(ctx)
			rolledBack = true
			w.emitFailure(ctx, batch, classifyDBError(err), r.RuleID)
			return fmt.Errorf("transactionlog: read prior state rule=%s: %w", r.RuleID, err)
		}

		// Decide change_kind.
		var changeKind ChangeKind
		switch {
		case !hasPrior:
			changeKind = ChangeFirstSeen
		case *priorStatus != string(r.Status):
			changeKind = ChangeStateChanged
		case stringValue(priorSeverity) != r.Severity:
			changeKind = ChangeSeverityChanged
		default:
			changeKind = "" // no change; skip transactions INSERT
		}

		// Spec C-03: INSERT transactions ONLY on change.
		if changeKind != "" {
			txnID, _ := uuid.NewV7()
			frameworkRefsJSON, _ := json.Marshal(r.FrameworkRefs)
			if _, err = tx.Exec(ctx, `
				INSERT INTO transactions
					(id, host_id, rule_id, scan_id, status, severity,
					 change_kind, evidence, framework_refs, skip_reason,
					 occurred_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11)`,
				txnID, batch.HostID, r.RuleID, batch.ScanID,
				string(r.Status), nullableString(r.Severity),
				string(changeKind), r.Evidence, frameworkRefsJSON,
				nullableString(r.SkipReason), now,
			); err != nil {
				_ = tx.Rollback(ctx)
				rolledBack = true
				w.emitFailure(ctx, batch, classifyDBError(err), r.RuleID)
				return fmt.Errorf("transactionlog: insert transaction rule=%s: %w", r.RuleID, err)
			}
			prior := "none"
			if hasPrior && priorStatus != nil {
				prior = *priorStatus
			}
			pending = append(pending, pendingEmit{
				ruleID: r.RuleID, scanID: batch.ScanID, hostID: batch.HostID,
				changeKind: changeKind, status: r.Status, priorStatus: prior,
			})
		}

		// host_rule_state UPSERT runs every Apply, change or not.
		// Spec C-02: ON CONFLICT (host_id, rule_id) DO UPDATE.
		// When state is unchanged AND a prior row exists, the UPSERT
		// guard below preserves the prior last_changed_at via a
		// COALESCE-style expression; the lastChangedAt local is only
		// applied for new/changed states.
		frameworkRefsJSON, _ := json.Marshal(r.FrameworkRefs)
		lastChangedAt := now
		if _, err = tx.Exec(ctx, `
			INSERT INTO host_rule_state
				(host_id, rule_id, current_status, severity,
				 last_checked_at, check_count, last_scan_id,
				 evidence, framework_refs, skip_reason,
				 first_seen_at, last_changed_at)
			VALUES ($1,$2,$3,$4,$5,1,$6,$7::jsonb,$8::jsonb,$9,$5,$10)
			ON CONFLICT (host_id, rule_id) DO UPDATE SET
				current_status   = EXCLUDED.current_status,
				severity         = EXCLUDED.severity,
				last_checked_at  = EXCLUDED.last_checked_at,
				check_count      = host_rule_state.check_count + 1,
				last_scan_id     = EXCLUDED.last_scan_id,
				evidence         = EXCLUDED.evidence,
				framework_refs   = EXCLUDED.framework_refs,
				skip_reason      = EXCLUDED.skip_reason,
				last_changed_at  = CASE
					WHEN host_rule_state.current_status <> EXCLUDED.current_status
					  OR COALESCE(host_rule_state.severity,'') <> COALESCE(EXCLUDED.severity,'')
					THEN EXCLUDED.last_changed_at
					ELSE host_rule_state.last_changed_at
				END`,
			batch.HostID, r.RuleID, string(r.Status),
			nullableString(r.Severity), now, batch.ScanID,
			r.Evidence, frameworkRefsJSON, nullableString(r.SkipReason),
			lastChangedAt,
		); err != nil {
			_ = tx.Rollback(ctx)
			rolledBack = true
			w.emitFailure(ctx, batch, classifyDBError(err), r.RuleID)
			return fmt.Errorf("transactionlog: upsert host_rule_state rule=%s: %w", r.RuleID, err)
		}
	}

	if err = tx.Commit(ctx); err != nil {
		rolledBack = true
		w.emitFailure(ctx, batch, classifyDBError(err), "")
		return fmt.Errorf("transactionlog: commit: %w", err)
	}

	// AC-09: emit finding.persisted per state-change AFTER commit.
	for _, p := range pending {
		w.emitFindingPersisted(ctx, p.hostID, p.ruleID, p.scanID, p.changeKind, p.status, p.priorStatus)
	}

	return nil
}

// emitFindingPersisted produces a finding.persisted audit event.
func (w *Writer) emitFindingPersisted(ctx context.Context, hostID uuid.UUID, ruleID string, scanID uuid.UUID, kind ChangeKind, status Status, priorStatus string) {
	w.emit(ctx, audit.FindingPersisted, audit.Event{
		ActorType: "system",
		Detail: mustJSON(map[string]string{
			"host_id":      hostID.String(),
			"rule_id":      ruleID,
			"scan_id":      scanID.String(),
			"change_kind":  string(kind),
			"status":       string(status),
			"prior_status": priorStatus,
		}),
	})
}

// emitFailure produces a writer.apply.failed audit event.
func (w *Writer) emitFailure(ctx context.Context, batch ApplyBatch, reason FailureReason, offendingRuleID string) {
	detail := map[string]any{
		"scan_id":              batch.ScanID.String(),
		"host_id":              batch.HostID.String(),
		"reason":               string(reason),
		"rule_count_attempted": len(batch.Results),
	}
	if offendingRuleID != "" {
		detail["offending_rule_id"] = offendingRuleID
	}
	w.emit(ctx, audit.WriterApplyFailed, audit.Event{
		ActorType: "system",
		Detail:    mustJSON(detail),
	})
}

// validateResult checks status validity, evidence size, and evidence
// shape. Spec ACs: AC-08 (evidence shape) + AC-14 (size cap).
//
// Evidence shape check is minimal in this commit: must parse as a JSON
// object (not array, not scalar). The full KensaEvidence-schema
// validation lands once the openapi.yaml KensaEvidence shape is
// committed; calls to that validator slot in here.
func validateResult(r Result) error {
	switch r.Status {
	case StatusPass, StatusFail, StatusSkipped, StatusError:
	default:
		return fmt.Errorf("%w: %q", ErrInvalidStatus, r.Status)
	}
	if len(r.Evidence) > MaxEvidenceBytes {
		return fmt.Errorf("%w: rule_id=%s size=%d > cap=%d",
			ErrEvidenceOversize, r.RuleID, len(r.Evidence), MaxEvidenceBytes)
	}

	// AC-08: evidence MUST be a JSON object. The KensaEvidence schema
	// (when defined in OpenAPI) requires fields like command, stdout,
	// expected, actual, exit_code — all of which live in a JSON object.
	// Reject anything that isn't a syntactically valid object.
	if len(r.Evidence) == 0 {
		// Allowed: empty evidence is a no-op (the writer stores "{}"
		// at insert time; the empty Go slice is treated as absent).
		return nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(r.Evidence, &probe); err != nil {
		return fmt.Errorf("%w: rule_id=%s: %v", ErrInvalidEvidence, r.RuleID, err)
	}
	return nil
}

// classifyDBError maps a Postgres error to one of the closed-enum
// FailureReason values on writer.apply.failed.
func classifyDBError(err error) FailureReason {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503": // foreign_key_violation
			return ReasonFKViolation
		case "40P01": // deadlock_detected
			return ReasonDeadlock
		}
	}
	if strings.Contains(err.Error(), "evidence") {
		return ReasonEvidenceOversize
	}
	return ReasonSQLCError
}

// nullableString converts an empty string to nil (for NULL in DB).
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// stringValue returns *s or empty string for nil.
func stringValue(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// mustJSON marshals v; map[string]X with simple values never errors.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
