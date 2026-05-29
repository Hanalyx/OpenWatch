package drift

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// EmitFunc mirrors audit.Emit. Same pattern as B.1a / B.1b / B.1c /
// B.2a.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Service computes drift for a given (scanID, hostID) pair against the
// transaction log. Construct once at boot via NewService.
type Service struct {
	pool       *pgxpool.Pool
	emit       EmitFunc
	thresholds Thresholds
}

// NewService wires the detector. emit is audit.Emit in production,
// a fake recorder in tests. thresholds defaults to DefaultThresholds
// when unset (any value 0); production wires from policy.AlertThresholds.
func NewService(pool *pgxpool.Pool, emit EmitFunc, thresholds Thresholds) *Service {
	if thresholds.MajorWorseningPP == 0 && thresholds.MinorWorseningPP == 0 && thresholds.ImprovementPP == 0 {
		thresholds = DefaultThresholds()
	}
	return &Service{pool: pool, emit: emit, thresholds: thresholds}
}

// Thresholds returns the active thresholds — useful for tests and
// observability.
func (s *Service) Thresholds() Thresholds { return s.thresholds }

// DetectForScan computes drift for hostID against scanID's transactions.
//
// Prior score: pulled from host_rule_state EXCLUDING rules whose
// last_scan_id == this scanID. This way, the "prior" view is the state
// before this scan landed (writer.Apply already moved host_rule_state
// to the new state, so we have to reconstruct).
//
// Current score: full host_rule_state for this host (post-Apply).
//
// Per-severity transition counts: read from the transactions table
// filtered to this scanID + state_changed change_kind.
//
// Spec ACs satisfied:
//
//   - AC-08 (C-01, C-06): no prior data → DriftStable with
//     HasPriorBaseline=false. The first-ever scan against a host
//     cannot drift.
//   - AC-09 (C-08): per-severity transition counts populated from
//     transactions.
//   - AC-10/11 (C-04): emission gates on Kind != DriftStable.
func (s *Service) DetectForScan(ctx context.Context, hostID, scanID uuid.UUID) (Report, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return Report{}, fmt.Errorf("drift: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Current score from host_rule_state (post-Apply).
	currentPassed, currentFailed, totalRows, err := s.readCurrentCounts(ctx, tx, hostID)
	if err != nil {
		return Report{}, err
	}
	currentScore := ComplianceScore(currentPassed, currentFailed)

	// Prior score: the state BEFORE this scanID landed. We reconstruct
	// it by inverting this scan's transactions. A transaction with
	// change_kind='first_seen' means the row had no prior; for
	// 'state_changed' / 'severity_changed' the prior is the previous
	// state in the transactions table.
	priorPassed, priorFailed, hadPrior, err := s.reconstructPriorCounts(ctx, tx, hostID, scanID, currentPassed, currentFailed)
	if err != nil {
		return Report{}, err
	}

	// Per-severity transitions from the transactions table.
	transitions, err := s.readSeverityTransitions(ctx, tx, hostID, scanID)
	if err != nil {
		return Report{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Report{}, fmt.Errorf("drift: commit: %w", err)
	}

	report := Report{
		HostID:           hostID,
		ScanID:           scanID,
		CurrentScore:     currentScore,
		HasPriorBaseline: hadPrior,
	}
	report.fillTransitions(transitions)

	// First-ever scan: no baseline to drift from.
	if !hadPrior || totalRows == 0 {
		report.Kind = DriftStable
		return report, nil
	}

	priorScore := ComplianceScore(priorPassed, priorFailed)
	report.PriorScore = priorScore
	report.ScoreDelta = currentScore - priorScore
	report.Kind = Classify(priorScore, currentScore, s.thresholds)

	// Emit on non-stable kinds (spec C-04).
	if report.Kind != DriftStable {
		s.emitDriftDetected(ctx, report)
	}

	return report, nil
}

// readCurrentCounts returns the passed / failed / total counts from
// host_rule_state (current state post-Apply).
func (s *Service) readCurrentCounts(ctx context.Context, tx pgx.Tx, hostID uuid.UUID) (passed, failed, total int, err error) {
	row := tx.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE current_status = 'pass')   AS passed,
			count(*) FILTER (WHERE current_status = 'fail')   AS failed,
			count(*)                                          AS total
		  FROM host_rule_state
		 WHERE host_id = $1`, hostID)
	if err := row.Scan(&passed, &failed, &total); err != nil {
		return 0, 0, 0, fmt.Errorf("read current counts: %w", err)
	}
	return passed, failed, total, nil
}

// reconstructPriorCounts derives the prior pass/fail counts by undoing
// this scan's state transitions. For each transaction with
// change_kind = 'state_changed':
//   - prior status was the OPPOSITE direction
//
// For 'first_seen' transactions, the rule didn't exist in the prior
// state (so it shouldn't count toward prior).
func (s *Service) reconstructPriorCounts(ctx context.Context, tx pgx.Tx, hostID, scanID uuid.UUID, currentPassed, currentFailed int) (priorPassed, priorFailed int, hadPrior bool, err error) {
	rows, err := tx.Query(ctx, `
		SELECT change_kind, status
		  FROM transactions
		 WHERE host_id = $1 AND scan_id = $2`,
		hostID, scanID)
	if err != nil {
		return 0, 0, false, fmt.Errorf("read transitions: %w", err)
	}
	defer rows.Close()

	priorPassed = currentPassed
	priorFailed = currentFailed
	firstSeenCount := 0

	for rows.Next() {
		var changeKind, status string
		if err := rows.Scan(&changeKind, &status); err != nil {
			return 0, 0, false, err
		}
		switch changeKind {
		case "first_seen":
			// This rule didn't exist in the prior state. Remove it
			// from the prior count.
			firstSeenCount++
			switch status {
			case "pass":
				priorPassed--
			case "fail":
				priorFailed--
			}
		case "state_changed":
			// Flip the prior count: if current is pass, prior was fail.
			switch status {
			case "pass":
				priorPassed--
				priorFailed++
			case "fail":
				priorFailed--
				priorPassed++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, false, err
	}

	// Total rows in current = currentPassed + currentFailed + skipped/error.
	// If ALL of those were first_seen, this is the first scan ever.
	var totalRulesInCurrent int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM host_rule_state WHERE host_id = $1`,
		hostID).Scan(&totalRulesInCurrent); err != nil {
		return 0, 0, false, err
	}
	hadPrior = firstSeenCount < totalRulesInCurrent

	return priorPassed, priorFailed, hadPrior, nil
}

// severityTransitions counts state changes by severity.
type severityTransitions struct {
	CriticalBecameFailing int
	HighBecameFailing     int
	MediumBecameFailing   int
	LowBecameFailing      int

	CriticalBecamePassing int
	HighBecamePassing     int
	MediumBecamePassing   int
	LowBecamePassing      int
}

// readSeverityTransitions tallies the per-severity transition counts
// from this scan's transactions rows. Spec C-08 / AC-09.
func (s *Service) readSeverityTransitions(ctx context.Context, tx pgx.Tx, hostID, scanID uuid.UUID) (severityTransitions, error) {
	var out severityTransitions
	rows, err := tx.Query(ctx, `
		SELECT severity, status, change_kind
		  FROM transactions
		 WHERE host_id = $1 AND scan_id = $2
		   AND change_kind IN ('state_changed', 'first_seen')`,
		hostID, scanID)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity *string
		var status, changeKind string
		if err := rows.Scan(&severity, &status, &changeKind); err != nil {
			return out, err
		}
		sev := ""
		if severity != nil {
			sev = strings.ToLower(*severity)
		}

		switch status {
		case "fail":
			switch sev {
			case "critical":
				out.CriticalBecameFailing++
			case "high":
				out.HighBecameFailing++
			case "medium":
				out.MediumBecameFailing++
			case "low":
				out.LowBecameFailing++
			}
		case "pass":
			// Only count "became passing" when this is a state-change
			// (first_seen+pass isn't a "became passing", it's a fresh row).
			if changeKind != "state_changed" {
				continue
			}
			switch sev {
			case "critical":
				out.CriticalBecamePassing++
			case "high":
				out.HighBecamePassing++
			case "medium":
				out.MediumBecamePassing++
			case "low":
				out.LowBecamePassing++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// fillTransitions copies the counts into the report's fields.
func (r *Report) fillTransitions(t severityTransitions) {
	r.CriticalBecameFailing = t.CriticalBecameFailing
	r.HighBecameFailing = t.HighBecameFailing
	r.MediumBecameFailing = t.MediumBecameFailing
	r.LowBecameFailing = t.LowBecameFailing
	r.CriticalBecamePassing = t.CriticalBecamePassing
	r.HighBecamePassing = t.HighBecamePassing
	r.MediumBecamePassing = t.MediumBecamePassing
	r.LowBecamePassing = t.LowBecamePassing
}

// emitDriftDetected emits the compliance.drift.detected audit event.
// Only called for non-stable kinds. Spec C-04 / AC-10.
func (s *Service) emitDriftDetected(ctx context.Context, r Report) {
	detail := map[string]any{
		"host_id":       r.HostID.String(),
		"scan_id":       r.ScanID.String(),
		"drift_type":    TypeForAudit(r.Kind),
		"score_delta":   r.ScoreDelta,
		"prior_score":   r.PriorScore,
		"current_score": r.CurrentScore,
		"severity_transitions": map[string]any{
			"critical_became_failing": r.CriticalBecameFailing,
			"high_became_failing":     r.HighBecameFailing,
			"medium_became_failing":   r.MediumBecameFailing,
			"low_became_failing":      r.LowBecameFailing,
			"critical_became_passing": r.CriticalBecamePassing,
			"high_became_passing":     r.HighBecamePassing,
			"medium_became_passing":   r.MediumBecamePassing,
			"low_became_passing":      r.LowBecamePassing,
		},
	}
	s.emit(ctx, audit.ComplianceDriftDetected, audit.Event{
		ActorType: "system",
		Detail:    mustJSON(detail),
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
