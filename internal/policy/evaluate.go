package policy

import (
	"context"
	"fmt"
	"time"
)

// Outcomes specific to the alert_thresholds policy. These ride in the
// Decision.Outcome field alongside the universal allow/deny/defer.
const (
	OutcomeAlertCritical Outcome = "critical"
	OutcomeAlertHigh     Outcome = "high"
	OutcomeAlertMedium   Outcome = "medium"
	OutcomeAlertOK       Outcome = "ok"
)

// EvaluateAlert evaluates the alert_thresholds policy against an
// AlertInput. Returns a Decision and emits a policy.applied audit event.
//
// Spec system-policy AC-08, AC-12, C-08.
func EvaluateAlert(ctx context.Context, in AlertInput) Decision {
	s := Get()
	if s == nil {
		s = Init()
	}
	t := s.AlertThresholds
	score := in.Score
	d := Decision{
		PolicyType:    TypeAlertThresholds,
		PolicyVersion: s.Versions[TypeAlertThresholds],
		AppliedAt:     time.Now(),
		Detail:        map[string]any{"score": score},
	}
	switch {
	case score < t.CriticalBelow:
		d.Outcome = OutcomeAlertCritical
		d.Reason = "score_below_critical_threshold"
		d.HumanMessage = fmt.Sprintf("score %d is below critical threshold %d", score, t.CriticalBelow)
	case score < t.HighBelow:
		d.Outcome = OutcomeAlertHigh
		d.Reason = "score_below_high_threshold"
		d.HumanMessage = fmt.Sprintf("score %d is below high threshold %d", score, t.HighBelow)
	case score < t.MediumBelow:
		d.Outcome = OutcomeAlertMedium
		d.Reason = "score_below_medium_threshold"
		d.HumanMessage = fmt.Sprintf("score %d is below medium threshold %d", score, t.MediumBelow)
	default:
		d.Outcome = OutcomeAlertOK
		d.Reason = "score_above_thresholds"
		d.HumanMessage = fmt.Sprintf("score %d is healthy", score)
	}
	emitApplied(ctx, d)
	return d
}
