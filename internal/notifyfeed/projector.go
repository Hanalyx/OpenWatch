package notifyfeed

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Projector turns the transaction-log changes a completed scan wrote into a
// single, grouped, per-host in-app notification — the headline "a rule that was
// passing is now failing" surface (notifications_design.md §3, Slice 2).
//
// It is the second producer of the bell, alongside the alertrouter Channel
// (host_unreachable/recovered, drift_*). The Channel covers fleet/host-level
// alerts; the Projector covers RULE-level regressions, which the alert engine
// does not classify. Both write through the same notifyfeed.Store, so read
// state, grouping, and fan-out are uniform.
//
// Runs in the scan worker (where transactionlog.Writer.Apply commits), called
// best-effort after the outcomes persist. Spec: system-notifications.
type Projector struct {
	store *Store
}

// NewProjector returns a regression projector over the given feed store.
func NewProjector(store *Store) *Projector { return &Projector{store: store} }

// regressionRow is one candidate change for a scan: a rule that flipped to fail.
type regressionRow struct {
	ruleID     string
	severity   string
	changeKind string
}

// ProjectScan reads the changes the given scan wrote for the given host and, if
// any qualify as a regression, records ONE grouped "rule_regression"
// notification fanned to every active recipient.
//
// What qualifies (notifications_design.md §3 "Compliance"):
//   - state_changed -> fail: a rule that was passing (or skipped/errored) now
//     fails. The unambiguous regression; always counted.
//   - first_seen -> fail, severity critical: a brand-new critical finding. Only
//     counted when the host has prior scan history — on a host's FIRST scan
//     every rule is first_seen, which is a baseline, not a regression, and must
//     not flood the bell with "N rules regressed".
//
// Grouping (design §8): one notification per host (group_key
// "rule_regression:<host>"), so a burst of N rules in one scan is one row, and a
// later scan's regressions collapse onto (and re-surface) the same row rather
// than piling up. The notification severity is the highest among the regressed
// rules; the title summarizes the counts.
//
// Best-effort: a nil/empty result is a no-op returning nil. The caller treats
// any error as non-fatal (the scan already persisted).
func (p *Projector) ProjectScan(ctx context.Context, scanID, hostID uuid.UUID) error {
	if scanID == uuid.Nil || hostID == uuid.Nil {
		return fmt.Errorf("notifyfeed: ProjectScan requires scanID and hostID")
	}

	rows, err := p.store.pool.Query(ctx, `
		SELECT rule_id, COALESCE(severity, ''), change_kind
		  FROM transactions
		 WHERE scan_id = $1 AND host_id = $2 AND status = 'fail'
		   AND change_kind IN ('state_changed', 'first_seen')`,
		scanID, hostID)
	if err != nil {
		return fmt.Errorf("notifyfeed: project read changes: %w", err)
	}
	var candidates []regressionRow
	for rows.Next() {
		var r regressionRow
		if err := rows.Scan(&r.ruleID, &r.severity, &r.changeKind); err != nil {
			rows.Close()
			return fmt.Errorf("notifyfeed: project scan row: %w", err)
		}
		candidates = append(candidates, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("notifyfeed: project read changes: %w", err)
	}
	if len(candidates) == 0 {
		return nil
	}

	// first_seen rows only count as "new critical finding" when this is not
	// the host's first scan (otherwise the whole baseline is first_seen).
	hasPriorHistory := false
	if hasFirstSeen(candidates) {
		if err := p.store.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM transactions WHERE host_id = $1 AND scan_id <> $2)`,
			hostID, scanID).Scan(&hasPriorHistory); err != nil {
			return fmt.Errorf("notifyfeed: project prior-history check: %w", err)
		}
	}

	regressed := make([]regressionRow, 0, len(candidates))
	for _, r := range candidates {
		switch r.changeKind {
		case "state_changed":
			regressed = append(regressed, r)
		case "first_seen":
			// New finding: only a critical one, and only on a host with
			// prior scan history, is bell-worthy.
			if hasPriorHistory && r.severity == "critical" {
				regressed = append(regressed, r)
			}
		}
	}
	if len(regressed) == 0 {
		return nil
	}

	total := len(regressed)
	criticalCount := 0
	topSeverity := ""
	for _, r := range regressed {
		if r.severity == "critical" {
			criticalCount++
		}
		if severityRank(r.severity) > severityRank(topSeverity) {
			topSeverity = r.severity
		}
	}
	if topSeverity == "" {
		topSeverity = "low" // a fail with no severity still warrants a low-rank ping
	}

	name := p.store.hostName(ctx, hostID)

	n := Notification{
		Kind:     "rule_regression",
		Severity: topSeverity,
		Title:    regressionTitle(name, total, criticalCount),
		Body:     regressionBody(total, criticalCount),
		HostID:   &hostID,
		Link:     "/hosts/" + hostID.String(),
		GroupKey: "rule_regression:" + hostID.String(),
	}
	if err := p.store.RecordFanout(ctx, n); err != nil {
		return fmt.Errorf("notifyfeed: project record: %w", err)
	}
	return nil
}

// hasFirstSeen reports whether any candidate is a first_seen change (so we only
// pay for the prior-history query when it can matter).
func hasFirstSeen(rows []regressionRow) bool {
	for _, r := range rows {
		if r.changeKind == "first_seen" {
			return true
		}
	}
	return false
}

// severityRank orders the alertrouter severity strings for "highest wins".
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// regressionTitle builds "web-01: 3 rules regressed (1 critical)".
func regressionTitle(host string, total, critical int) string {
	t := fmt.Sprintf("%s: %d %s regressed", host, total, plural(total, "rule", "rules"))
	if critical > 0 {
		t += fmt.Sprintf(" (%d critical)", critical)
	}
	return t
}

// regressionBody is the short detail line under the title.
func regressionBody(total, critical int) string {
	b := fmt.Sprintf("The latest scan flipped %d %s from passing to failing.",
		total, plural(total, "rule", "rules"))
	if critical > 0 {
		b += fmt.Sprintf(" %d %s critical.", critical, plural(critical, "is", "are"))
	}
	return b
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
