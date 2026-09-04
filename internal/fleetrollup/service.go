package fleetrollup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/framework"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service is the read-only fleet rollup query handle. Constructed
// once at boot via NewService.
type Service struct {
	pool *pgxpool.Pool
}

// NewService returns a Service bound to the given pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// FleetComplianceScore returns the fleet-wide compliance score from
// host_rule_state. Counts only rows with current_status IN
// ('pass','fail') — skipped + error rows are excluded from both
// numerator and denominator.
//
// Every row is scoped to its host's current corpus (internal/corpus), so
// a rule that has left a host's scanned corpus stops counting there. A
// host with no completed scan contributes nothing.
//
// The mean is EQUAL-HOST: score each host, then average the scores. It is not
// a pooled ratio over every rule row, which weighted each host by how many
// rules it carried and called the result a fleet score.
//
// A host that produced no verdict is counted in HostsWithoutScore and left out
// of the mean, never averaged in as zero. An empty fleet has NO score rather
// than zero percent, and still returns nil error, never pgx.ErrNoRows.
//
// ONE LENS. Every host is scored against the framework passed here, resolved to
// that host's OS. Per-host effective targets are deliberately not honored: an
// average over hosts each graded on a different benchmark is not a measurement
// of anything. Spec system-fleet-rollup C-05, AC-01 to AC-03.
//
// WithFramework filters to rows whose framework_refs JSONB contains
// the given key (api-fleet-observability v1.1.0 AC-14).
func (s *Service) FleetComplianceScore(ctx context.Context, opts ...Option) (Score, error) {
	o := applyOpts(opts)

	// Per-host OS-resolved lens (framework.OSResolvedMatchSQL): each host
	// contributes its OWN OS-specific benchmark — a RHEL 9 host scores against
	// stig_rhel9, a RHEL 10 host against stig_rhel10 — rather than the family
	// union, which would grade every host against every OS variant it carries
	// mapped rules for. $1 NULL = all rules. Joins hosts for each row's OS.
	// One row per host, then the mean of those rows. The GROUP BY is what makes
	// it equal-host: without it this is the pooled ratio it replaces.
	//
	// The per-host value is ScorePctSQL, which is NOT rounded. Rounding each
	// host to one decimal before averaging is a different function from
	// averaging and rounding once: 0/1 and 2/3 average to 33.3, but rounding
	// first averages 0.0 and 66.7 to 33.4.
	// The population is EVERY ACTIVE HOST, left-joined to its rule state, not
	// the hosts that happen to have rows.
	//
	// Building per_host from host_rule_state_current made a host disappear
	// instead of counting: never scanned, scanned and produced nothing, or
	// carrying no rule that matches the chosen lens all yielded no row at all,
	// so HostsWithoutScore under-reported and hosts_scored plus
	// hosts_without_score did not add up to the fleet. The lens predicate
	// therefore belongs in the JOIN condition; in WHERE it would turn the outer
	// join back into an inner one and undo this.
	q := `
		WITH per_host AS (
			SELECT hh.id AS host_id,
			       ` + compliance.ScorePctSQL(
		compliance.StatusCountSQL("hrs", "'pass'"),
		compliance.StatusCountSQL("hrs", "'pass','fail'")) + ` AS score_pct,
			       ` + compliance.StatusCountSQL("hrs", "'pass'") + ` AS passing,
			       ` + compliance.StatusCountSQL("hrs", "'fail'") + ` AS failing,
			       ` + compliance.StatusCountSQL("hrs", "'skipped'") + ` AS skipped,
			       ` + compliance.StatusCountSQL("hrs", "'error'") + ` AS errored,
			       -- The engine that produced THIS host's outcomes, copied from
			       -- the run its rule state belongs to. MIN over one host's rows
			       -- is that host's single value; the DISTINCT across hosts is
			       -- taken below.
			       MIN(sr.engine_version) AS engine_version
			  FROM hosts hh
			  LEFT JOIN host_rule_state_current hrs
			    ON hrs.host_id = hh.id
			   AND ` + framework.OSResolvedMatchSQL("$1", "hh.os_family", "hh.os_version") + `
			  LEFT JOIN scan_runs sr ON sr.id = hrs.last_scan_id
			 WHERE hh.deleted_at IS NULL
			 GROUP BY hh.id
		)
		SELECT ` + compliance.MeanScoreSQL("score_pct") + `,
		       COUNT(*) FILTER (WHERE score_pct IS NOT NULL)::int,
		       COUNT(*) FILTER (WHERE score_pct IS NULL)::int,
		       COUNT(*)::int,
		       COALESCE(SUM(passing), 0)::bigint,
		       COALESCE(SUM(failing), 0)::bigint,
		       COALESCE(SUM(skipped), 0)::bigint,
		       COALESCE(SUM(errored), 0)::bigint,
		       -- Engine contributors WITH COUNTS, over the SCORED hosts only.
		       -- A bare version list could not tell "every scored host ran
		       -- v0.9.0" from "one did and the rest recorded nothing", and the
		       -- singular engine_version then published agreement that did not
		       -- exist. The counts make the difference visible and let the
		       -- envelope refuse an accounting that does not reconcile.
		       COALESCE(
		           (SELECT jsonb_agg(jsonb_build_object(
		                       'engine_version', e.engine_version,
		                       'contributors_scored', e.n)
		                   ORDER BY e.engine_version)
		              FROM (SELECT engine_version, COUNT(*)::int AS n
		                      FROM per_host
		                     WHERE score_pct IS NOT NULL AND engine_version IS NOT NULL
		                     GROUP BY engine_version) e),
		           '[]'::jsonb),
		       -- Scored hosts whose run recorded no engine.
		       COUNT(*) FILTER (WHERE score_pct IS NOT NULL AND engine_version IS NULL)::int
		  FROM per_host`
	var mean *float64
	var scored, unscored, total int
	var counts compliance.Counts
	var engineRows []struct {
		EngineVersion      string `json:"engine_version"`
		ContributorsScored int    `json:"contributors_scored"`
	}
	var withoutEngine int
	// The counts come from the SAME statement as the score, so a scan
	// completing between two queries cannot leave the number and the outcomes
	// behind it describing different snapshots of the fleet.
	if err := s.pool.QueryRow(ctx, q, nullableFramework(o.framework)).
		Scan(&mean, &scored, &unscored, &total,
			&counts.Pass, &counts.Fail, &counts.Skipped, &counts.Error,
			&engineRows, &withoutEngine); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// An aggregate over an empty set returns one row of NULLs, never
			// NoRows, but defend anyway. An empty fleet has no score.
			return Score{}, nil
		}
		return Score{}, fmt.Errorf("fleetrollup: FleetComplianceScore: %w", err)
	}
	score, err := compliance.ScoreFromNullable(mean)
	if err != nil {
		return Score{}, fmt.Errorf("fleetrollup: FleetComplianceScore: %w", err)
	}
	engines := make([]compliance.EngineContributor, 0, len(engineRows))
	for _, e := range engineRows {
		engines = append(engines, compliance.EngineContributor{
			EngineVersion: e.EngineVersion, ContributorsScored: e.ContributorsScored,
		})
	}
	// The invariant, checked rather than assumed. If it ever fails, a host
	// vanished from the population and the counts describe a fleet that is not
	// the one being reported on.
	if scored+unscored != total {
		return Score{}, fmt.Errorf(
			"fleetrollup: FleetComplianceScore: %d scored + %d unscored != %d hosts",
			scored, unscored, total)
	}
	return Score{
		Score:  score,
		Counts: counts,
		// skipReasonsTyped is false for every deployment until KN-OW-021 ships.
		// Passing it rather than assuming it keeps the call site honest about
		// which world it is in.
		Coverage:           compliance.AssessmentCoverage(counts, false),
		HostsScored:        scored,
		HostsWithoutScore:  unscored,
		HostsTotal:         total,
		Lens:               o.framework,
		Engines:            engines,
		HostsWithoutEngine: withoutEngine,
	}, nil
}

// nullableFramework returns nil for the empty string (so the query's
// "$1::text IS NULL OR …" short-circuits to TRUE = unfiltered) or the
// string otherwise. Keeps the SQL constant across both code paths.
func nullableFramework(framework string) any {
	if framework == "" {
		return nil
	}
	return framework
}

// FleetLiveness returns host counts by reachability status. The four
// buckets sum to the count of active (deleted_at IS NULL) hosts. Hosts
// that have a row in `hosts` but no row in `host_liveness` are counted
// as never_probed. Spec AC-04.
func (s *Service) FleetLiveness(ctx context.Context) (LivenessRollup, error) {
	const q = `
		SELECT
			COUNT(*) FILTER (WHERE hl.reachability_status = 'reachable')                AS reachable,
			COUNT(*) FILTER (WHERE hl.reachability_status = 'unreachable')              AS unreachable,
			COUNT(*) FILTER (WHERE hl.reachability_status = 'unknown')                  AS unknown,
			COUNT(*) FILTER (WHERE hl.host_id IS NULL)                                  AS never_probed
		  FROM hosts h
		  LEFT JOIN host_liveness hl ON hl.host_id = h.id
		 WHERE h.deleted_at IS NULL`
	var out LivenessRollup
	if err := s.pool.QueryRow(ctx, q).Scan(
		&out.Reachable, &out.Unreachable, &out.Unknown, &out.NeverProbed,
	); err != nil {
		return LivenessRollup{}, fmt.Errorf("fleetrollup: FleetLiveness: %w", err)
	}
	return out, nil
}

// ConnectivityBreakdown returns the 4-state per-host count breakdown.
// All five buckets are derived in one round-trip from host_liveness;
// hosts without a liveness row are counted as never_probed. Spec
// api-fleet-connectivity-breakdown AC-02/03/04/05.
//
// Band rules (priority — down dominates):
//
//	consecutive_failures>=3                                  -> down
//	reachable AND consecutive_failures=0                      -> online
//	reachable AND consecutive_failures>=1                     -> degraded
//	unreachable AND consecutive_failures<3                    -> critical
//	(no host_liveness row)                                    -> never_probed
//	unknown OR any other state with consecutive_failures<3    -> never_probed
//
// The last fallback keeps the sum invariant — a host with
// reachability_status='unknown' but a stub row is still NOT online.
func (s *Service) ConnectivityBreakdown(ctx context.Context) (ConnectivityBreakdown, error) {
	const q = `
		SELECT
			COUNT(*) FILTER (WHERE hl.host_id IS NOT NULL
			                   AND hl.consecutive_failures < 3
			                   AND hl.reachability_status = 'reachable'
			                   AND hl.consecutive_failures = 0)                       AS online,
			COUNT(*) FILTER (WHERE hl.host_id IS NOT NULL
			                   AND hl.consecutive_failures < 3
			                   AND hl.reachability_status = 'reachable'
			                   AND hl.consecutive_failures >= 1)                      AS degraded,
			COUNT(*) FILTER (WHERE hl.host_id IS NOT NULL
			                   AND hl.consecutive_failures < 3
			                   AND hl.reachability_status = 'unreachable')             AS critical,
			COUNT(*) FILTER (WHERE hl.host_id IS NOT NULL
			                   AND hl.consecutive_failures >= 3)                       AS down,
			COUNT(*) FILTER (WHERE hl.host_id IS NULL
			                    OR (hl.host_id IS NOT NULL
			                       AND hl.consecutive_failures < 3
			                       AND hl.reachability_status NOT IN ('reachable','unreachable'))) AS never_probed
		  FROM hosts h
		  LEFT JOIN host_liveness hl ON hl.host_id = h.id
		 WHERE h.deleted_at IS NULL`
	var out ConnectivityBreakdown
	if err := s.pool.QueryRow(ctx, q).Scan(
		&out.Online, &out.Degraded, &out.Critical, &out.Down, &out.NeverProbed,
	); err != nil {
		return ConnectivityBreakdown{}, fmt.Errorf("fleetrollup: ConnectivityBreakdown: %w", err)
	}
	return out, nil
}

// TopFailingRules returns the rules with the most failing hosts, in
// descending order. limit is coerced to [0, MaxLimit]. A coerced
// limit of 0 returns an empty slice with nil error (no query
// executed). Spec AC-05 / AC-06 / AC-10.
//
// WithFramework filters to rows whose framework_refs JSONB contains
// the given key (api-fleet-observability v1.1.0 AC-15).
func (s *Service) TopFailingRules(ctx context.Context, limit int, opts ...Option) ([]RuleFailureRollup, error) {
	n := clampLimit(limit)
	if n == 0 {
		return []RuleFailureRollup{}, nil
	}
	o := applyOpts(opts)
	// framework.MatchSQL($2) is family-aware (matches any corpus key in the
	// family, e.g. "stig" spans stig_rhel9 + stig_rhel10) and handles the
	// NULL/all-rules case; a bare framework_refs ? $2 would only match an
	// exact key. Kept consistent with FleetComplianceScore.
	q := `
		SELECT rule_id, COUNT(*)::BIGINT AS failing_host_count
		  FROM host_rule_state_current
		 WHERE current_status = 'fail'
		   AND ` + framework.MatchSQL("$2") + `
		 GROUP BY rule_id
		 ORDER BY failing_host_count DESC, rule_id ASC
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, n, nullableFramework(o.framework))
	if err != nil {
		return nil, fmt.Errorf("fleetrollup: TopFailingRules: %w", err)
	}
	defer rows.Close()

	out := make([]RuleFailureRollup, 0, n)
	for rows.Next() {
		var r RuleFailureRollup
		if err := rows.Scan(&r.RuleID, &r.FailingHostCount); err != nil {
			return nil, fmt.Errorf("fleetrollup: TopFailingRules scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fleetrollup: TopFailingRules iterate: %w", err)
	}
	return out, nil
}

// TopFailingHosts returns the hosts with the most failing rules, in
// descending order. limit is coerced to [0, MaxLimit]. Spec AC-07 / AC-10.
//
// WithFramework filters to rows whose framework_refs JSONB contains
// the given key (api-fleet-observability v1.1.0).
func (s *Service) TopFailingHosts(ctx context.Context, limit int, opts ...Option) ([]HostFailureRollup, error) {
	n := clampLimit(limit)
	if n == 0 {
		return []HostFailureRollup{}, nil
	}
	o := applyOpts(opts)
	q := `
		SELECT host_id, COUNT(*)::BIGINT AS failing_rule_count
		  FROM host_rule_state_current
		 WHERE current_status = 'fail'
		   AND ` + framework.MatchSQL("$2") + `
		 GROUP BY host_id
		 ORDER BY failing_rule_count DESC, host_id ASC
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, n, nullableFramework(o.framework))
	if err != nil {
		return nil, fmt.Errorf("fleetrollup: TopFailingHosts: %w", err)
	}
	defer rows.Close()

	out := make([]HostFailureRollup, 0, n)
	for rows.Next() {
		var h HostFailureRollup
		if err := rows.Scan(&h.HostID, &h.FailingRuleCount); err != nil {
			return nil, fmt.Errorf("fleetrollup: TopFailingHosts scan: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fleetrollup: TopFailingHosts iterate: %w", err)
	}
	return out, nil
}

// RecentChanges returns the most recent transactions, ordered by
// occurred_at DESC. since filters to rows strictly newer than the
// given timestamp. Pass time.Time{} (the zero value) to disable the
// cursor. limit is coerced to [0, MaxLimit]. Spec AC-08 / AC-10.
//
// WithFramework filters to transactions whose framework_refs JSONB
// contains the given key (api-fleet-observability v1.1.0 AC-16).
func (s *Service) RecentChanges(ctx context.Context, since time.Time, limit int, opts ...Option) ([]TransactionRollup, error) {
	n := clampLimit(limit)
	if n == 0 {
		return []TransactionRollup{}, nil
	}
	o := applyOpts(opts)
	// The "$2::timestamptz IS NULL" idiom lets us encode "no cursor"
	// without branching the SQL. Same trick for framework via $3::text.
	q := `
		SELECT id, host_id, rule_id, status, COALESCE(severity, ''), change_kind, occurred_at
		  FROM transactions
		 WHERE ($2::timestamptz IS NULL OR occurred_at > $2)
		   AND ` + framework.MatchSQL("$3") + `
		 ORDER BY occurred_at DESC
		 LIMIT $1`
	var sinceParam any
	if !since.IsZero() {
		sinceParam = since
	}
	rows, err := s.pool.Query(ctx, q, n, sinceParam, nullableFramework(o.framework))
	if err != nil {
		return nil, fmt.Errorf("fleetrollup: RecentChanges: %w", err)
	}
	defer rows.Close()

	out := make([]TransactionRollup, 0, n)
	for rows.Next() {
		var (
			t      TransactionRollup
			hostID uuid.UUID
			id     uuid.UUID
		)
		if err := rows.Scan(&id, &hostID, &t.RuleID, &t.Status, &t.Severity, &t.ChangeKind, &t.OccurredAt); err != nil {
			return nil, fmt.Errorf("fleetrollup: RecentChanges scan: %w", err)
		}
		t.ID = id
		t.HostID = hostID
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fleetrollup: RecentChanges iterate: %w", err)
	}
	return out, nil
}
