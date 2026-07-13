package fleetrollup

import (
	"context"
	"errors"
	"fmt"
	"time"

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
// On an empty fleet, returns Score{0, 0} with nil error (NOT
// pgx.ErrNoRows). Spec AC-01 / AC-02 / AC-03.
//
// WithFramework filters to rows whose framework_refs JSONB contains
// the given key (api-fleet-observability v1.1.0 AC-14).
func (s *Service) FleetComplianceScore(ctx context.Context, opts ...Option) (Score, error) {
	o := applyOpts(opts)

	// Single SQL covers the unfiltered (framework=""), specific-key, and
	// family paths. framework.MatchSQL($1) is TRUE when $1 is NULL (all
	// rules) or framework_refs carries that exact key OR any key in that
	// family (e.g. "stig" matches stig_rhel9 + stig_rhel10 across a mixed-OS
	// fleet — a single key filter would miss the other OS).
	q := `
		SELECT
			COUNT(*) FILTER (WHERE current_status = 'pass')                  AS passing,
			COUNT(*) FILTER (WHERE current_status IN ('pass','fail'))        AS evaluations
		  FROM host_rule_state
		 WHERE ` + framework.MatchSQL("$1")
	var passing, evaluations int64
	if err := s.pool.QueryRow(ctx, q, nullableFramework(o.framework)).Scan(&passing, &evaluations); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Filtered COUNT never returns NoRows but defend anyway.
			return Score{}, nil
		}
		return Score{}, fmt.Errorf("fleetrollup: FleetComplianceScore: %w", err)
	}
	if evaluations == 0 {
		return Score{PassingFraction: 0, TotalEvaluations: 0}, nil
	}
	return Score{
		PassingFraction:  float64(passing) / float64(evaluations),
		TotalEvaluations: evaluations,
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
		  FROM host_rule_state
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
		  FROM host_rule_state
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
