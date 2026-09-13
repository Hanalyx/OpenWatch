package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/fleetrollup"
	"github.com/Hanalyx/openwatch/internal/framework"
)

// Sentinel errors. Handlers map these to HTTP status codes.
var (
	ErrNotFound          = errors.New("group: not found")
	ErrInvalidKind       = errors.New("group: kind must be site or os_category")
	ErrInvalidMembership = errors.New("group: membership must be manual or auto")
	ErrAutoNeedsFamily   = errors.New("group: auto membership requires a match_family")
	ErrManualHasFamily   = errors.New("group: manual membership must not set match_family")
	ErrSiteMustBeManual  = errors.New("group: a site must use manual membership")
	ErrDuplicateFamily   = errors.New("group: an auto group already exists for that OS family")
	ErrEmptyName         = errors.New("group: name is required")
	ErrTargetOnlyOnSite  = errors.New("group: only a site group may carry a compliance target")
	ErrInvalidTarget     = errors.New("group: target_framework is too long or has invalid characters")
)

// Service owns group CRUD, membership, and the per-group rollups.
type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	var matchFamily, targetFramework *string
	err := row.Scan(&g.ID, &g.Name, &g.Kind, &g.Subtype, &g.Color, &g.Membership,
		&matchFamily, &g.Maintenance, &targetFramework, &g.CreatedAt, &g.UpdatedAt)
	if matchFamily != nil {
		g.MatchFamily = *matchFamily
	}
	if targetFramework != nil {
		g.TargetFramework = *targetFramework
	}
	return g, err
}

const groupCols = `id, name, kind, subtype, color, membership, match_family, maintenance, target_framework, created_at, updated_at`

// Create validates and inserts a group.
func (s *Service) Create(ctx context.Context, in CreateInput) (Group, error) {
	if in.Name == "" {
		return Group{}, ErrEmptyName
	}
	if in.Kind != KindSite && in.Kind != KindOSCategory {
		return Group{}, ErrInvalidKind
	}
	if in.Membership != MembershipManual && in.Membership != MembershipAuto {
		return Group{}, ErrInvalidMembership
	}
	if in.Kind == KindSite && in.Membership != MembershipManual {
		return Group{}, ErrSiteMustBeManual
	}
	if in.Membership == MembershipAuto && in.MatchFamily == "" {
		return Group{}, ErrAutoNeedsFamily
	}
	if in.Membership == MembershipManual && in.MatchFamily != "" {
		return Group{}, ErrManualHasFamily
	}
	color := in.Color
	if color == "" {
		color = "info"
	}
	var matchFamily *string
	if in.Membership == MembershipAuto {
		matchFamily = &in.MatchFamily
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO groups (id, name, kind, subtype, color, membership, match_family)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+groupCols,
		uuid.New(), in.Name, in.Kind, in.Subtype, color, in.Membership, matchFamily)
	g, err := scanGroup(row)
	if isUniqueViolation(err) {
		return Group{}, ErrDuplicateFamily
	}
	if err != nil {
		return Group{}, fmt.Errorf("group: create: %w", err)
	}
	return g, nil
}

// Get returns one group (without rollup).
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Group, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE id = $1`, id)
	g, err := scanGroup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	return g, err
}

// Update patches a group's editable display fields (name/subtype/color).
// Kind and membership are immutable.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (Group, error) {
	if in.Name == "" {
		return Group{}, ErrEmptyName
	}
	color := in.Color
	if color == "" {
		color = "info"
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE groups SET name = $2, subtype = $3, color = $4, updated_at = now()
		WHERE id = $1
		RETURNING `+groupCols, id, in.Name, in.Subtype, color)
	g, err := scanGroup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	return g, err
}

// SetMaintenance toggles a group's maintenance flag.
func (s *Service) SetMaintenance(ctx context.Context, id uuid.UUID, on bool) (Group, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE groups SET maintenance = $2, updated_at = now()
		WHERE id = $1 RETURNING `+groupCols, id, on)
	g, err := scanGroup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	return g, err
}

// SetTarget sets (or clears, when family is "") the group's compliance target
// framework. Only a site group may carry a target (D1): an os_category group
// is an automatic OS grouping, not a statement of compliance intent, so a
// target on one is rejected with ErrTargetOnlyOnSite.
func (s *Service) SetTarget(ctx context.Context, id uuid.UUID, family string) (Group, error) {
	if !validTargetFramework(family) {
		return Group{}, ErrInvalidTarget
	}
	g, err := s.Get(ctx, id)
	if err != nil {
		return Group{}, err // ErrNotFound
	}
	if g.Kind != KindSite {
		return Group{}, ErrTargetOnlyOnSite
	}
	var arg *string
	if family != "" {
		arg = &family
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE groups SET target_framework = $2, updated_at = now()
		WHERE id = $1 RETURNING `+groupCols, id, arg)
	g, err = scanGroup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	return g, err
}

// validTargetFramework bounds a compliance-target family token: empty (clear)
// or <=64 lowercase alnum plus _-. It is resolved leniently against the live
// corpus at query time, so this only blocks garbage / length.
func validTargetFramework(f string) bool {
	if len(f) > 64 {
		return false
	}
	for _, r := range f {
		if !(r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// Delete removes a group (group_members cascade).
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("group: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AddMember assigns a host to a MANUAL group. Auto groups reject manual
// membership (their members are derived).
func (s *Service) AddMember(ctx context.Context, groupID, hostID uuid.UUID) error {
	g, err := s.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if g.Membership != MembershipManual {
		return fmt.Errorf("group: cannot add a member to an auto group")
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO group_members (group_id, host_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, groupID, hostID)
	if err != nil {
		return fmt.Errorf("group: add member: %w", err)
	}
	return nil
}

// RemoveMember removes a host from a manual group.
func (s *Service) RemoveMember(ctx context.Context, groupID, hostID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1 AND host_id = $2`, groupID, hostID)
	if err != nil {
		return fmt.Errorf("group: remove member: %w", err)
	}
	return nil
}

// List returns every group with its computed rollup, sites first.
func (s *Service) List(ctx context.Context, orgDefault string) ([]GroupWithRollup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+groupCols+`
		FROM groups
		ORDER BY kind, name`)
	if err != nil {
		return nil, fmt.Errorf("group: list: %w", err)
	}
	var groups []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	out := make([]GroupWithRollup, 0, len(groups))
	for _, g := range groups {
		roll, err := s.rollup(ctx, g, orgDefault)
		if err != nil {
			return nil, err
		}
		out = append(out, GroupWithRollup{Group: g, Rollup: roll})
	}
	return out, nil
}

// ScopeGroup resolves a group id to its display name and the set of
// active member host ids, for callers that scope a fleet computation to
// one group (e.g. a scoped Reports executive summary). Manual groups
// read group_members; auto groups derive from hosts.os_family ==
// match_family. Returns ErrNotFound when the group does not exist. An
// empty group yields a non-nil, empty id slice (a valid "no hosts"
// scope), distinct from the unscoped all-hosts case the caller models
// as no group at all.
func (s *Service) ScopeGroup(ctx context.Context, groupID uuid.UUID) (string, []uuid.UUID, error) {
	return s.ScopeGroupIn(ctx, s.pool, groupID)
}

// ScopeGroupIn is ScopeGroup against a caller-supplied queryer, so the group
// name and its member set can be read inside the caller's transaction.
func (s *Service) ScopeGroupIn(ctx context.Context, q db.Queryer, groupID uuid.UUID) (string, []uuid.UUID, error) {
	row := q.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE id = $1`, groupID)
	g, err := scanGroup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	cte, arg := memberCTE(g)
	rows, err := q.Query(ctx, cte, arg)
	if err != nil {
		return "", nil, fmt.Errorf("group: scope members: %w", err)
	}
	defer rows.Close()
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return "", nil, fmt.Errorf("group: scope scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("group: scope iterate: %w", err)
	}
	return g.Name, ids, nil
}

// memberCTE returns the SQL selecting a group's ACTIVE member host ids plus the
// bound argument. Manual groups read group_members; auto groups derive
// from hosts.os_family == match_family.
//
// Both branches filter deleted_at. The manual branch did not, so a soft-deleted
// host kept voting in every number the group publishes: hosts_total, the mean,
// the outcome counts, online and down, and critical_hosts. The member CHIP list
// joins hosts and dropped it, so the card showed nine members and averaged ten.
// It also made ScopeGroup's promise of active members untrue, which matters
// more: that function feeds bulk actions.
func memberCTE(g Group) (string, any) {
	if g.Membership == MembershipAuto {
		return `SELECT id AS host_id FROM hosts WHERE deleted_at IS NULL AND os_family = $1`, g.MatchFamily
	}
	return `SELECT gm.host_id
	          FROM group_members gm
	          JOIN hosts h ON h.id = gm.host_id AND h.deleted_at IS NULL
	         WHERE gm.group_id = $1`, g.ID
}

func (s *Service) rollup(ctx context.Context, g Group, orgDefault string) (Rollup, error) {
	cte, arg := memberCTE(g)
	var r Rollup
	var mean *float64
	var counts compliance.Counts
	var engineRows []struct {
		EngineVersion      string `json:"engine_version"`
		ContributorsScored int    `json:"contributors_scored"`
	}
	// ONE LENS FOR THE WHOLE GROUP: this group's own target_framework ($3),
	// else the org default ($2), else all rules. Each member is then RESOLVED
	// to its own OS variant of that family (framework.OSResolvedMatchSQL),
	// which is one lens applied across a mixed fleet rather than two blended.
	//
	// It used to read host_effective_target, which is the wrong view for this
	// question twice over. That view takes the HOST's own target first, so one
	// member could be graded on a different benchmark from its neighbors inside
	// the same average. Failing that it takes the target of the OLDEST site
	// group the host belongs to, which is not necessarily the group being
	// rendered: a host in two differently targeted groups was scored on the
	// first group's benchmark on both cards. Averaging members graded on
	// different benchmarks produces a number that reconciles with no rule list.
	// api-groups C-07.
	lensRef := `COALESCE(NULLIF($3::text, ''), NULLIF($2::text, ''))`
	osMatch := framework.OSResolvedMatchSQL(lensRef, "h.os_family", "h.os_version")
	// The corpus view on the hrs JOIN covers all three subselects below. A
	// member with no completed scan contributes no rule rows, so it produces no
	// score and is left out of the AVERAGE, but it is still a member: the
	// per-host CTE below is built from the membership and left-joins the rule
	// state, so that member is counted in HostsWithoutScore rather than
	// disappearing from the population the average describes.
	lensJoin := `JOIN host_rule_state_current hrs ON hrs.host_id = m.host_id
		         JOIN hosts h ON h.id = m.host_id`
	err := s.pool.QueryRow(ctx, `
		WITH m AS (`+cte+`),
		-- One row per MEMBER, then the mean of those rows. Averaging the rows
		-- is what makes the group score equal-host; summing pass and evaluated
		-- across members and dividing once is the pooled ratio this replaces,
		-- under which a member carrying 800 rules outweighed one carrying 40.
		-- The per-member value is UNROUNDED; the mean is rounded once.
		-- Every MEMBER, left-joined to its rule state. Building this from the
		-- rule state made a member disappear rather than count: never scanned,
		-- scanned and produced nothing, or carrying no rule matching the lens
		-- all yielded no row, so hosts_without_score under-reported and the two
		-- counts did not add up to the membership.
		per_host AS (
			SELECT m.host_id,
			       `+compliance.ScorePctSQL(
		compliance.StatusCountSQL("hrs", "'pass'"),
		compliance.StatusCountSQL("hrs", "'pass','fail'"))+` AS score_pct,
			       `+compliance.StatusCountSQL("hrs", "'pass'")+` AS passing,
			       `+compliance.StatusCountSQL("hrs", "'fail'")+` AS failing,
			       `+compliance.StatusCountSQL("hrs", "'skipped'")+` AS skipped,
			       `+compliance.StatusCountSQL("hrs", "'error'")+` AS errored,
			       -- The engine that produced THIS member's outcomes, bound to
			       -- the rows through the scan id they carry. Without it every
			       -- group reported an empty engine list even after its members'
			       -- scans recorded their producers.
			       MIN(sr.engine_version) AS engine_version
			  FROM m
			  JOIN hosts h ON h.id = m.host_id
			  LEFT JOIN host_rule_state_current hrs
			    ON hrs.host_id = m.host_id AND `+osMatch+`
			  LEFT JOIN scan_runs sr ON sr.id = hrs.last_scan_id
			 GROUP BY m.host_id
		)
		SELECT
		  (SELECT count(*) FROM m),
		  (SELECT count(*) FROM m JOIN host_liveness hl ON hl.host_id = m.host_id
		     WHERE hl.reachability_status = 'reachable'),
		  (SELECT count(*) FROM m JOIN host_liveness hl ON hl.host_id = m.host_id
		     WHERE hl.reachability_status = 'unreachable'),
		  (SELECT count(DISTINCT hrs.host_id) FROM m `+lensJoin+`
		     WHERE hrs.current_status = 'fail' AND hrs.severity ILIKE 'critical' AND `+osMatch+`),
		  (SELECT `+compliance.MeanScoreSQL("score_pct")+` FROM per_host),
		  (SELECT count(*) FILTER (WHERE score_pct IS NOT NULL) FROM per_host)::int,
		  (SELECT count(*) FILTER (WHERE score_pct IS NULL) FROM per_host)::int,
		  (SELECT COALESCE(SUM(passing), 0) FROM per_host)::bigint,
		  (SELECT COALESCE(SUM(failing), 0) FROM per_host)::bigint,
		  (SELECT COALESCE(SUM(skipped), 0) FROM per_host)::bigint,
		  (SELECT COALESCE(SUM(errored), 0) FROM per_host)::bigint,
		  -- Engine contributors over the SCORED members only, with counts, so
		  -- the accounting reconciles with hosts_scored.
		  (SELECT COALESCE(
		       jsonb_agg(jsonb_build_object(
		           'engine_version', e.engine_version,
		           'contributors_scored', e.n) ORDER BY e.engine_version),
		       '[]'::jsonb)
		     FROM (SELECT engine_version, COUNT(*)::int AS n
		             FROM per_host
		            WHERE score_pct IS NOT NULL AND engine_version IS NOT NULL
		            GROUP BY engine_version) e),
		  (SELECT COUNT(*) FILTER (WHERE score_pct IS NOT NULL AND engine_version IS NULL)
		     FROM per_host)::int`,
		arg, orgDefault, g.TargetFramework).Scan(&r.Hosts, &r.Online, &r.Down, &r.CriticalHosts,
		&mean, &r.Score.HostsScored, &r.Score.HostsWithoutScore,
		&counts.Pass, &counts.Fail, &counts.Skipped, &counts.Error,
		&engineRows, &r.Score.HostsWithoutEngine)
	if err != nil {
		return Rollup{}, fmt.Errorf("group: rollup: %w", err)
	}
	score, err := compliance.ScoreFromNullable(mean)
	if err != nil {
		return Rollup{}, fmt.Errorf("group: rollup score: %w", err)
	}
	// Every member is either scored or counted as unscored. A mismatch means a
	// member fell out of the population the average claims to describe.
	if r.Score.HostsScored+r.Score.HostsWithoutScore != r.Hosts {
		return Rollup{}, fmt.Errorf("group: rollup: %d scored + %d unscored != %d members",
			r.Score.HostsScored, r.Score.HostsWithoutScore, r.Hosts)
	}
	for _, e := range engineRows {
		r.Score.Engines = append(r.Score.Engines, compliance.EngineContributor{
			EngineVersion: e.EngineVersion, ContributorsScored: e.ContributorsScored,
		})
	}
	r.Score.Score = score
	r.Score.Counts = counts
	// skipReasonsTyped is false until KN-OW-021 ships, same as the fleet.
	r.Score.Coverage = compliance.AssessmentCoverage(counts, false)
	r.Score.HostsTotal = r.Hosts
	// The lens this group was scored on: its own target, else the org default,
	// else all rules. It is the same precedence the query applied.
	r.Score.Lens = g.TargetFramework
	if r.Score.Lens == "" {
		r.Score.Lens = orgDefault
	}

	chips, err := s.pool.Query(ctx, `
		WITH m AS (`+cte+`)
		SELECT h.id, h.hostname,
		  CASE hl.reachability_status
		    WHEN 'reachable' THEN 'online'
		    WHEN 'unreachable' THEN 'down'
		    ELSE 'unknown' END
		FROM m JOIN hosts h ON h.id = m.host_id
		LEFT JOIN host_liveness hl ON hl.host_id = h.id
		WHERE h.deleted_at IS NULL
		ORDER BY h.hostname LIMIT 8`, arg)
	if err != nil {
		return Rollup{}, fmt.Errorf("group: rollup chips: %w", err)
	}
	defer chips.Close()
	for chips.Next() {
		var c MemberChip
		if err := chips.Scan(&c.HostID, &c.Hostname, &c.Status); err != nil {
			return Rollup{}, err
		}
		r.Members = append(r.Members, c)
	}
	return r, chips.Err()
}

// Summary computes the Groups-page KPI row.
func (s *Service) Summary(ctx context.Context, orgDefault string) (FleetSummary, error) {
	var sum FleetSummary
	err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*),
		  count(*) FILTER (WHERE kind = 'site'),
		  count(*) FILTER (WHERE kind = 'os_category')
		FROM groups`).Scan(&sum.Groups, &sum.Sites, &sum.OSCategories)
	if err != nil {
		return FleetSummary{}, fmt.Errorf("group: summary groups: %w", err)
	}

	// Hosts in maintenance = distinct active hosts that belong to a
	// maintenance group (manual member OR auto-matched).
	err = s.pool.QueryRow(ctx, `
		WITH maint AS (
		  SELECT gm.host_id FROM group_members gm JOIN groups g ON g.id = gm.group_id
		    WHERE g.maintenance
		  UNION
		  SELECT h.id FROM hosts h JOIN groups g
		    ON g.membership = 'auto' AND g.maintenance AND g.match_family = h.os_family
		    WHERE h.deleted_at IS NULL
		)
		SELECT count(*) FROM maint m JOIN hosts h ON h.id = m.host_id WHERE h.deleted_at IS NULL`).
		Scan(&sum.HostsMaintenance)
	if err != nil {
		return FleetSummary{}, fmt.Errorf("group: summary maintenance: %w", err)
	}

	// Ungrouped = active hosts that are in no manual group and match no
	// auto group.
	err = s.pool.QueryRow(ctx, `
		WITH grouped AS (
		  SELECT host_id FROM group_members
		  UNION
		  SELECT h.id FROM hosts h JOIN groups g
		    ON g.membership = 'auto' AND g.match_family = h.os_family
		    WHERE h.deleted_at IS NULL
		)
		SELECT count(*) FROM hosts h
		WHERE h.deleted_at IS NULL AND h.id NOT IN (SELECT host_id FROM grouped)`).
		Scan(&sum.Ungrouped)
	if err != nil {
		return FleetSummary{}, fmt.Errorf("group: summary ungrouped: %w", err)
	}

	// The fleet KPI on the Groups page IS GET /fleet/score.
	//
	// It used to be a second query that meant to compute the same thing, and
	// they had already drifted: this one read the bare corpus view instead of
	// the host population, so a never-scanned host vanished from the counts
	// rather than being reported as unscored, and it had no deleted_at filter,
	// so a soft-deleted host with stale rule state still moved the number.
	// api-groups C-05 and system-compliance-lens AC-11 require the two to
	// agree, and two implementations of one rule agree only until someone edits
	// one of them. Calling the same function makes the divergence impossible
	// rather than merely tested for.
	fleet, err := fleetrollup.NewService(s.pool).
		FleetComplianceScore(ctx, fleetrollup.WithFramework(orgDefault))
	if err != nil {
		return FleetSummary{}, fmt.Errorf("group: summary compliance: %w", err)
	}
	sum.Score = fleet
	return sum, nil
}

// isUniqueViolation reports whether err is a Postgres 23505.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
