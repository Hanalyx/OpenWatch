package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
func (s *Service) List(ctx context.Context) ([]GroupWithRollup, error) {
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
		roll, err := s.rollup(ctx, g)
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
	g, err := s.Get(ctx, groupID)
	if err != nil {
		return "", nil, err // ErrNotFound propagates
	}
	cte, arg := memberCTE(g)
	rows, err := s.pool.Query(ctx, cte, arg)
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

// memberCTE returns the SQL selecting a group's member host ids plus the
// bound argument. Manual groups read group_members; auto groups derive
// from hosts.os_family == match_family.
func memberCTE(g Group) (string, any) {
	if g.Membership == MembershipAuto {
		return `SELECT id AS host_id FROM hosts WHERE deleted_at IS NULL AND os_family = $1`, g.MatchFamily
	}
	return `SELECT host_id FROM group_members WHERE group_id = $1`, g.ID
}

func (s *Service) rollup(ctx context.Context, g Group) (Rollup, error) {
	cte, arg := memberCTE(g)
	var r Rollup
	var passing, evaluated int
	err := s.pool.QueryRow(ctx, `
		WITH m AS (`+cte+`)
		SELECT
		  (SELECT count(*) FROM m),
		  (SELECT count(*) FROM m JOIN host_liveness hl ON hl.host_id = m.host_id
		     WHERE hl.reachability_status = 'reachable'),
		  (SELECT count(*) FROM m JOIN host_liveness hl ON hl.host_id = m.host_id
		     WHERE hl.reachability_status = 'unreachable'),
		  (SELECT count(DISTINCT hrs.host_id) FROM m JOIN host_rule_state hrs ON hrs.host_id = m.host_id
		     WHERE hrs.current_status = 'fail' AND hrs.severity ILIKE 'critical'),
		  (SELECT count(*) FROM m JOIN host_rule_state hrs ON hrs.host_id = m.host_id
		     WHERE hrs.current_status = 'pass'),
		  (SELECT count(*) FROM m JOIN host_rule_state hrs ON hrs.host_id = m.host_id
		     WHERE hrs.current_status IN ('pass','fail'))`,
		arg).Scan(&r.Hosts, &r.Online, &r.Down, &r.CriticalHosts, &passing, &evaluated)
	if err != nil {
		return Rollup{}, fmt.Errorf("group: rollup: %w", err)
	}
	if evaluated > 0 {
		pct := int((passing*100 + evaluated/2) / evaluated)
		r.AvgCompliancePct = &pct
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
func (s *Service) Summary(ctx context.Context) (FleetSummary, error) {
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

	// Fleet avg compliance across all active hosts (passing / evaluated).
	var passing, evaluated int
	err = s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE current_status = 'pass'),
		  count(*) FILTER (WHERE current_status IN ('pass','fail'))
		FROM host_rule_state`).Scan(&passing, &evaluated)
	if err != nil {
		return FleetSummary{}, fmt.Errorf("group: summary compliance: %w", err)
	}
	if evaluated > 0 {
		pct := int((passing*100 + evaluated/2) / evaluated)
		sum.AvgCompliancePct = &pct
	}
	return sum, nil
}

// isUniqueViolation reports whether err is a Postgres 23505.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
