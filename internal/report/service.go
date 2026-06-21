package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get when no report has the given id.
// Handlers map it to 404.
var ErrNotFound = errors.New("report: not found")

// ErrGroupScopeUnavailable is returned by Generate when a group scope is
// requested but no group resolver was wired (WithGroups). In production
// the resolver is always wired, so this is a programmer/config error.
var ErrGroupScopeUnavailable = errors.New("report: group scope unavailable")

// topFailingLimit caps how many failing rules the executive summary
// embeds. Small, leadership-facing list (matches the prototype).
const topFailingLimit = 5

// executiveTitle is the fixed title for the one MVP report kind.
const executiveTitle = "Fleet Compliance - Executive Summary"

// allHostsLabel is the scope_label when no group scopes the report.
const allHostsLabel = "All hosts"

// GroupScoper resolves a group id to its display name and member host
// ids, so the report service can scope a fleet computation to one group
// without depending on the group package's types. internal/group's
// Service satisfies it via ScopeGroup.
type GroupScoper interface {
	ScopeGroup(ctx context.Context, groupID uuid.UUID) (name string, hostIDs []uuid.UUID, err error)
}

// Service owns the reports library: generating an executive summary
// from current posture, and listing/fetching stored reports.
type Service struct {
	pool   *pgxpool.Pool
	groups GroupScoper // nil until WithGroups; group scoping then 503s
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// WithGroups wires the group resolver used for group-scoped reports.
// Returns the receiver for chaining at construction time.
func (s *Service) WithGroups(g GroupScoper) *Service {
	s.groups = g
	return s
}

const reportCols = `id, title, kind, scope_label, scope, data_as_of, generated_by, format, content, created_at`

func scanReport(row pgx.Row) (Report, error) {
	var rep Report
	var scopeRaw []byte
	err := row.Scan(&rep.ID, &rep.Title, &rep.Kind, &rep.ScopeLabel, &scopeRaw,
		&rep.DataAsOf, &rep.GeneratedBy, &rep.Format, &rep.Content, &rep.CreatedAt)
	if err != nil {
		return rep, err
	}
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &rep.Scope); err != nil {
			return rep, fmt.Errorf("report: decode scope: %w", err)
		}
	}
	return rep, nil
}

// Generate computes the Fleet Compliance Executive Summary from current
// posture (host_rule_state pass/fail counts + critical, the active host
// count, and the top failing rules) and inserts an immutable report
// row. The optional req scopes the summary to a group's member hosts
// and/or a framework lens; an empty req covers all hosts and all
// frameworks (the pre-A1 behavior). generatedBy is the actor recorded on
// the artifact (an email or "scheduler"). The returned Report carries
// the stored JSON content and the resolved scope.
func (s *Service) Generate(ctx context.Context, generatedBy string, req GenerateRequest) (Report, error) {
	scope := Scope{Framework: req.Framework}
	var hostIDs []uuid.UUID // nil = all hosts (no host filter)
	if req.GroupID != nil {
		if s.groups == nil {
			return Report{}, ErrGroupScopeUnavailable
		}
		name, ids, err := s.groups.ScopeGroup(ctx, *req.GroupID)
		if err != nil {
			return Report{}, err // group.ErrNotFound propagates; handler maps to 400
		}
		scope.GroupID = req.GroupID
		scope.GroupName = name
		// A resolved group always filters by host id — even an empty
		// group, which must read as zero hosts (not "all hosts").
		hostIDs = ids
		if hostIDs == nil {
			hostIDs = []uuid.UUID{}
		}
	}

	content, err := s.computeExecutive(ctx, hostIDs, scope.Framework)
	if err != nil {
		return Report{}, err
	}
	raw, err := json.Marshal(content)
	if err != nil {
		return Report{}, fmt.Errorf("report: marshal content: %w", err)
	}
	scopeRaw, err := json.Marshal(scope)
	if err != nil {
		return Report{}, fmt.Errorf("report: marshal scope: %w", err)
	}

	dataAsOf := time.Now().UTC()
	row := s.pool.QueryRow(ctx, `
		INSERT INTO reports (id, title, kind, scope_label, scope, data_as_of, generated_by, format, content)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+reportCols,
		uuid.New(), executiveTitle, KindExecutive, scopeLabel(scope), scopeRaw,
		dataAsOf, generatedBy, "json", raw)
	rep, err := scanReport(row)
	if err != nil {
		return Report{}, fmt.Errorf("report: generate insert: %w", err)
	}
	return rep, nil
}

// computeExecutive samples the fleet posture from host_rule_state and
// the hosts table. Same shape as the Groups fleet rollup and
// fleetrollup.TopFailingRules so the numbers agree across the app. When
// hostIDs is non-nil the posture is scoped to those hosts (an empty
// slice yields zero rows); when framework is non-empty only rules whose
// framework_refs contain that key are counted (the same `?` lens as
// fleetrollup.WithFramework).
func (s *Service) computeExecutive(ctx context.Context, hostIDs []uuid.UUID, framework string) (ExecutiveContent, error) {
	var c ExecutiveContent

	// Shared host_rule_state filters, parameterized so the scoped and
	// unscoped paths are one query each.
	var hrsWhere strings.Builder
	args := []any{}
	addArg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if hostIDs != nil {
		hrsWhere.WriteString(" AND host_id = ANY(" + addArg(hostIDs) + ")")
	}
	if framework != "" {
		hrsWhere.WriteString(" AND framework_refs ? " + addArg(framework))
	}

	var passing, failing, critical, evaluated int
	err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE current_status = 'pass'),
		  count(*) FILTER (WHERE current_status = 'fail'),
		  count(*) FILTER (WHERE current_status = 'fail' AND severity ILIKE 'critical'),
		  count(*) FILTER (WHERE current_status IN ('pass','fail'))
		FROM host_rule_state
		WHERE true`+hrsWhere.String(), args...).Scan(&passing, &failing, &critical, &evaluated)
	if err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: posture counts: %w", err)
	}
	c.PassingRules = passing
	c.FailingRules = failing
	c.CriticalIssues = critical
	c.CompliancePct = compliancePct(passing, evaluated)

	// Active host count: all non-deleted hosts, or the scoped subset.
	hostQ := `SELECT count(*) FROM hosts WHERE deleted_at IS NULL`
	hostArgs := []any{}
	if hostIDs != nil {
		hostQ += " AND id = ANY($1)"
		hostArgs = append(hostArgs, hostIDs)
	}
	if err := s.pool.QueryRow(ctx, hostQ, hostArgs...).Scan(&c.HostCount); err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: host count: %w", err)
	}

	// Top failing rules reuse the same host_rule_state filters plus the
	// LIMIT as the next placeholder.
	limitPH := fmt.Sprintf("$%d", len(args)+1)
	topArgs := append(append([]any{}, args...), topFailingLimit)
	rows, err := s.pool.Query(ctx, `
		SELECT rule_id, count(*)::int AS failing_host_count
		  FROM host_rule_state
		 WHERE current_status = 'fail'`+hrsWhere.String()+`
		 GROUP BY rule_id
		 ORDER BY failing_host_count DESC, rule_id ASC
		 LIMIT `+limitPH, topArgs...)
	if err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: top failing rules: %w", err)
	}
	defer rows.Close()
	c.TopFailingRules = []TopFailingRule{}
	for rows.Next() {
		var t TopFailingRule
		if err := rows.Scan(&t.RuleID, &t.FailingHostCount); err != nil {
			return ExecutiveContent{}, fmt.Errorf("report: top failing scan: %w", err)
		}
		c.TopFailingRules = append(c.TopFailingRules, t)
	}
	if err := rows.Err(); err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: top failing iterate: %w", err)
	}
	return c, nil
}

// scopeLabel renders the human scope_label from a resolved scope:
// "<group or All hosts>" optionally suffixed with " · <FRAMEWORK family>"
// (e.g. "Production · CIS", "All hosts · STIG", "Production", "All hosts").
func scopeLabel(sc Scope) string {
	left := allHostsLabel
	if sc.GroupName != "" {
		left = sc.GroupName
	}
	if fw := frameworkFamilyLabel(sc.Framework); fw != "" {
		return left + " · " + fw
	}
	return left
}

// frameworkFamilyLabel shortens a framework_refs key to its family for a
// leadership-facing label: "cis_rhel9_v2.0.0" -> "CIS", "stig_rhel9_v2r7"
// -> "STIG". The family is the token before the first underscore,
// uppercased. Empty in -> empty out (no lens).
func frameworkFamilyLabel(framework string) string {
	if framework == "" {
		return ""
	}
	head := framework
	if i := strings.IndexByte(framework, '_'); i > 0 {
		head = framework[:i]
	}
	return strings.ToUpper(head)
}

// compliancePct rounds passing/evaluated to a whole percent (round half
// up). It returns nil when nothing has been evaluated yet, so the
// executive summary distinguishes "0% compliant" from "never scanned".
// Pure (no DB), so the rounding contract is unit-tested directly.
func compliancePct(passing, evaluated int) *int {
	if evaluated <= 0 {
		return nil
	}
	pct := (passing*100 + evaluated/2) / evaluated
	return &pct
}

// List returns every report, newest first.
func (s *Service) List(ctx context.Context) ([]Report, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reportCols+` FROM reports ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("report: list: %w", err)
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, fmt.Errorf("report: list scan: %w", err)
		}
		out = append(out, rep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("report: list iterate: %w", err)
	}
	return out, nil
}

// Get returns one report by id, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Report, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+reportCols+` FROM reports WHERE id = $1`, id)
	rep, err := scanReport(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, fmt.Errorf("report: get: %w", err)
	}
	return rep, nil
}
