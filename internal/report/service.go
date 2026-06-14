package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get when no report has the given id.
// Handlers map it to 404.
var ErrNotFound = errors.New("report: not found")

// topFailingLimit caps how many failing rules the executive summary
// embeds. Small, leadership-facing list (matches the prototype).
const topFailingLimit = 5

// executiveTitle is the fixed title for the one MVP report kind.
const executiveTitle = "Fleet Compliance - Executive Summary"

// executiveScope is the fixed scope for the MVP (no scope picker yet).
const executiveScope = "All hosts"

// Service owns the reports library: generating an executive summary
// from current posture, and listing/fetching stored reports.
type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

const reportCols = `id, title, kind, scope_label, data_as_of, generated_by, format, content, created_at`

func scanReport(row pgx.Row) (Report, error) {
	var rep Report
	err := row.Scan(&rep.ID, &rep.Title, &rep.Kind, &rep.ScopeLabel,
		&rep.DataAsOf, &rep.GeneratedBy, &rep.Format, &rep.Content, &rep.CreatedAt)
	return rep, err
}

// Generate computes the Fleet Compliance Executive Summary from current
// posture (host_rule_state pass/fail counts + critical, the active host
// count, and the top failing rules) and inserts an immutable report
// row. generatedBy is the actor recorded on the artifact (an email or
// "scheduler"). The returned Report carries the stored JSON content.
func (s *Service) Generate(ctx context.Context, generatedBy string) (Report, error) {
	content, err := s.computeExecutive(ctx)
	if err != nil {
		return Report{}, err
	}
	raw, err := json.Marshal(content)
	if err != nil {
		return Report{}, fmt.Errorf("report: marshal content: %w", err)
	}

	dataAsOf := time.Now().UTC()
	row := s.pool.QueryRow(ctx, `
		INSERT INTO reports (id, title, kind, scope_label, data_as_of, generated_by, format, content)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+reportCols,
		uuid.New(), executiveTitle, KindExecutive, executiveScope,
		dataAsOf, generatedBy, "json", raw)
	rep, err := scanReport(row)
	if err != nil {
		return Report{}, fmt.Errorf("report: generate insert: %w", err)
	}
	return rep, nil
}

// computeExecutive samples the fleet posture from host_rule_state and
// the hosts table. Same shape as the Groups fleet rollup and
// fleetrollup.TopFailingRules so the numbers agree across the app.
func (s *Service) computeExecutive(ctx context.Context) (ExecutiveContent, error) {
	var c ExecutiveContent

	var passing, failing, critical, evaluated int
	err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE current_status = 'pass'),
		  count(*) FILTER (WHERE current_status = 'fail'),
		  count(*) FILTER (WHERE current_status = 'fail' AND severity ILIKE 'critical'),
		  count(*) FILTER (WHERE current_status IN ('pass','fail'))
		FROM host_rule_state`).Scan(&passing, &failing, &critical, &evaluated)
	if err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: posture counts: %w", err)
	}
	c.PassingRules = passing
	c.FailingRules = failing
	c.CriticalIssues = critical
	c.CompliancePct = compliancePct(passing, evaluated)

	err = s.pool.QueryRow(ctx, `
		SELECT count(*) FROM hosts WHERE deleted_at IS NULL`).Scan(&c.HostCount)
	if err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: host count: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT rule_id, count(*)::int AS failing_host_count
		  FROM host_rule_state
		 WHERE current_status = 'fail'
		 GROUP BY rule_id
		 ORDER BY failing_host_count DESC, rule_id ASC
		 LIMIT $1`, topFailingLimit)
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
