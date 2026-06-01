package activity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service serves Activity feeds via a single UNION query.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds a Service to a pgxpool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// List returns a page of activity rows and the count hidden by RBAC.
// Spec C-01..C-06; AC-01..AC-10.
func (s *Service) List(ctx context.Context, f Filter, c Caller) ([]Row, int, string, error) {
	if f.Limit < 1 || f.Limit > 200 {
		return nil, 0, "", ErrInvalidLimit
	}
	if f.Source != "" && !IsKnownSource(f.Source) {
		return nil, 0, "", ErrInvalidSource
	}
	if f.Severity != "" && !IsKnownSeverity(f.Severity) {
		return nil, 0, "", ErrInvalidSeverity
	}

	// Per-source RBAC: when the caller lacks the permission a leg
	// requires, we still build the leg (so its row count flows into
	// hiddenByRBAC) but tag it as suppressed. A second SELECT
	// computes the suppressed total.
	includeAlerts := c.CanReadAlerts && (f.Source == "" || f.Source == string(SourceAlert))
	includeTxn := c.CanReadHosts && (f.Source == "" || f.Source == string(SourceTransaction))
	includeIntel := c.CanReadHosts && (f.Source == "" || f.Source == string(SourceIntelligence))
	includeAudit := c.CanReadAudit && (f.Source == "" || f.Source == string(SourceAudit))

	// suppressed legs are the ones whose rows would have matched the
	// filters but are excluded by RBAC.
	suppressAlerts := !c.CanReadAlerts && (f.Source == "" || f.Source == string(SourceAlert))
	suppressTxn := !c.CanReadHosts && (f.Source == "" || f.Source == string(SourceTransaction))
	suppressIntel := !c.CanReadHosts && (f.Source == "" || f.Source == string(SourceIntelligence))
	suppressAudit := !c.CanReadAudit && (f.Source == "" || f.Source == string(SourceAudit))

	rows, err := s.queryUnion(ctx, f, includeAlerts, includeTxn, includeIntel, includeAudit)
	if err != nil {
		return nil, 0, "", err
	}
	cursor := ""
	if len(rows) == f.Limit {
		cursor = rows[len(rows)-1].OccurredAt.Format(time.RFC3339Nano)
	}

	hidden := 0
	if suppressAlerts || suppressTxn || suppressIntel || suppressAudit {
		hidden, err = s.countHidden(ctx, f, suppressAlerts, suppressTxn, suppressIntel, suppressAudit)
		if err != nil {
			return nil, 0, "", err
		}
	}
	return rows, hidden, cursor, nil
}

// queryUnion builds and runs the single UNION query. The per-leg
// include flags swap that leg's SELECT for SELECT WHERE FALSE so the
// planner skips it without changing the column shape.
func (s *Service) queryUnion(ctx context.Context, f Filter, includeAlerts, includeTxn, includeIntel, includeAudit bool) ([]Row, error) {
	// Build per-leg filter expressions (severity, time range, host,
	// cursor) once and inject them into each leg via a placeholder
	// counter. We pass the same args in the same order to every leg
	// — Postgres allows reusing $N positions across SELECTs in a UNION.
	args := []any{}
	idx := 1
	addArg := func(v any) string {
		args = append(args, v)
		ph := "$" + itoa(idx)
		idx++
		return ph
	}
	severityPH := ""
	if f.Severity != "" {
		severityPH = addArg(f.Severity)
	}
	sincePH := ""
	if f.Since != nil {
		sincePH = addArg(*f.Since)
	}
	untilPH := ""
	if f.Until != nil {
		untilPH = addArg(*f.Until)
	}
	hostPH := ""
	if f.HostID != nil && *f.HostID != uuid.Nil {
		hostPH = addArg(*f.HostID)
	}
	cursorPH := ""
	if f.Cursor != "" {
		if t, err := time.Parse(time.RFC3339Nano, f.Cursor); err == nil {
			cursorPH = addArg(t)
		}
	}
	limitPH := addArg(f.Limit)

	// commonWhere is the per-leg filter snippet. timeCol is the column
	// each leg uses as the "when" timestamp (occurred_at uniformly,
	// but kept as a parameter in case a future source uses detected_at).
	commonWhere := func(severityCol, timeCol, hostCol string, hostNullable bool) string {
		parts := []string{}
		if severityPH != "" {
			parts = append(parts, severityCol+" = "+severityPH)
		}
		if sincePH != "" {
			parts = append(parts, timeCol+" >= "+sincePH)
		}
		if untilPH != "" {
			parts = append(parts, timeCol+" < "+untilPH)
		}
		if hostPH != "" {
			if hostNullable {
				parts = append(parts, hostCol+" = "+hostPH)
			} else {
				parts = append(parts, hostCol+" = "+hostPH)
			}
		}
		if cursorPH != "" {
			parts = append(parts, timeCol+" < "+cursorPH)
		}
		if len(parts) == 0 {
			return ""
		}
		return " AND " + strings.Join(parts, " AND ")
	}

	legs := []string{}
	if includeAlerts {
		legs = append(legs, `
			SELECT id::text AS id, 'alert' AS source, severity, host_id,
			       title AS title,
			       COALESCE(body, '') AS summary,
			       occurred_at
			  FROM alerts
			 WHERE state != 'dismissed'`+
			commonWhere("severity", "occurred_at", "host_id", true))
	}
	if includeTxn {
		legs = append(legs, `
			SELECT id::text AS id, 'transaction' AS source,
			       COALESCE(severity, 'info') AS severity,
			       host_id,
			       rule_id AS title,
			       COALESCE(change_kind, '') AS summary,
			       occurred_at
			  FROM transactions
			 WHERE 1=1`+
			commonWhere("COALESCE(severity, 'info')", "occurred_at", "host_id", false))
	}
	if includeIntel {
		legs = append(legs, `
			SELECT id::text AS id, 'intelligence' AS source,
			       severity, host_id,
			       event_code AS title,
			       '' AS summary,
			       occurred_at
			  FROM host_intelligence_events
			 WHERE 1=1`+
			commonWhere("severity", "occurred_at", "host_id", false))
	}
	if includeAudit {
		// audit_events severity is info|warning|error|critical — map
		// warning -> medium, error -> high, others pass through.
		auditSev := `CASE severity
		                WHEN 'warning' THEN 'medium'
		                WHEN 'error' THEN 'high'
		                ELSE COALESCE(severity, 'info')
		            END`
		legs = append(legs, `
			SELECT id::text AS id, 'audit' AS source,
			       `+auditSev+` AS severity,
			       NULL::uuid AS host_id,
			       action AS title,
			       COALESCE(resource_id, '') AS summary,
			       occurred_at
			  FROM audit_events
			 WHERE 1=1`+
			commonWhere(auditSev, "occurred_at", "''", true))
	}

	if len(legs) == 0 {
		return nil, nil
	}

	// Spec C-01: single Query. UNION ALL across legs + final
	// ORDER BY + LIMIT.
	q := strings.Join(legs, "\n\t\t\tUNION ALL\n") + `
		 ORDER BY occurred_at DESC LIMIT ` + limitPH

	pgRows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("activity: query: %w", err)
	}
	defer pgRows.Close()
	out := []Row{}
	for pgRows.Next() {
		var (
			r        Row
			idStr    string
			source   string
			severity string
			hostID   *uuid.UUID
		)
		if err := pgRows.Scan(&idStr, &source, &severity, &hostID, &r.Title, &r.Summary, &r.OccurredAt); err != nil {
			return nil, fmt.Errorf("activity: scan: %w", err)
		}
		id, _ := uuid.Parse(idStr)
		r.ID = id
		r.Source = Source(source)
		r.Severity = Severity(severity)
		r.HostID = hostID
		out = append(out, r)
	}
	return out, pgRows.Err()
}

// countHidden tallies the rows the caller WOULD have seen if RBAC had
// not suppressed them. Returns 0 when no legs are suppressed.
func (s *Service) countHidden(ctx context.Context, f Filter, supAlerts, supTxn, supIntel, supAudit bool) (int, error) {
	args := []any{}
	idx := 1
	addArg := func(v any) string {
		args = append(args, v)
		ph := "$" + itoa(idx)
		idx++
		return ph
	}
	severityPH := ""
	if f.Severity != "" {
		severityPH = addArg(f.Severity)
	}
	sincePH := ""
	if f.Since != nil {
		sincePH = addArg(*f.Since)
	}
	untilPH := ""
	if f.Until != nil {
		untilPH = addArg(*f.Until)
	}
	hostPH := ""
	if f.HostID != nil && *f.HostID != uuid.Nil {
		hostPH = addArg(*f.HostID)
	}
	cursorPH := ""
	if f.Cursor != "" {
		if t, err := time.Parse(time.RFC3339Nano, f.Cursor); err == nil {
			cursorPH = addArg(t)
		}
	}

	commonWhere := func(severityCol, timeCol, hostCol string) string {
		parts := []string{}
		if severityPH != "" {
			parts = append(parts, severityCol+" = "+severityPH)
		}
		if sincePH != "" {
			parts = append(parts, timeCol+" >= "+sincePH)
		}
		if untilPH != "" {
			parts = append(parts, timeCol+" < "+untilPH)
		}
		if hostPH != "" {
			parts = append(parts, hostCol+" = "+hostPH)
		}
		if cursorPH != "" {
			parts = append(parts, timeCol+" < "+cursorPH)
		}
		if len(parts) == 0 {
			return ""
		}
		return " AND " + strings.Join(parts, " AND ")
	}

	parts := []string{}
	if supAlerts {
		parts = append(parts, `SELECT count(*) FROM alerts WHERE state != 'dismissed'`+
			commonWhere("severity", "occurred_at", "host_id"))
	}
	if supTxn {
		parts = append(parts, `SELECT count(*) FROM transactions WHERE 1=1`+
			commonWhere("COALESCE(severity, 'info')", "occurred_at", "host_id"))
	}
	if supIntel {
		parts = append(parts, `SELECT count(*) FROM host_intelligence_events WHERE 1=1`+
			commonWhere("severity", "occurred_at", "host_id"))
	}
	if supAudit {
		auditSev := `CASE severity WHEN 'warning' THEN 'medium' WHEN 'error' THEN 'high' ELSE COALESCE(severity, 'info') END`
		parts = append(parts, `SELECT count(*) FROM audit_events WHERE 1=1`+
			commonWhere(auditSev, "occurred_at", "''"))
	}
	if len(parts) == 0 {
		return 0, nil
	}

	q := "SELECT (" + strings.Join(parts, ") + (") + ")"
	var total int
	if err := s.pool.QueryRow(ctx, q, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("activity: count hidden: %w", err)
	}
	return total, nil
}

// itoa is a small base-10 stringifier so service.go doesn't import strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
