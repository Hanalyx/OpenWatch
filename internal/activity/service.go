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
	pool   *pgxpool.Pool
	titler RuleTitleFunc // optional; resolves rule_id -> title for the compliance leg
}

// NewService binds a Service to a pgxpool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// WithRuleTitler injects the rule-id -> title resolver used to render the
// compliance (transaction) leg's headline. Nil-safe; without it the leg
// falls back to the raw rule id. Returns the Service for chaining.
func (s *Service) WithRuleTitler(f RuleTitleFunc) *Service {
	s.titler = f
	return s
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
	includeMonitoring := c.CanReadHosts && (f.Source == "" || f.Source == string(SourceMonitoring))

	// suppressed legs are the ones whose rows would have matched the
	// filters but are excluded by RBAC.
	suppressAlerts := !c.CanReadAlerts && (f.Source == "" || f.Source == string(SourceAlert))
	suppressTxn := !c.CanReadHosts && (f.Source == "" || f.Source == string(SourceTransaction))
	suppressIntel := !c.CanReadHosts && (f.Source == "" || f.Source == string(SourceIntelligence))
	suppressAudit := !c.CanReadAudit && (f.Source == "" || f.Source == string(SourceAudit))
	suppressMonitoring := !c.CanReadHosts && (f.Source == "" || f.Source == string(SourceMonitoring))

	// Fetch limit+1 internally so we can tell whether this is the
	// last page. If we got back exactly limit+1 rows, there's at
	// least one more row beyond; trim it off and emit the cursor.
	// Spec C-03 / AC-08.
	rows, err := s.queryUnion(ctx, f, includeAlerts, includeTxn, includeIntel, includeAudit, includeMonitoring)
	if err != nil {
		return nil, 0, "", err
	}
	cursor := ""
	if len(rows) > f.Limit {
		cursor = rows[f.Limit-1].OccurredAt.Format(time.RFC3339Nano)
		rows = rows[:f.Limit]
	}

	hidden := 0
	if suppressAlerts || suppressTxn || suppressIntel || suppressAudit || suppressMonitoring {
		hidden, err = s.countHidden(ctx, f, suppressAlerts, suppressTxn, suppressIntel, suppressAudit, suppressMonitoring)
		if err != nil {
			return nil, 0, "", err
		}
	}
	return rows, hidden, cursor, nil
}

// queryUnion builds and runs the single UNION query. The per-leg
// include flags swap that leg's SELECT for SELECT WHERE FALSE so the
// planner skips it without changing the column shape.
func (s *Service) queryUnion(ctx context.Context, f Filter, includeAlerts, includeTxn, includeIntel, includeAudit, includeMonitoring bool) ([]Row, error) {
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
	// Fetch limit+1 so List can detect the terminal page (Spec C-03).
	limitPH := addArg(f.Limit + 1)

	// commonWhere is the per-leg filter snippet. timeCol is the column
	// each leg uses as the "when" timestamp (occurred_at uniformly,
	// but kept as a parameter in case a future source uses detected_at).
	// hasHostCol=false means the leg has no host_id column (e.g.
	// audit_events) and MUST be excluded when a host_id filter is
	// applied — emitting a FALSE predicate keeps the column shape of
	// the UNION while skipping every row. The previous shape passed
	// hostCol="''" and "''=$hostPH" which crashed Postgres with
	// `invalid input syntax for type uuid: ""` whenever host_id was
	// set (the parameter is a uuid.UUID and PG won't cast '' to uuid).
	commonWhere := func(severityCol, timeCol, hostCol string, hasHostCol bool) string {
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
			if hasHostCol {
				parts = append(parts, hostCol+" = "+hostPH)
			} else {
				parts = append(parts, "FALSE")
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

	// Every leg emits the same column shape. The last five columns are
	// carriers for the Go enrichment pass (enrichRows): `code` plus three
	// text contexts and a jsonb detail. The alert + monitoring legs already
	// build their title/summary in SQL, so they leave the carriers empty
	// and the enrichment pass skips them. Spec system-activity C-09.
	const emptyCarriers = `, '' AS code, '' AS ctx_a, '' AS ctx_b, '' AS ctx_c, NULL::jsonb AS detail`
	legs := []string{}
	if includeAlerts {
		legs = append(legs, `
			SELECT id::text AS id, 'alert' AS source, severity, host_id,
			       title AS title,
			       COALESCE(body, '') AS summary,
			       occurred_at`+emptyCarriers+`
			  FROM alerts
			 WHERE state != 'dismissed'`+
			commonWhere("severity", "occurred_at", "host_id", true /* hasHostCol */))
	}
	if includeTxn {
		// title/summary are rebuilt in Go from code(rule_id) + ctx_a(status)
		// + ctx_b(change_kind) via the rule titler. The SQL title/summary
		// here are placeholders the enrichment pass overwrites.
		legs = append(legs, `
			SELECT id::text AS id, 'transaction' AS source,
			       COALESCE(severity, 'info') AS severity,
			       host_id,
			       rule_id AS title,
			       COALESCE(change_kind, '') AS summary,
			       occurred_at,
			       rule_id AS code, status AS ctx_a,
			       COALESCE(change_kind, '') AS ctx_b, '' AS ctx_c,
			       NULL::jsonb AS detail
			  FROM transactions
			 WHERE 1=1`+
			commonWhere("COALESCE(severity, 'info')", "occurred_at", "host_id", true /* hasHostCol */))
	}
	if includeIntel {
		// title/summary rebuilt in Go from code(event_code) + detail JSONB.
		legs = append(legs, `
			SELECT id::text AS id, 'intelligence' AS source,
			       severity, host_id,
			       event_code AS title,
			       '' AS summary,
			       occurred_at,
			       event_code AS code, '' AS ctx_a, '' AS ctx_b, '' AS ctx_c,
			       detail AS detail
			  FROM host_intelligence_events
			 WHERE 1=1`+
			commonWhere("severity", "occurred_at", "host_id", true /* hasHostCol */))
	}
	if includeAudit {
		// audit_events severity is info|warning|error|critical — map
		// warning -> medium, error -> high, others pass through.
		auditSev := `CASE severity
		                WHEN 'warning' THEN 'medium'
		                WHEN 'error' THEN 'high'
		                ELSE COALESCE(severity, 'info')
		            END`
		// title/summary rebuilt in Go from code(action) + ctx_a(actor_label)
		// + ctx_b(actor_type) + ctx_c(resource_type). resource_id (a UUID)
		// is deliberately not surfaced in the headline.
		legs = append(legs, `
			SELECT id::text AS id, 'audit' AS source,
			       `+auditSev+` AS severity,
			       NULL::uuid AS host_id,
			       action AS title,
			       COALESCE(resource_id, '') AS summary,
			       occurred_at,
			       action AS code, COALESCE(actor_label, '') AS ctx_a,
			       actor_type AS ctx_b, COALESCE(resource_type, '') AS ctx_c,
			       NULL::jsonb AS detail
			  FROM audit_events
			 WHERE 1=1`+
			commonWhere(auditSev, "occurred_at", "", false))
	}
	if includeMonitoring {
		// host_monitoring_history.id is a bigint sequence. The unified
		// Row.ID is a uuid, so we synthesize a stable uuid from the
		// bigint: a constant 'monitoring' prefix in the first 16 hex
		// chars and the bigint (lpad'd to 12 hex chars) in the last 12.
		// 12 hex chars = 48 bits = 281T, which we won't hit before the
		// retention sweep prunes the history.
		//
		// monitoringSeverity collapses the multi-layer band onto the
		// closed severity enum.
		monSev := `CASE monitoring_state
		                WHEN 'down' THEN 'critical'
		                WHEN 'critical' THEN 'high'
		                WHEN 'degraded' THEN 'medium'
		                WHEN 'online' THEN 'info'
		                WHEN 'maintenance' THEN 'info'
		                ELSE 'info'
		            END`
		// monitoringTitle derives the operator-readable headline from
		// the (previous_state, monitoring_state) pair.
		monTitle := `CASE monitoring_state
		                  WHEN 'down' THEN 'Host became unreachable'
		                  WHEN 'critical' THEN 'Host critical'
		                  WHEN 'degraded' THEN 'Host degraded'
		                  WHEN 'online' THEN
		                      CASE WHEN previous_state IS NOT NULL
		                           THEN 'Host recovered'
		                           ELSE 'Host online' END
		                  WHEN 'maintenance' THEN 'Maintenance mode enabled'
		                  ELSE 'Monitoring state changed'
		              END`
		// monitoringSummary surfaces the failure context. error_message
		// is preferred (the SSH / probe error text); failed_layer is a
		// terse fallback like "ssh fail".
		monSummary := `CASE
		                    WHEN error_message IS NOT NULL AND error_message <> ''
		                        THEN error_message
		                    WHEN failed_layer IS NOT NULL AND failed_layer <> ''
		                        THEN failed_layer || ' fail'
		                    ELSE ''
		                END`
		legs = append(legs, `
			SELECT ('00000000-0000-7000-8000-' || lpad(to_hex(id), 12, '0'))::uuid::text AS id,
			       'monitoring' AS source,
			       `+monSev+` AS severity,
			       host_id,
			       `+monTitle+` AS title,
			       `+monSummary+` AS summary,
			       check_time AS occurred_at`+emptyCarriers+`
			  FROM host_monitoring_history
			 WHERE (previous_state IS NULL OR monitoring_state <> previous_state)`+
			commonWhere(monSev, "check_time", "host_id", true))
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
			r                      Row
			idStr                  string
			source                 string
			severity               string
			hostID                 *uuid.UUID
			code, ctxA, ctxB, ctxC string
			detail                 []byte
		)
		if err := pgRows.Scan(&idStr, &source, &severity, &hostID,
			&r.Title, &r.Summary, &r.OccurredAt,
			&code, &ctxA, &ctxB, &ctxC, &detail); err != nil {
			return nil, fmt.Errorf("activity: scan: %w", err)
		}
		id, _ := uuid.Parse(idStr)
		r.ID = id
		r.Source = Source(source)
		r.Severity = Severity(severity)
		r.HostID = hostID
		// Rebuild title/summary in Go for the three legs that carry raw
		// codes (the alert + monitoring legs leave the carriers empty and
		// keep their SQL-built text). Spec C-09.
		switch r.Source {
		case SourceTransaction:
			r.Title, r.Summary = formatTransaction(code, ctxA, ctxB, s.titler)
		case SourceIntelligence:
			r.Title, r.Summary = formatIntelligence(code, detail)
		case SourceAudit:
			r.Title, r.Summary = FormatAudit(code, ctxA, ctxB, ctxC)
		}
		out = append(out, r)
	}
	return out, pgRows.Err()
}

// countHidden tallies the rows the caller WOULD have seen if RBAC had
// not suppressed them. Returns 0 when no legs are suppressed.
func (s *Service) countHidden(ctx context.Context, f Filter, supAlerts, supTxn, supIntel, supAudit, supMonitoring bool) (int, error) {
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

	// Mirrors queryUnion.commonWhere — hasHostCol=false makes the leg
	// evaluate to FALSE when a host_id filter is applied, avoiding the
	// `'' = $uuid` type-cast crash on the audit leg.
	commonWhere := func(severityCol, timeCol, hostCol string, hasHostCol bool) string {
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
			if hasHostCol {
				parts = append(parts, hostCol+" = "+hostPH)
			} else {
				parts = append(parts, "FALSE")
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

	parts := []string{}
	if supAlerts {
		parts = append(parts, `SELECT count(*) FROM alerts WHERE state != 'dismissed'`+
			commonWhere("severity", "occurred_at", "host_id", true))
	}
	if supTxn {
		parts = append(parts, `SELECT count(*) FROM transactions WHERE 1=1`+
			commonWhere("COALESCE(severity, 'info')", "occurred_at", "host_id", true))
	}
	if supIntel {
		parts = append(parts, `SELECT count(*) FROM host_intelligence_events WHERE 1=1`+
			commonWhere("severity", "occurred_at", "host_id", true))
	}
	if supAudit {
		auditSev := `CASE severity WHEN 'warning' THEN 'medium' WHEN 'error' THEN 'high' ELSE COALESCE(severity, 'info') END`
		parts = append(parts, `SELECT count(*) FROM audit_events WHERE 1=1`+
			commonWhere(auditSev, "occurred_at", "", false))
	}
	if supMonitoring {
		monSev := `CASE monitoring_state WHEN 'down' THEN 'critical' WHEN 'critical' THEN 'high' WHEN 'degraded' THEN 'medium' WHEN 'online' THEN 'info' WHEN 'maintenance' THEN 'info' ELSE 'info' END`
		parts = append(parts, `SELECT count(*) FROM host_monitoring_history WHERE (previous_state IS NULL OR monitoring_state <> previous_state)`+
			commonWhere(monSev, "check_time", "host_id", true))
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
