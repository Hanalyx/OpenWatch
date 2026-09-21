// Audit log export — GET /api/v1/audit/events/export. Downloads the
// filtered audit trail as a CSV or JSON attachment (NIST 800-53 AU-7 audit
// reduction + report generation). Reuses the list query (queryEvents) with
// the shared filters, capped at auditExportCap rows, so the export covers
// the whole filtered set — not just one page. Spec api-audit-events-query.

package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// auditExportCap bounds an export so a huge trail can't stream unbounded.
// Beyond this, operators page the list endpoint or narrow the filters; the
// cap is logged + flagged (X-OpenWatch-Export-Truncated) so a truncated export is never silently mistaken for "all".
const auditExportCap = 10000

// auditExportParams is the query surface the export declares in
// api/openapi.yaml, one entry per parameter of getAuditEventsExport. The
// contract-coverage test keeps it equal to the declaration.
var auditExportParams = map[string]struct{}{
	"format": {}, "action": {}, "correlation_id": {}, "actor_type": {},
	"resource_type": {}, "resource_id": {}, "since": {}, "until": {},
}

// firstUnknownQueryParam returns the first query key not in allowed, in
// the request's own order, or "" when every key is declared.
func firstUnknownQueryParam(r *http.Request, allowed map[string]struct{}) string {
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		if pair == "" {
			continue
		}
		key := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			key = pair[:i]
		}
		if unescaped, err := url.QueryUnescape(key); err == nil {
			key = unescaped
		}
		if _, ok := allowed[key]; !ok {
			return key
		}
	}
	return ""
}

// GetAuditEventsExport streams the filtered audit events as a downloadable
// CSV (default) or JSON file. audit:export gated, independently of the
// audit:read list (v1.4.0; audit:read through 1.3.1, which let every reader
// export, CP bugs/OW-056). Spec api-audit-events-query C-08 / AC-13 / AC-16.
func (h *handlers) GetAuditEventsExport(w http.ResponseWriter, r *http.Request, params api.GetAuditEventsExportParams) {
	if denied := auth.EnforcePermission(w, r, auth.AuditExport); denied {
		return
	}

	// A filter the export does not declare is rejected, never ignored. The
	// generated router drops unknown query parameters silently, and for
	// this route that turns a misspelled filter into an export of the
	// whole trail that the caller files as if it were the narrow one. The
	// list endpoint stays lenient; the strictness is this route's alone
	// (v1.5.0, CP bugs/OW-064).
	if unknown := firstUnknownQueryParam(r, auditExportParams); unknown != "" {
		writeError(w, http.StatusBadRequest, "request.unknown_parameter", "client",
			"the export does not accept the "+unknown+" parameter", false)
		return
	}

	// Reuse the list query with the same filters at the export cap.
	lp := api.GetAuditEventsParams{
		Action:        params.Action,
		CorrelationId: params.CorrelationId,
		ActorType:     params.ActorType,
		ResourceType:  params.ResourceType,
		ResourceId:    params.ResourceId,
		Since:         params.Since,
		Until:         params.Until,
	}
	rows, err := h.queryEvents(r.Context(), lp, auditExportCap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.internal", "server",
			"failed to query audit events for export", true)
		return
	}

	// A capped export is byte-indistinguishable from a complete one — for an
	// AU-7 audit-reduction artifact that would silently misrepresent "all".
	// Mark a truncated export with a header AND a server log so it is never
	// mistaken for the full trail.
	truncated := len(rows) >= auditExportCap
	if truncated {
		w.Header().Set("X-OpenWatch-Export-Truncated", "true")
		slog.WarnContext(r.Context(), "audit export truncated at cap",
			slog.Int("cap", auditExportCap))
	}

	stamp := time.Now().UTC().Format("20060102-150405")

	if params.Format != nil && *params.Format == api.GetAuditEventsExportParamsFormatJson {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", "audit-log-"+stamp+".json"))
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return
	}

	// CSV (default). One header row + one row per event. The detail JSONB
	// is intentionally omitted from CSV (it is already redacted at write
	// time and does not flatten to a cell); JSON export carries it.
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "audit-log-"+stamp+".csv"))
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"occurred_at", "action", "message", "severity",
		"actor_type", "actor_label", "actor_id",
		"resource_type", "resource_id", "correlation_id",
	})
	for _, ev := range rows {
		// csvSafe neutralizes spreadsheet formula injection on every cell.
		_ = cw.Write([]string{
			ev.OccurredAt.Format(time.RFC3339),
			csvSafe(ev.Action),
			csvSafe(deref(ev.Message)),
			csvSafe(deref(ev.Severity)),
			csvSafe(ev.ActorType),
			csvSafe(deref(ev.ActorLabel)),
			csvSafe(deref(ev.ActorId)),
			csvSafe(deref(ev.ResourceType)),
			csvSafe(deref(ev.ResourceId)),
			csvSafe(ev.CorrelationId),
		})
	}
	cw.Flush()
}

// csvSafe neutralizes spreadsheet formula injection (CWE-1236). A cell whose
// first character is =, +, -, @, or a tab/CR is executed as a formula by
// Excel / Google Sheets / LibreOffice when the export is opened. Prefixing
// such a cell with a single quote forces it to render as literal text.
// encoding/csv handles CSV quoting but does NOT neutralize this.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
