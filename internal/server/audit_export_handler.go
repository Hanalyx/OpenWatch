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
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// auditExportCap bounds an export so a huge trail can't stream unbounded.
// Beyond this, operators page the list endpoint or narrow the filters; the
// cap is logged + flagged (X-OpenWatch-Export-Truncated) so a truncated export is never silently mistaken for "all".
const auditExportCap = 10000

// GetAuditEventsExport streams the filtered audit events as a downloadable
// CSV (default) or JSON file. audit:read gated. Spec api-audit-events-query
// v1.3.0 C-08 / AC-13.
func (h *handlers) GetAuditEventsExport(w http.ResponseWriter, r *http.Request, params api.GetAuditEventsExportParams) {
	if denied := auth.EnforcePermission(w, r, auth.AuditRead); denied {
		return
	}

	// Reuse the list query with the same filters at the export cap.
	lp := api.GetAuditEventsParams{
		Action:       params.Action,
		ActorType:    params.ActorType,
		ResourceType: params.ResourceType,
		ResourceId:   params.ResourceId,
		Since:        params.Since,
		Until:        params.Until,
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

	if params.Format != nil && *params.Format == api.Json {
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
