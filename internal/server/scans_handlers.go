// Scans HTTP surface: the durable, point-in-time scan history and its
// per-rule evidence + OSCAL export. This is the SANCTIONED home for
// compliance evidence — the raw check output the host-detail Compliance
// tab deliberately omits (api-host-compliance C-02) is exposed here,
// gated by scan:read, so a compliance officer reads a historical scan's
// proof at /scans without needing host:read.
//
// Reads come from internal/scanresult (scan_results + content-addressed
// scan_evidence); OSCAL is reconstructed on demand via Kensa's exporter.
//
// Spec: api-scans.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	kensapkg "github.com/Hanalyx/kensa/pkg/kensa"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/scanresult"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// scanResultsReady guards every scans handler: 503 when the read service
// is not wired (mirrors reportSvcReady).
func (h *handlers) scanResultsReady(w http.ResponseWriter) bool {
	if h.scanResultSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"scan results service not wired", true)
		return false
	}
	return true
}

// GetScans lists a host's scans newest first. Spec api-scans.
func (h *handlers) GetScans(w http.ResponseWriter, r *http.Request, params api.GetScansParams) {
	if denied := auth.EnforcePermission(w, r, auth.ScanRead); denied {
		return
	}
	if !h.scanResultsReady(w) {
		return
	}
	ctx := r.Context()
	hostID := uuid.UUID(params.HostId)

	if _, err := h.hosts.GetByID(ctx, hostID); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client", "host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "host lookup failed", true)
		return
	}

	limit := 20
	if params.Limit != nil {
		limit = *params.Limit
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	var cursor time.Time
	if params.Cursor != nil {
		cursor = *params.Cursor
	}

	rows, next, err := h.scanResultSvc.ListByHost(ctx, hostID, limit, cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "scan list failed", true)
		return
	}
	resp := api.ScanList{Scans: []api.ScanSummary{}}
	for _, s := range rows {
		resp.Scans = append(resp.Scans, toAPIScanSummary(s))
	}
	if !next.IsZero() {
		n := next
		resp.NextCursor = &n
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetScanById returns a scan's metadata + per-rule results. Spec api-scans.
func (h *handlers) GetScanById(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.ScanRead); denied {
		return
	}
	if !h.scanResultsReady(w) {
		return
	}
	ctx := r.Context()
	scanID := uuid.UUID(id)

	summary, err := h.scanResultSvc.GetScan(ctx, scanID)
	if err != nil {
		if errors.Is(err, scanresult.ErrScanNotFound) {
			writeError(w, http.StatusNotFound, "scans.not_found", "client", "scan not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "scan lookup failed", true)
		return
	}
	results, err := h.scanResultSvc.ScanResults(ctx, scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "scan results failed", true)
		return
	}
	resp := api.ScanDetail{Scan: toAPIScanSummary(summary), Results: []api.ScanRuleResult{}}
	for _, rr := range results {
		// Resolve the human title, category, and one-line description from
		// the rule catalog (same source the host compliance lens uses);
		// fall back to rule_id / "uncategorized" when the catalog has no
		// entry. Catalog text only, never stored check output.
		title, category, description := rr.RuleID, "uncategorized", ""
		if meta, ok := h.ruleCatalog.Get(rr.RuleID); ok {
			title = meta.Title
			if meta.Category != "" {
				category = meta.Category
			}
			description = firstSentence(meta.Description)
		}
		out := api.ScanRuleResult{
			RuleId:        rr.RuleID,
			Title:         title,
			Category:      category,
			Status:        rr.Status,
			Severity:      rr.Severity,
			FrameworkRefs: rr.FrameworkRefs,
			HasEvidence:   rr.HasEvidence,
		}
		if description != "" {
			d := description
			out.Description = &d
		}
		if rr.SkipReason != "" {
			s := rr.SkipReason
			out.SkipReason = &s
		}
		resp.Results = append(resp.Results, out)
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetScanRuleEvidence returns one rule's full evidence for a scan — the
// drill-down payload (Formatted + Evidence views). Spec api-scans.
func (h *handlers) GetScanRuleEvidence(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, ruleId string) {
	if denied := auth.EnforcePermission(w, r, auth.ScanRead); denied {
		return
	}
	if !h.scanResultsReady(w) {
		return
	}
	d, err := h.scanResultSvc.RuleEvidence(r.Context(), uuid.UUID(id), ruleId)
	if err != nil {
		if errors.Is(err, scanresult.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "scans.not_found", "client", "scan or rule not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "rule evidence failed", true)
		return
	}
	resp := api.ScanRuleEvidence{
		RuleId:        d.RuleID,
		Status:        d.Status,
		Severity:      d.Severity,
		Detail:        d.Detail,
		Checks:        toAPIChecks(d.Checks),
		FrameworkRefs: d.FrameworkRefs,
	}
	if d.Error != "" {
		e := d.Error
		resp.Error = &e
	}
	if d.SkipReason != "" {
		s := d.SkipReason
		resp.SkipReason = &s
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetScanRuleOSCAL streams one rule's outcome as an OSCAL 1.0.6
// Assessment Results document. Spec api-scans.
func (h *handlers) GetScanRuleOSCAL(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, ruleId string) {
	if denied := auth.EnforcePermission(w, r, auth.ScanRead); denied {
		return
	}
	if !h.scanResultsReady(w) {
		return
	}
	ctx := r.Context()
	scanID := uuid.UUID(id)

	hostname, ok := h.scanHostname(w, ctx, scanID)
	if !ok {
		return
	}
	outcome, err := h.scanResultSvc.ReconstructOutcome(ctx, scanID, ruleId)
	if err != nil {
		if errors.Is(err, scanresult.ErrRuleNotFound) || errors.Is(err, scanresult.ErrScanNotFound) {
			writeError(w, http.StatusNotFound, "scans.not_found", "client", "scan or rule not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "oscal reconstruct failed", true)
		return
	}
	doc, err := kensapkg.ExportOSCALOutcome(nil, outcome, hostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "oscal export failed", true)
		return
	}
	writeOSCAL(w, doc, fmt.Sprintf("oscal-%s-%s.json", scanID, ruleId))
}

// GetScanOSCAL streams a whole scan as an OSCAL 1.0.6 Assessment Results
// document. Spec api-scans.
func (h *handlers) GetScanOSCAL(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.ScanRead); denied {
		return
	}
	if !h.scanResultsReady(w) {
		return
	}
	ctx := r.Context()
	scanID := uuid.UUID(id)

	hostname, ok := h.scanHostname(w, ctx, scanID)
	if !ok {
		return
	}
	outcomes, err := h.scanResultSvc.ReconstructScan(ctx, scanID)
	if err != nil {
		if errors.Is(err, scanresult.ErrScanNotFound) {
			writeError(w, http.StatusNotFound, "scans.not_found", "client", "scan not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "oscal reconstruct failed", true)
		return
	}
	// Whole-scan ExportOSCALScan dereferences result.Outcomes — needs a
	// non-nil ScanResult (per-rule tolerates a nil scan; this does not).
	result := &kensaapi.ScanResult{HostID: scanID.String(), Outcomes: outcomes}
	doc, err := kensapkg.ExportOSCALScan(result, hostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "oscal export failed", true)
		return
	}
	writeOSCAL(w, doc, fmt.Sprintf("oscal-%s.json", scanID))
}

// scanHostname resolves the scan's host hostname for the OSCAL document,
// writing the appropriate 404/500 and returning ok=false on failure.
func (h *handlers) scanHostname(w http.ResponseWriter, ctx context.Context, scanID uuid.UUID) (string, bool) {
	summary, err := h.scanResultSvc.GetScan(ctx, scanID)
	if err != nil {
		if errors.Is(err, scanresult.ErrScanNotFound) {
			writeError(w, http.StatusNotFound, "scans.not_found", "client", "scan not found", false)
			return "", false
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "scan lookup failed", true)
		return "", false
	}
	hostRow, err := h.hosts.GetByID(ctx, summary.HostID)
	if err != nil {
		// The scan exists but its host was removed (FK is RESTRICT, so this
		// is unexpected) — fall back to the host id as the OSCAL subject.
		return summary.HostID.String(), true
	}
	return hostRow.Hostname, true
}

// toAPIScanSummary maps a reader summary to the wire shape.
func toAPIScanSummary(s scanresult.ScanSummary) api.ScanSummary {
	out := api.ScanSummary{
		ScanId:        openapi_types.UUID(s.ScanID),
		HostId:        openapi_types.UUID(s.HostID),
		Status:        s.Status,
		TriggerSource: s.TriggerSource,
		QueuedAt:      s.QueuedAt,
		PolicyVersion: s.PolicyVersion,
		RulesPass:     s.RulesPass,
		RulesFail:     s.RulesFail,
		RulesSkipped:  s.RulesSkipped,
		RulesError:    s.RulesError,
	}
	out.StartedAt = s.StartedAt
	out.FinishedAt = s.FinishedAt
	return out
}

// toAPIChecks maps kensa CheckEvidence to the wire shape, lifting the
// always-present fields and pointer-wrapping the optional ones.
func toAPIChecks(checks []kensaapi.CheckEvidence) []api.ScanCheckEvidence {
	out := make([]api.ScanCheckEvidence, 0, len(checks))
	for _, c := range checks {
		ev := api.ScanCheckEvidence{Method: c.Method, ExitCode: c.ExitCode}
		if c.Command != "" {
			v := c.Command
			ev.Command = &v
		}
		if c.Stdout != "" {
			v := c.Stdout
			ev.Stdout = &v
		}
		if c.Stderr != "" {
			v := c.Stderr
			ev.Stderr = &v
		}
		if c.Expected != "" {
			v := c.Expected
			ev.Expected = &v
		}
		if c.Actual != "" {
			v := c.Actual
			ev.Actual = &v
		}
		if c.Truncated {
			v := c.Truncated
			ev.Truncated = &v
		}
		out = append(out, ev)
	}
	return out
}

// writeOSCAL writes a verbatim OSCAL JSON document as a downloadable
// attachment (kensa already produced canonical JSON; do not re-encode).
func writeOSCAL(w http.ResponseWriter, doc []byte, filename string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}
