// Reports HTTP surface: the Reports library (list + fetch) and the
// "Generate report" action. Thin handlers over internal/report - RBAC
// (host:read for reads, host:write for generate), error-to-status
// mapping, and report.Report -> api.Report wire shaping live here; the
// posture computation lives in the service.
//
// MVP: generate produces exactly one kind, the Fleet Compliance
// Executive Summary, for all hosts. Signing, PDF/OSCAL rendering, the
// Scheduled dispatcher and the Templates gallery are deferred.
//
// Spec: api-reports.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/report"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// toAPIReport maps a service report to the wire shape. content is stored
// as raw JSON; it is decoded into a generic map for the response object.
func toAPIReport(rep report.Report) (api.Report, error) {
	content := map[string]interface{}{}
	if len(rep.Content) > 0 {
		if err := json.Unmarshal(rep.Content, &content); err != nil {
			return api.Report{}, err
		}
	}
	return api.Report{
		Id:          openapitypes.UUID(rep.ID),
		Title:       rep.Title,
		Kind:        api.ReportKind(rep.Kind),
		ScopeLabel:  rep.ScopeLabel,
		DataAsOf:    rep.DataAsOf,
		GeneratedBy: rep.GeneratedBy,
		Format:      rep.Format,
		Content:     content,
		CreatedAt:   rep.CreatedAt,
	}, nil
}

// reportSvcReady guards every handler: 503 when the service is not wired.
func (h *handlers) reportSvcReady(w http.ResponseWriter) bool {
	if h.reportSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"report service not wired", true)
		return false
	}
	return true
}

// reportActor returns the human-readable identifier recorded on a
// generated artifact (the calling principal's id, or "system" when the
// request is anonymous).
func reportActor(r *http.Request) string {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous || id.ID == "" {
		return "system"
	}
	return id.ID
}

// GetReports implements api.ServerInterface.
// Spec api-reports.
func (h *handlers) GetReports(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if !h.reportSvcReady(w) {
		return
	}
	reports, err := h.reportSvc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"report list failed", true)
		return
	}
	resp := api.ReportListResponse{Reports: []api.Report{}}
	for _, rep := range reports {
		out, err := toAPIReport(rep)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"report content decode failed", true)
			return
		}
		resp.Reports = append(resp.Reports, out)
	}
	writeJSON(w, http.StatusOK, resp)
}

// PostReportGenerate implements api.ServerInterface.
// Spec api-reports.
func (h *handlers) PostReportGenerate(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.reportSvcReady(w) {
		return
	}
	rep, err := h.reportSvc.Generate(r.Context(), reportActor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"report generation failed", true)
		return
	}
	out, err := toAPIReport(rep)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"report content decode failed", true)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// GetReportByID implements api.ServerInterface.
// Spec api-reports.
func (h *handlers) GetReportByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if !h.reportSvcReady(w) {
		return
	}
	rep, err := h.reportSvc.Get(r.Context(), id)
	if errors.Is(err, report.ErrNotFound) {
		writeError(w, http.StatusNotFound, "reports.not_found", "client",
			"report not found", false)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"report fetch failed", true)
		return
	}
	out, err := toAPIReport(rep)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"report content decode failed", true)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
