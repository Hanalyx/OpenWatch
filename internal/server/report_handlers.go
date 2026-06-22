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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/group"
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
	out := api.Report{
		Id:            openapitypes.UUID(rep.ID),
		Title:         rep.Title,
		Kind:          api.ReportKind(rep.Kind),
		ScopeLabel:    rep.ScopeLabel,
		Scope:         toAPIReportScope(rep.Scope),
		DataAsOf:      rep.DataAsOf,
		GeneratedBy:   rep.GeneratedBy,
		Format:        rep.Format,
		Content:       content,
		ContentSha256: rep.ContentSHA256,
		CreatedAt:     rep.CreatedAt,
	}
	if len(rep.Signature) > 0 {
		sig := base64.StdEncoding.EncodeToString(rep.Signature)
		out.Signature = &sig
	}
	if rep.SigningKeyID != "" {
		kid := rep.SigningKeyID
		out.SigningKeyId = &kid
	}
	return out, nil
}

// toAPIReportScope maps the stored scope to the wire shape, omitting the
// empty (all-hosts, all-frameworks) fields.
func toAPIReportScope(sc report.Scope) api.ReportScope {
	out := api.ReportScope{}
	if sc.GroupID != nil {
		gid := openapitypes.UUID(*sc.GroupID)
		out.GroupId = &gid
	}
	if sc.GroupName != "" {
		name := sc.GroupName
		out.GroupName = &name
	}
	if sc.Framework != "" {
		fw := sc.Framework
		out.Framework = &fw
	}
	return out
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

// GetReportFrameworks implements api.ServerInterface: lists the framework
// lenses present across the fleet.
// Spec api-reports.
func (h *handlers) GetReportFrameworks(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if !h.reportSvcReady(w) {
		return
	}
	fws, err := h.reportSvc.Frameworks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"framework catalog failed", true)
		return
	}
	resp := api.ReportFrameworksResponse{Frameworks: []api.ReportFramework{}}
	for _, f := range fws {
		resp.Frameworks = append(resp.Frameworks, api.ReportFramework{
			Framework: f.Framework,
			RuleCount: f.RuleCount,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetReportSigningKey implements api.ServerInterface: returns the public
// key for offline verification of report signatures.
// Spec api-reports.
func (h *handlers) GetReportSigningKey(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if !h.reportSvcReady(w) {
		return
	}
	signer := h.reportSvc.Signer()
	if signer == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"report signing not configured", true)
		return
	}
	writeJSON(w, http.StatusOK, api.ReportSigningKey{
		KeyId:     signer.KeyID(),
		Algorithm: api.Ed25519,
		PublicKey: base64.StdEncoding.EncodeToString(signer.PublicKey()),
		Ephemeral: signer.Ephemeral(),
	})
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

	// The scope body is optional; an empty/absent body generates the
	// all-hosts, all-frameworks summary (the pre-A1 behavior).
	var body api.GenerateReportRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "reports.invalid_request", "client",
				"malformed request body", false)
			return
		}
	}
	req := report.GenerateRequest{}
	if body.Kind != nil {
		req.Kind = report.Kind(*body.Kind)
	}
	if body.GroupId != nil {
		gid := uuid.UUID(*body.GroupId)
		req.GroupID = &gid
	}
	if body.Framework != nil {
		req.Framework = *body.Framework
	}

	rep, err := h.reportSvc.Generate(r.Context(), reportActor(r), req)
	if errors.Is(err, report.ErrInvalidKind) {
		writeError(w, http.StatusBadRequest, "reports.invalid_kind", "client",
			"kind must be executive or attestation", false)
		return
	}
	if errors.Is(err, group.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "reports.invalid_scope", "client",
			"unknown group_id scope", false)
		return
	}
	if errors.Is(err, report.ErrGroupScopeUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"group scoping not available", true)
		return
	}
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

// GetReportExport implements api.ServerInterface: streams a rendered
// face of a report (PDF or JSON) as a downloadable attachment.
// Spec api-reports.
func (h *handlers) GetReportExport(w http.ResponseWriter, r *http.Request, id openapitypes.UUID, params api.GetReportExportParams) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if !h.reportSvcReady(w) {
		return
	}
	face := report.FacePDF
	if params.Format != nil {
		face = string(*params.Format)
	}

	body, mediaType, err := h.reportSvc.Export(r.Context(), id, face)
	if errors.Is(err, report.ErrNotFound) {
		writeError(w, http.StatusNotFound, "reports.not_found", "client", "report not found", false)
		return
	}
	if errors.Is(err, report.ErrInvalidFace) {
		writeError(w, http.StatusBadRequest, "reports.invalid_format", "client",
			"format does not apply to this report kind", false)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"report export failed", true)
		return
	}

	filename := "openwatch-report." + face
	if rep, gerr := h.reportSvc.Get(r.Context(), id); gerr == nil {
		filename = report.ExportFilename(rep, face)
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
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
