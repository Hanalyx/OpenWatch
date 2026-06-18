// Remediation governance HTTP surface (free / OpenWatch Core): list / get /
// request / approve / reject / steps. Thin handlers over internal/remediation -
// RBAC + the host 404 pre-read + error-to-status mapping live here; the
// lifecycle invariants (one-open, state guards, separation of duties, the
// never-touch-a-host invariant) live in the service.
//
// The act verbs (:dry-run, :execute, :rollback) are OpenWatch+ licensed: they
// enforce the dangerous, license-gated remediation:execute / remediation:rollback
// permission (403 then 402 via the RBAC+license middleware) and, for an entitled
// caller, report 501 because the host-mutating body is the licensed track
// (docs/engineering/remediation_licensed_plan.md), not built in the core.
//
// Spec: specs/api/remediation.spec.yaml

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/remediation"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// toAPIRemediation maps a service request to the wire shape.
func toAPIRemediation(rq remediation.Request) api.RemediationRequest {
	rebootReq := rq.RebootRequired
	txnal := rq.Transactional
	out := api.RemediationRequest{
		Id:             openapitypes.UUID(rq.ID),
		HostId:         openapitypes.UUID(rq.HostID),
		RuleId:         rq.RuleID,
		Status:         api.RemediationRequestStatus(rq.Status),
		RequestedBy:    openapitypes.UUID(rq.RequestedBy),
		RequestedAt:    rq.RequestedAt,
		ReviewedAt:     rq.ReviewedAt,
		RebootRequired: &rebootReq,
		Transactional:  &txnal,
	}
	if rq.ReviewedBy != nil {
		rb := openapitypes.UUID(*rq.ReviewedBy)
		out.ReviewedBy = &rb
	}
	if rq.ReviewNote != "" {
		n := rq.ReviewNote
		out.ReviewNote = &n
	}
	if rq.HostName != "" {
		hn := rq.HostName
		out.HostName = &hn
	}
	if rq.Mechanism != "" {
		m := rq.Mechanism
		out.Mechanism = &m
	}
	if rq.ScanRunID != nil {
		sr := openapitypes.UUID(*rq.ScanRunID)
		out.ScanRunId = &sr
	}
	if rq.Projected.CIS != nil || rq.Projected.STIG != nil || rq.Projected.NIST != nil {
		out.ProjectedLift = &api.ProjectedLift{
			Cis:  rq.Projected.CIS,
			Stig: rq.Projected.STIG,
			Nist: rq.Projected.NIST,
		}
	}
	return out
}

func toAPIStep(st remediation.Step) api.RemediationStep {
	out := api.RemediationStep{
		Id:        openapitypes.UUID(st.ID),
		RuleId:    st.RuleID,
		DryRun:    st.DryRun,
		AppliedAt: st.AppliedAt,
	}
	if st.Mechanism != "" {
		m := st.Mechanism
		out.Mechanism = &m
	}
	if st.PhaseResult != nil {
		pr := api.RemediationStepPhaseResult(*st.PhaseResult)
		out.PhaseResult = &pr
	}
	return out
}

func writeRemediationList(w http.ResponseWriter, items []remediation.Request) {
	resp := api.RemediationRequestList{Requests: []api.RemediationRequest{}}
	for _, rq := range items {
		resp.Requests = append(resp.Requests, toAPIRemediation(rq))
	}
	writeJSON(w, http.StatusOK, resp)
}

// remediationSvcReady guards every handler: 503 when the service is not wired.
func (h *handlers) remediationSvcReady(w http.ResponseWriter) bool {
	if h.remediationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"remediation service not wired", true)
		return false
	}
	return true
}

// mapRemediationErr translates a service error to an HTTP response. Returns
// true when it handled (wrote) the error.
func mapRemediationErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, remediation.ErrNotFound):
		writeError(w, http.StatusNotFound, "remediation.not_found", "client",
			"remediation request not found", false)
	case errors.Is(err, remediation.ErrDuplicateOpen):
		writeError(w, http.StatusConflict, "remediation.already_open", "client",
			"an open remediation request already exists for this host and rule", false)
	case errors.Is(err, remediation.ErrWrongState):
		writeError(w, http.StatusConflict, "remediation.wrong_state", "client",
			"action not valid for the request's current state", false)
	case errors.Is(err, remediation.ErrSelfReview):
		writeError(w, http.StatusConflict, "remediation.self_review", "client",
			"the requester cannot review their own request", false)
	case errors.Is(err, remediation.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"rule_id is required", false)
	default:
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"remediation operation failed", true)
	}
	return true
}

// ListRemediationRequests implements api.ServerInterface.
// Spec api-remediation AC-05.
func (h *handlers) ListRemediationRequests(
	w http.ResponseWriter, r *http.Request, params api.ListRemediationRequestsParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.RemediationRead); denied {
		return
	}
	if !h.remediationSvcReady(w) {
		return
	}
	f := remediation.ListFilter{}
	if params.Status != nil {
		f.Status = remediation.Status(*params.Status)
	}
	if params.HostId != nil {
		hid := uuid.UUID(*params.HostId)
		f.HostID = &hid
	}
	if params.RuleId != nil {
		f.RuleID = *params.RuleId
	}
	if params.Limit != nil {
		f.Limit = *params.Limit
	}
	items, err := h.remediationSvc.ListRequests(r.Context(), f)
	if mapRemediationErr(w, err) {
		return
	}
	writeRemediationList(w, items)
}

// RequestRemediation implements api.ServerInterface.
// Spec api-remediation AC-01, AC-05.
func (h *handlers) RequestRemediation(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.RemediationRequest); denied {
		return
	}
	if !h.remediationSvcReady(w) {
		return
	}
	var req api.RemediationRequestCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	ctx := r.Context()
	hostID := uuid.UUID(req.HostId)
	if _, err := h.hosts.GetByID(ctx, hostID); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client", "host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "lookup failed", true)
		return
	}
	requestedBy, ok := h.reviewerID(w, r)
	if !ok {
		return
	}
	var scanRunID *uuid.UUID
	if req.ScanRunId != nil {
		s := uuid.UUID(*req.ScanRunId)
		scanRunID = &s
	}
	rq, err := h.remediationSvc.Request(ctx, hostID, req.RuleId, scanRunID, requestedBy)
	if mapRemediationErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, toAPIRemediation(rq))
}

// GetRemediationRequest implements api.ServerInterface.
// Spec api-remediation AC-05.
func (h *handlers) GetRemediationRequest(w http.ResponseWriter, r *http.Request, rid openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.RemediationRead); denied {
		return
	}
	if !h.remediationSvcReady(w) {
		return
	}
	rq, err := h.remediationSvc.Get(r.Context(), uuid.UUID(rid))
	if mapRemediationErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toAPIRemediation(rq))
}

// ListRemediationSteps implements api.ServerInterface.
// Spec api-remediation AC-05.
func (h *handlers) ListRemediationSteps(w http.ResponseWriter, r *http.Request, rid openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.RemediationRead); denied {
		return
	}
	if !h.remediationSvcReady(w) {
		return
	}
	ctx := r.Context()
	if _, err := h.remediationSvc.Get(ctx, uuid.UUID(rid)); mapRemediationErr(w, err) {
		return
	}
	steps, err := h.remediationSvc.ListSteps(ctx, uuid.UUID(rid))
	if mapRemediationErr(w, err) {
		return
	}
	resp := api.RemediationStepList{Steps: []api.RemediationStep{}}
	for _, st := range steps {
		resp.Steps = append(resp.Steps, toAPIStep(st))
	}
	writeJSON(w, http.StatusOK, resp)
}

// reviewRemediation is the shared body for approve/reject: parse rid + note,
// run the transition fn, map the result.
func (h *handlers) reviewRemediation(
	w http.ResponseWriter, r *http.Request, rid openapitypes.UUID,
	fn func(ctx context.Context, id, reviewer uuid.UUID, note string) (remediation.Request, error),
) {
	if denied := auth.EnforcePermission(w, r, auth.RemediationApprove); denied {
		return
	}
	if !h.remediationSvcReady(w) {
		return
	}
	var req api.RemediationReview
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	note := ""
	if req.Note != nil {
		note = *req.Note
	}
	reviewer, ok := h.reviewerID(w, r)
	if !ok {
		return
	}
	rq, err := fn(r.Context(), uuid.UUID(rid), reviewer, note)
	if mapRemediationErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toAPIRemediation(rq))
}

// ApproveRemediation implements api.ServerInterface.
// Spec api-remediation AC-02, AC-03, AC-05.
func (h *handlers) ApproveRemediation(w http.ResponseWriter, r *http.Request, rid openapitypes.UUID) {
	h.reviewRemediation(w, r, rid, h.remediationSvc.Approve)
}

// RejectRemediation implements api.ServerInterface.
// Spec api-remediation AC-02, AC-03, AC-05.
func (h *handlers) RejectRemediation(w http.ResponseWriter, r *http.Request, rid openapitypes.UUID) {
	h.reviewRemediation(w, r, rid, h.remediationSvc.Reject)
}

// licensedRemediationAct enforces the dangerous, license-gated permission
// (403 then 402 via the RBAC+license middleware) and, when the caller is
// entitled, reports 501: the host-mutating execution body is the OpenWatch+
// licensed track, not built in the core. Spec api-remediation AC-06.
func (h *handlers) licensedRemediationAct(w http.ResponseWriter, r *http.Request, perm auth.Permission) {
	if denied := auth.EnforcePermission(w, r, perm); denied {
		return
	}
	writeError(w, http.StatusNotImplemented, "remediation.not_implemented", "server",
		"remediation execution is an OpenWatch+ feature not yet implemented", false)
}

// DryRunRemediation implements api.ServerInterface (OpenWatch+ licensed).
func (h *handlers) DryRunRemediation(w http.ResponseWriter, r *http.Request, _ openapitypes.UUID) {
	h.licensedRemediationAct(w, r, auth.RemediationExecute)
}

// ExecuteRemediation implements api.ServerInterface (OpenWatch+ licensed).
func (h *handlers) ExecuteRemediation(w http.ResponseWriter, r *http.Request, _ openapitypes.UUID) {
	h.licensedRemediationAct(w, r, auth.RemediationExecute)
}

// RollbackRemediation implements api.ServerInterface (OpenWatch+ licensed).
func (h *handlers) RollbackRemediation(w http.ResponseWriter, r *http.Request, _ openapitypes.UUID) {
	h.licensedRemediationAct(w, r, auth.RemediationRollback)
}
