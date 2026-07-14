// Compliance exception governance HTTP surface: request / list /
// approve / reject / revoke. Thin handlers over internal/exception -
// RBAC + the host 404 pre-read + error-to-status mapping live here;
// the lifecycle invariants (one-open, state guards, separation of
// duties, overlay) live in the service.
//
// Spec: specs/api/compliance-exceptions.spec.yaml

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/exception"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// toAPIException maps a service exception to the wire shape.
func toAPIException(e exception.Exception) api.Exception {
	out := api.Exception{
		Id:          openapitypes.UUID(e.ID),
		HostId:      openapitypes.UUID(e.HostID),
		RuleId:      e.RuleID,
		Reason:      e.Reason,
		Status:      api.ExceptionStatus(e.Status),
		RequestedBy: openapitypes.UUID(e.RequestedBy),
		RequestedAt: e.RequestedAt,
		ExpiresAt:   e.ExpiresAt,
		ReviewedAt:  e.ReviewedAt,
	}
	if e.ReviewedBy != nil {
		rb := openapitypes.UUID(*e.ReviewedBy)
		out.ReviewedBy = &rb
	}
	if e.ReviewNote != "" {
		n := e.ReviewNote
		out.ReviewNote = &n
	}
	if e.HostName != "" {
		hn := e.HostName
		out.HostName = &hn
	}
	return out
}

func writeExceptionList(w http.ResponseWriter, items []exception.Exception) {
	resp := api.ExceptionList{Exceptions: []api.Exception{}}
	for _, e := range items {
		resp.Exceptions = append(resp.Exceptions, toAPIException(e))
	}
	writeJSON(w, http.StatusOK, resp)
}

// exceptionSvcReady guards every handler: 503 when the service is not
// wired (the generic builder guard, system-daemon-orchestration AC-11,
// keeps this from happening in serve).
func (h *handlers) exceptionSvcReady(w http.ResponseWriter) bool {
	if h.exceptionSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"exception service not wired", true)
		return false
	}
	return true
}

// reviewerID returns the authenticated user's UUID, or an error
// response if it cannot be parsed (should not happen post-auth).
func (h *handlers) reviewerID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(auth.FromContext(r.Context()).ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"actor id unavailable", true)
		return uuid.Nil, false
	}
	return id, true
}

// mapExceptionErr translates a service error to an HTTP response.
// Returns true when it handled (wrote) the error.
func mapExceptionErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, exception.ErrNotFound):
		writeError(w, http.StatusNotFound, "exceptions.not_found", "client",
			"exception not found", false)
	case errors.Is(err, exception.ErrDuplicateOpen):
		writeError(w, http.StatusConflict, "exceptions.already_open", "client",
			"an open exception already exists for this host and rule", false)
	case errors.Is(err, exception.ErrWrongState):
		writeError(w, http.StatusConflict, "exceptions.wrong_state", "client",
			"action not valid for the exception's current state", false)
	case errors.Is(err, exception.ErrSelfReview):
		writeError(w, http.StatusConflict, "exceptions.self_review", "client",
			"the requester cannot review their own exception", false)
	case errors.Is(err, exception.ErrExpired):
		writeError(w, http.StatusConflict, "exceptions.expired", "client",
			"the request's expiry has already passed; ask the requester to resubmit with a future expiry", false)
	case errors.Is(err, exception.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"rule_id and reason are required", false)
	default:
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"exception operation failed", true)
	}
	return true
}

// GetHostExceptions implements api.ServerInterface.
// Spec api-compliance-exceptions AC-06.
func (h *handlers) GetHostExceptions(
	w http.ResponseWriter, r *http.Request, id openapitypes.UUID, params api.GetHostExceptionsParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.ExceptionRead); denied {
		return
	}
	if !h.exceptionSvcReady(w) {
		return
	}
	ctx := r.Context()
	hostID := uuid.UUID(id)
	if _, err := h.hosts.GetByID(ctx, hostID); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client", "host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "lookup failed", true)
		return
	}
	includeHistory := params.History != nil && *params.History
	items, err := h.exceptionSvc.ListForHost(ctx, hostID, includeHistory)
	if mapExceptionErr(w, err) {
		return
	}
	writeExceptionList(w, items)
}

// PostHostException implements api.ServerInterface.
// Spec api-compliance-exceptions AC-01, AC-06.
func (h *handlers) PostHostException(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.ExceptionRequest); denied {
		return
	}
	if !h.exceptionSvcReady(w) {
		return
	}
	ctx := r.Context()
	hostID := uuid.UUID(id)
	if _, err := h.hosts.GetByID(ctx, hostID); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client", "host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "lookup failed", true)
		return
	}
	var req api.ExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	requestedBy, ok := h.reviewerID(w, r)
	if !ok {
		return
	}
	e, err := h.exceptionSvc.Request(ctx, hostID, req.RuleId, req.Reason, requestedBy, req.ExpiresAt)
	if mapExceptionErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, toAPIException(e))
}

// GetComplianceExceptions implements api.ServerInterface.
// Spec api-compliance-exceptions AC-06.
func (h *handlers) GetComplianceExceptions(
	w http.ResponseWriter, r *http.Request, params api.GetComplianceExceptionsParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.ExceptionRead); denied {
		return
	}
	if !h.exceptionSvcReady(w) {
		return
	}
	var status exception.Status
	if params.Status != nil {
		status = exception.Status(*params.Status)
	}
	limit := 200
	if params.Limit != nil {
		limit = *params.Limit
	}
	items, err := h.exceptionSvc.ListFleet(r.Context(), status, limit)
	if mapExceptionErr(w, err) {
		return
	}
	writeExceptionList(w, items)
}

// reviewException is the shared body for approve/reject/revoke: parse
// xid + note, run the transition fn, map the result.
func (h *handlers) reviewException(
	w http.ResponseWriter, r *http.Request, xid openapitypes.UUID, perm auth.Permission,
	fn func(ctx context.Context, id, reviewer uuid.UUID, note string) (exception.Exception, error),
) {
	if denied := auth.EnforcePermission(w, r, perm); denied {
		return
	}
	if !h.exceptionSvcReady(w) {
		return
	}
	var req api.ExceptionReview
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	note := ""
	if req.Note != nil {
		note = *req.Note
	}
	reviewer, ok := h.reviewerID(w, r)
	if !ok {
		return
	}
	e, err := fn(r.Context(), uuid.UUID(xid), reviewer, note)
	if mapExceptionErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toAPIException(e))
}

// PostExceptionApprove implements api.ServerInterface.
// Spec api-compliance-exceptions AC-02, AC-03, AC-06.
func (h *handlers) PostExceptionApprove(w http.ResponseWriter, r *http.Request, xid openapitypes.UUID) {
	h.reviewException(w, r, xid, auth.ExceptionApprove, h.exceptionSvc.Approve)
}

// PostExceptionReject implements api.ServerInterface.
// Spec api-compliance-exceptions AC-02, AC-03, AC-06.
func (h *handlers) PostExceptionReject(w http.ResponseWriter, r *http.Request, xid openapitypes.UUID) {
	h.reviewException(w, r, xid, auth.ExceptionApprove, h.exceptionSvc.Reject)
}

// PostExceptionRevoke implements api.ServerInterface.
// Spec api-compliance-exceptions AC-02, AC-06.
func (h *handlers) PostExceptionRevoke(w http.ResponseWriter, r *http.Request, xid openapitypes.UUID) {
	h.reviewException(w, r, xid, auth.ExceptionRevoke, h.exceptionSvc.Revoke)
}
