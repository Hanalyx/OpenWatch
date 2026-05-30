// Host inventory CRUD admin handlers. Spec:
// app/specs/api/hosts.spec.yaml.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"
)

// GetHosts lists active hosts.
// Spec api-hosts AC-05, AC-06, AC-07.
func (h *handlers) GetHosts(w http.ResponseWriter, r *http.Request, params api.GetHostsParams) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	lp := host.ListParams{}
	if params.Environment != nil {
		lp.Environment = *params.Environment
	}
	if params.Tag != nil {
		lp.Tag = *params.Tag
	}
	list, err := h.hosts.List(r.Context(), lp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"list hosts failed", true)
		return
	}
	out := make([]api.HostResponse, len(list))
	for i, h := range list {
		out[i] = hostResponse(h)
	}
	writeJSON(w, http.StatusOK, api.HostListResponse{Hosts: out})
}

// PostHosts creates a host.
// Spec api-hosts AC-01, AC-03, AC-04.
func (h *handlers) PostHosts(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	var req api.HostCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"hostname and ip_address are required", false)
		return
	}
	params := host.CreateParams{
		Hostname:  req.Hostname,
		IPAddress: req.IpAddress,
	}
	if req.Port != nil {
		params.Port = *req.Port
	}
	if req.DisplayName != nil {
		params.DisplayName = *req.DisplayName
	}
	if req.Description != nil {
		params.Description = *req.Description
	}
	if req.Environment != nil {
		params.Environment = *req.Environment
	}
	if req.Tags != nil {
		params.Tags = *req.Tags
	}
	if req.GroupId != nil {
		u := uuid.UUID(*req.GroupId)
		params.GroupID = &u
	}
	if req.Username != nil {
		params.Username = *req.Username
	}
	if creator := h.identityUUID(r); creator != nil {
		params.CreatedBy = *creator
	}
	created, err := h.hosts.CreateHost(r.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, host.ErrInvalidHost):
			writeError(w, http.StatusBadRequest, "hosts.invalid_input", "client",
				"hostname, ip_address, or port is invalid", false)
		case errors.Is(err, host.ErrDuplicateHost):
			writeError(w, http.StatusConflict, "hosts.duplicate", "client",
				"hostname already exists in this environment", false)
		case errors.Is(err, host.ErrInvalidCreator):
			writeError(w, http.StatusBadRequest, "hosts.invalid_creator", "client",
				"created_by user does not exist", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				err.Error(), true)
		}
		return
	}
	emitAudit(r, audit.HostCreated, created.ID.String(), map[string]any{
		"hostname":    created.Hostname,
		"environment": created.Environment,
	})
	writeJSON(w, http.StatusCreated, hostResponse(created))
}

// GetHostByID fetches a host with liveness + compliance_summary enrichment.
// Spec api-hosts AC-08, AC-13, AC-14, AC-15, AC-16, AC-17, AC-18.
func (h *handlers) GetHostByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID, params api.GetHostByIDParams) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	ctx := r.Context()
	hostID := uuid.UUID(id)

	got, err := h.hosts.GetByID(ctx, hostID)
	if err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}

	liveness, err := loadHostLiveness(ctx, h.pool, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"liveness lookup failed", true)
		return
	}
	// v1.2.0: optional ?framework= filters the compliance_summary;
	// liveness is unaffected (spec C-07).
	var framework string
	if params.Framework != nil {
		framework = *params.Framework
	}
	summary, err := loadHostComplianceSummary(ctx, h.pool, hostID, framework)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"compliance summary lookup failed", true)
		return
	}

	resp := api.HostDetailResponse{
		Host:              hostResponse(got),
		Liveness:          liveness,
		ComplianceSummary: summary,
	}
	writeJSON(w, http.StatusOK, resp)
}

// PatchHostByID updates mutable host fields.
// Spec api-hosts AC-09, AC-10.
func (h *handlers) PatchHostByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	var req api.HostUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	params := host.UpdateParams{
		IPAddress:   req.IpAddress,
		Port:        req.Port,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Environment: req.Environment,
		Tags:        req.Tags,
		Username:    req.Username,
	}
	if req.GroupId != nil {
		u := uuid.UUID(*req.GroupId)
		params.GroupID = &u
	}
	updated, err := h.hosts.UpdateHost(r.Context(), uuid.UUID(id), params)
	if err != nil {
		switch {
		case errors.Is(err, host.ErrInvalidHost):
			writeError(w, http.StatusBadRequest, "hosts.invalid_input", "client",
				"updated values failed validation", false)
		case errors.Is(err, host.ErrDuplicateHost):
			writeError(w, http.StatusConflict, "hosts.duplicate", "client",
				"hostname already exists in this environment", false)
		case errors.Is(err, host.ErrHostNotFound):
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				err.Error(), true)
		}
		return
	}
	emitAudit(r, audit.HostUpdated, updated.ID.String(), nil)
	writeJSON(w, http.StatusOK, hostResponse(updated))
}

// DeleteHostByID soft-deletes a host.
// Spec api-hosts AC-11, AC-12.
func (h *handlers) DeleteHostByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostDelete); denied {
		return
	}
	if err := h.hosts.SoftDelete(r.Context(), uuid.UUID(id)); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"delete failed", true)
		return
	}
	emitAudit(r, audit.HostDeleted, id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// hostResponse maps host.Host into the wire shape.
func hostResponse(h host.Host) api.HostResponse {
	desc := h.Description
	displayName := h.DisplayName
	env := h.Environment
	username := h.Username
	tags := h.Tags
	createdBy := openapitypes.UUID(h.CreatedBy)
	var groupID *openapitypes.UUID
	if h.GroupID != nil {
		u := openapitypes.UUID(*h.GroupID)
		groupID = &u
	}
	return api.HostResponse{
		Id:          openapitypes.UUID(h.ID),
		Hostname:    h.Hostname,
		IpAddress:   h.IPAddress,
		Port:        h.Port,
		DisplayName: &displayName,
		Description: &desc,
		Environment: env,
		Tags:        &tags,
		GroupId:     groupID,
		Username:    &username,
		CreatedBy:   &createdBy,
		CreatedAt:   &h.CreatedAt,
		UpdatedAt:   &h.UpdatedAt,
	}
}
