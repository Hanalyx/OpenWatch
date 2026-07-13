// Host group HTTP surface: fleet summary + group CRUD + membership +
// the maintenance toggle. Thin handlers over internal/group - RBAC
// (host:read for the list, host:write for mutations), error-to-status
// mapping, and group.Group -> api.Group wire shaping live here; the
// validation invariants (kind/membership rules, duplicate auto family)
// live in the service.
//
// Spec: api-groups.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/group"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// toAPIGroup maps a service group to the wire shape.
func toAPIGroup(g group.Group) api.Group {
	out := api.Group{
		Id:          openapitypes.UUID(g.ID),
		Name:        g.Name,
		Kind:        api.GroupKind(g.Kind),
		Subtype:     g.Subtype,
		Color:       g.Color,
		Membership:  api.GroupMembership(g.Membership),
		Maintenance: g.Maintenance,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
	if g.MatchFamily != "" {
		mf := g.MatchFamily
		out.MatchFamily = &mf
	}
	if g.TargetFramework != "" {
		tf := g.TargetFramework
		out.TargetFramework = &tf
	}
	return out
}

// PostGroupTarget sets or clears a site group's compliance target framework.
// Spec api-groups.
func (h *handlers) PostGroupTarget(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	var req api.GroupTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	g, err := h.groupSvc.SetTarget(r.Context(), uuid.UUID(id), req.TargetFramework)
	if mapGroupErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toAPIGroup(g))
}

// toAPIRollup maps a service rollup to the wire shape.
func toAPIRollup(r group.Rollup) api.GroupRollup {
	out := api.GroupRollup{
		Hosts:            r.Hosts,
		Online:           r.Online,
		Down:             r.Down,
		CriticalHosts:    r.CriticalHosts,
		AvgCompliancePct: r.AvgCompliancePct,
		Members:          []api.GroupMember{},
	}
	for _, m := range r.Members {
		out.Members = append(out.Members, api.GroupMember{
			HostId:   openapitypes.UUID(m.HostID),
			Hostname: m.Hostname,
			Status:   m.Status,
		})
	}
	return out
}

// toAPIGroupWithRollup maps a service group+rollup to the wire shape.
func toAPIGroupWithRollup(g group.GroupWithRollup) api.GroupWithRollup {
	return api.GroupWithRollup{
		Id:          openapitypes.UUID(g.ID),
		Name:        g.Name,
		Kind:        api.GroupWithRollupKind(g.Kind),
		Subtype:     g.Subtype,
		Color:       g.Color,
		Membership:  api.GroupWithRollupMembership(g.Membership),
		Maintenance: g.Maintenance,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
		MatchFamily: matchFamilyPtr(g.MatchFamily),
		Rollup:      toAPIRollup(g.Rollup),
	}
}

func matchFamilyPtr(mf string) *string {
	if mf == "" {
		return nil
	}
	return &mf
}

// groupSvcReady guards every handler: 503 when the service is not wired
// (the generic builder guard keeps this from happening in serve).
func (h *handlers) groupSvcReady(w http.ResponseWriter) bool {
	if h.groupSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"group service not wired", true)
		return false
	}
	return true
}

// mapGroupErr translates a service error to an HTTP response. Returns
// true when it handled (wrote) the error.
func mapGroupErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, group.ErrNotFound):
		writeError(w, http.StatusNotFound, "groups.not_found", "client",
			"group not found", false)
	case errors.Is(err, group.ErrDuplicateFamily):
		writeError(w, http.StatusConflict, "groups.duplicate_family", "client",
			"an auto group already exists for that OS family", false)
	case errors.Is(err, group.ErrEmptyName):
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"name is required", false)
	case errors.Is(err, group.ErrInvalidKind):
		writeError(w, http.StatusBadRequest, "validation.invalid", "client",
			"kind must be site or os_category", false)
	case errors.Is(err, group.ErrInvalidMembership):
		writeError(w, http.StatusBadRequest, "validation.invalid", "client",
			"membership must be manual or auto", false)
	case errors.Is(err, group.ErrAutoNeedsFamily):
		writeError(w, http.StatusBadRequest, "validation.invalid", "client",
			"auto membership requires a match_family", false)
	case errors.Is(err, group.ErrManualHasFamily):
		writeError(w, http.StatusBadRequest, "validation.invalid", "client",
			"manual membership must not set match_family", false)
	case errors.Is(err, group.ErrSiteMustBeManual):
		writeError(w, http.StatusBadRequest, "validation.invalid", "client",
			"a site must use manual membership", false)
	case errors.Is(err, group.ErrTargetOnlyOnSite):
		writeError(w, http.StatusBadRequest, "validation.invalid", "client",
			"only a site group may carry a compliance target", false)
	case errors.Is(err, group.ErrInvalidTarget):
		writeError(w, http.StatusBadRequest, "validation.invalid", "client",
			"target_framework is too long or has invalid characters", false)
	default:
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"group operation failed", true)
	}
	return true
}

// GetGroups implements api.ServerInterface.
// Spec api-groups.
func (h *handlers) GetGroups(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	ctx := r.Context()
	sum, err := h.groupSvc.Summary(ctx)
	if mapGroupErr(w, err) {
		return
	}
	groups, err := h.groupSvc.List(ctx)
	if mapGroupErr(w, err) {
		return
	}
	resp := api.GroupListResponse{
		Summary: api.GroupSummary{
			Groups:           sum.Groups,
			Sites:            sum.Sites,
			OsCategories:     sum.OSCategories,
			HostsMaintenance: sum.HostsMaintenance,
			AvgCompliancePct: sum.AvgCompliancePct,
			Ungrouped:        sum.Ungrouped,
		},
		Groups: []api.GroupWithRollup{},
	}
	for _, g := range groups {
		resp.Groups = append(resp.Groups, toAPIGroupWithRollup(g))
	}
	writeJSON(w, http.StatusOK, resp)
}

// PostGroup implements api.ServerInterface.
// Spec api-groups.
func (h *handlers) PostGroup(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	var req api.GroupCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	in := group.CreateInput{
		Name:       req.Name,
		Kind:       group.Kind(req.Kind),
		Membership: group.Membership(req.Membership),
	}
	if req.Subtype != nil {
		in.Subtype = *req.Subtype
	}
	if req.Color != nil {
		in.Color = *req.Color
	}
	if req.MatchFamily != nil {
		in.MatchFamily = *req.MatchFamily
	}
	g, err := h.groupSvc.Create(r.Context(), in)
	if mapGroupErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, toAPIGroup(g))
}

// PatchGroup implements api.ServerInterface.
// Spec api-groups.
func (h *handlers) PatchGroup(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	var req api.GroupUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	in := group.UpdateInput{Name: req.Name}
	if req.Subtype != nil {
		in.Subtype = *req.Subtype
	}
	if req.Color != nil {
		in.Color = *req.Color
	}
	g, err := h.groupSvc.Update(r.Context(), uuid.UUID(id), in)
	if mapGroupErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toAPIGroup(g))
}

// DeleteGroup implements api.ServerInterface.
// Spec api-groups.
func (h *handlers) DeleteGroup(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	if mapGroupErr(w, h.groupSvc.Delete(r.Context(), uuid.UUID(id))) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PostGroupMaintenance implements api.ServerInterface.
// Spec api-groups.
func (h *handlers) PostGroupMaintenance(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	var req api.GroupMaintenanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	g, err := h.groupSvc.SetMaintenance(r.Context(), uuid.UUID(id), req.On)
	if mapGroupErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, toAPIGroup(g))
}

// PostGroupMember implements api.ServerInterface.
// Spec api-groups.
func (h *handlers) PostGroupMember(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	var req api.GroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	err := h.groupSvc.AddMember(r.Context(), uuid.UUID(id), uuid.UUID(req.HostId))
	if mapGroupMemberErr(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteGroupMember implements api.ServerInterface.
// Spec api-groups.
func (h *handlers) DeleteGroupMember(
	w http.ResponseWriter, r *http.Request, id openapitypes.UUID, hostID openapitypes.UUID,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	if !h.groupSvcReady(w) {
		return
	}
	err := h.groupSvc.RemoveMember(r.Context(), uuid.UUID(id), uuid.UUID(hostID))
	if mapGroupErr(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// mapGroupMemberErr maps AddMember errors. The "auto group" rejection is
// a plain error (not a sentinel), so it falls through to a 400 here
// rather than the generic 500 in mapGroupErr. ErrNotFound (unknown
// group) still maps to 404.
func mapGroupMemberErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, group.ErrNotFound):
		writeError(w, http.StatusNotFound, "groups.not_found", "client",
			"group not found", false)
	default:
		writeError(w, http.StatusBadRequest, "groups.auto_membership", "client",
			"cannot add a member to an auto group", false)
	}
	return true
}
