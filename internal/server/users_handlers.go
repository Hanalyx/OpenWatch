// User CRUD + custom-role admin handlers. Spec: app/specs/api/users.spec.yaml.

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"
)

// GetUsers lists active users.
// Spec api-users AC-04, AC-05.
func (h *handlers) GetUsers(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.UserRead); denied {
		return
	}
	list, err := h.users.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"list users failed", true)
		return
	}
	out := make([]api.UserResponse, len(list))
	for i, u := range list {
		out[i] = userResponse(u)
	}
	writeJSON(w, http.StatusOK, api.UsersListResponse{Users: out})
}

// PostUsers creates a user.
// Spec api-users AC-01, AC-02, AC-03.
func (h *handlers) PostUsers(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.UserWrite); denied {
		return
	}
	var req api.UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"username, email, password required", false)
		return
	}
	// API-created users get DefaultPolicy at creation. Promotion to admin
	// happens via POST /users/{id}/roles:assign; that role assignment
	// triggers AdminPolicy on the next password change. The create-admin
	// CLI bootstraps the first admin and applies AdminPolicy directly.
	u, err := h.users.CreateUser(r.Context(), users.CreateParams{
		Username: req.Username, Email: req.Email, Password: req.Password,
	})
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrPasswordTooShort),
			errors.Is(err, identity.ErrPasswordTooLong),
			errors.Is(err, identity.ErrPasswordBreached):
			writeError(w, http.StatusBadRequest, "auth.password_policy", "client",
				err.Error(), false)
		case strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "23505"):
			writeError(w, http.StatusConflict, "users.taken", "client",
				"username or email already in use", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				err.Error(), true)
		}
		return
	}
	emitAudit(r, audit.AdminUserCreated, u.ID.String(), map[string]any{"username": u.Username})
	writeJSON(w, http.StatusCreated, userResponse(u))
}

// GetUserByID fetches a user.
// Spec api-users AC-06.
func (h *handlers) GetUserByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.UserRead); denied {
		return
	}
	u, err := h.users.GetUserByID(r.Context(), uuid.UUID(id))
	if err != nil {
		if errors.Is(err, users.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "users.not_found", "client",
				"user not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}
	writeJSON(w, http.StatusOK, userResponse(u))
}

// DeleteUserByID soft-deletes a user.
// Spec api-users AC-07.
func (h *handlers) DeleteUserByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.UserDelete); denied {
		return
	}
	if err := h.users.SoftDelete(r.Context(), uuid.UUID(id)); err != nil {
		if errors.Is(err, users.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "users.not_found", "client",
				"user not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"delete failed", true)
		return
	}
	emitAudit(r, audit.AdminUserDeleted, id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// PostUserRolesAssign attaches a role.
// Spec api-users AC-08, AC-09.
func (h *handlers) PostUserRolesAssign(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.RoleAssign); denied {
		return
	}
	var req api.UserRoleAssignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RoleId == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"role_id is required", false)
		return
	}
	// Anti-escalation: a caller may not grant a role more privileged than
	// themselves. Spec api-users C-05 / AC-13 (mirrors api-tokens C-03).
	if !auth.RoleGrantsWithin(auth.FromContext(r.Context()), auth.RoleID(req.RoleId)) {
		writeError(w, http.StatusForbidden, "authz.role_exceeds_grant", "client",
			"cannot assign a role that grants permissions you do not hold", false)
		return
	}
	// Resolve "who is the granter" so audit + DB row record it.
	grantedBy := h.identityUUID(r)
	if err := h.users.AssignRole(r.Context(), uuid.UUID(id), auth.RoleID(req.RoleId), grantedBy); err != nil {
		if errors.Is(err, users.ErrUnknownRole) {
			writeError(w, http.StatusBadRequest, "users.unknown_role", "client",
				"role does not exist", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"assign failed", true)
		return
	}
	emitAudit(r, audit.AuthzRoleAssigned, id.String(), map[string]any{"role_id": req.RoleId})
	w.WriteHeader(http.StatusNoContent)
}

// PostUserRolesUnassign removes a role.
// Spec api-users AC-10.
func (h *handlers) PostUserRolesUnassign(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.RoleAssign); denied {
		return
	}
	var req api.UserRoleAssignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RoleId == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"role_id is required", false)
		return
	}
	if err := h.users.UnassignRole(r.Context(), uuid.UUID(id), auth.RoleID(req.RoleId)); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"unassign failed", true)
		return
	}
	emitAudit(r, audit.AuthzRoleRemoved, id.String(), map[string]any{"role_id": req.RoleId})
	w.WriteHeader(http.StatusNoContent)
}

// PostRolesCreate creates a custom role.
// Spec api-users AC-11, AC-12, C-03, C-04.
func (h *handlers) PostRolesCreate(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.RoleWrite); denied {
		return
	}
	var req api.CustomRoleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"id, description, permissions required", false)
		return
	}
	creator := h.identityUUID(r)
	created := uuid.Nil
	if creator != nil {
		created = *creator
	}
	// Permission validator: every permission must be in auth.Permissions.
	validator := func(perm string) bool {
		_, ok := auth.Permissions[auth.Permission(perm)]
		return ok
	}
	role, invalid, err := h.users.CreateCustomRole(r.Context(), users.CustomRoleParams{
		ID: req.Id, Description: req.Description, Permissions: req.Permissions, CreatedBy: created,
	}, validator)
	if err != nil {
		switch {
		case errors.Is(err, users.ErrUnknownPermission):
			detail := map[string]any{"invalid_permissions": invalid}
			writeErrorWithDetail(w, http.StatusBadRequest, "users.unknown_permission", "client",
				"role grants permissions not in the registry", false, detail)
		case errors.Is(err, users.ErrRoleIDTaken):
			writeError(w, http.StatusConflict, "users.role_id_taken", "client",
				"role id already exists", false)
		case errors.Is(err, users.ErrCustomRoleEmpty):
			writeError(w, http.StatusBadRequest, "validation.field_required", "client",
				"permissions must be non-empty", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				err.Error(), true)
		}
		return
	}
	emitAudit(r, audit.AuthzRoleAssigned, role.ID, map[string]any{"created_role": role.ID})
	writeJSON(w, http.StatusCreated, api.CustomRoleResponse{
		Id:          role.ID,
		Description: role.Description,
		IsBuiltIn:   role.IsBuiltIn,
		Permissions: role.Permissions,
	})
}

// identityUUID returns the calling user's UUID, or nil if anonymous /
// not parseable. Used by role-grant audit + created_by tracking.
func (h *handlers) identityUUID(r *http.Request) *uuid.UUID {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		return nil
	}
	u, err := uuid.Parse(id.ID)
	if err != nil {
		return nil
	}
	return &u
}

// userResponse maps users.User into the wire shape. Admin status is
// inferred from the user's role assignments at the call site; this
// struct intentionally carries no is_admin flag.
func userResponse(u users.User) api.UserResponse {
	resp := api.UserResponse{
		Id:                   openapitypes.UUID(u.ID),
		Username:             u.Username,
		Email:                u.Email,
		LastPasswordChangeAt: &u.LastPasswordChangeAt,
		CreatedAt:            &u.CreatedAt,
		UpdatedAt:            &u.UpdatedAt,
	}
	// Roles is populated only by the list path (ListUsers); lookups that
	// don't join user_roles leave it nil, and we omit it rather than emit
	// a misleading empty/null array.
	if u.Roles != nil {
		resp.Roles = &u.Roles
	}
	if u.DisabledAt != nil {
		resp.DisabledAt = u.DisabledAt
	}
	return resp
}

// writeErrorWithDetail is the writeError variant that includes a
// detail object. Used by AC-12 to surface invalid_permissions.
func writeErrorWithDetail(w http.ResponseWriter, status int, code, fault, msg string, retryable bool, detail map[string]any) {
	body := map[string]any{
		"error": map[string]any{
			"code":          code,
			"fault":         fault,
			"retryable":     retryable,
			"human_message": msg,
			"detail":        detail,
		},
	}
	bs, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(bs)
}
