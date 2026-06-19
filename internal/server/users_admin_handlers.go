// Admin user-management HTTP surface: reset another user's (or one's own)
// password, and disable / enable an account. Thin handlers over
// internal/users - RBAC (admin:user_manage), the self-disable lockout guard,
// and error-to-status mapping live here; the password policy, session
// revocation, and disabled-state semantics live in the service.
//
// Spec: specs/api/users.spec.yaml (admin reset-password + disable/enable).

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/users"
)

// mapUserAdminErr translates a users service error to an HTTP response.
// Returns true when it handled (wrote) the error.
func mapUserAdminErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, users.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "users.not_found", "client", "user not found", false)
	case errors.Is(err, identity.ErrPasswordTooShort),
		errors.Is(err, identity.ErrPasswordTooLong),
		errors.Is(err, identity.ErrPasswordBreached):
		writeError(w, http.StatusBadRequest, "validation.password_policy", "client", err.Error(), false)
	default:
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"user operation failed", true)
	}
	return true
}

// PostUserResetPassword implements api.ServerInterface.
// Spec api-users (admin reset-password).
func (h *handlers) PostUserResetPassword(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AdminUserManage); denied {
		return
	}
	var req api.UserPasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}
	if err := h.users.AdminResetPassword(r.Context(), uuid.UUID(id), req.NewPassword); mapUserAdminErr(w, err) {
		return
	}
	caller := auth.FromContext(r.Context()).ID
	emitAudit(r, audit.AdminUserPasswordReset, caller, map[string]any{
		"target_user_id": id.String(),
		"self":           caller == id.String(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// PostUserDisable implements api.ServerInterface.
// Spec api-users (disable/enable).
func (h *handlers) PostUserDisable(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AdminUserManage); denied {
		return
	}
	caller := auth.FromContext(r.Context()).ID
	// Lockout prevention: an admin must not disable their own account.
	if caller == id.String() {
		writeError(w, http.StatusConflict, "users.cannot_disable_self", "client",
			"you cannot disable your own account", false)
		return
	}
	if err := h.users.Disable(r.Context(), uuid.UUID(id)); mapUserAdminErr(w, err) {
		return
	}
	emitAudit(r, audit.AdminUserDisabled, caller, map[string]any{"target_user_id": id.String()})
	h.writeUser(w, r, uuid.UUID(id))
}

// PostUserEnable implements api.ServerInterface.
// Spec api-users (disable/enable).
func (h *handlers) PostUserEnable(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AdminUserManage); denied {
		return
	}
	if err := h.users.Enable(r.Context(), uuid.UUID(id)); mapUserAdminErr(w, err) {
		return
	}
	caller := auth.FromContext(r.Context()).ID
	emitAudit(r, audit.AdminUserEnabled, caller, map[string]any{"target_user_id": id.String()})
	h.writeUser(w, r, uuid.UUID(id))
}

// writeUser re-reads the user and writes it as a 200 UserResponse. Used by
// disable/enable so the client gets the updated disabled_at without a refetch.
func (h *handlers) writeUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	u, err := h.users.GetUserByID(r.Context(), id)
	if mapUserAdminErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, userResponse(u))
}
