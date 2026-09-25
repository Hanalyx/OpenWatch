// Admin user-management HTTP surface: reset another user's (or one's own)
// password, and disable / enable an account. Thin handlers over
// internal/users - RBAC (admin:user_manage), the self-disable lockout guard,
// and error-to-status mapping live here; the password policy, session
// revocation, and disabled-state semantics live in the service.
//
// Spec: specs/api/users.spec.yaml (admin reset-password + disable/enable).

package server

import (
	"context"
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
	// Classified by the stage the transaction reached, in this order.
	// The commit stage comes FIRST: an uncertain commit stays uncertain
	// even when what interrupted it was a deadline, which the later cases
	// would otherwise read as "not applied". Spec system-auth-identity
	// C-37, C-43.
	case errors.Is(err, identity.ErrCommitUnknown):
		// Neither result is asserted, and a blind retry is not invited.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"the change may or may not have been applied. Check the account before trying again.", false)
	case errors.Is(err, identity.ErrNotBegun):
		// No transaction began, typically because no connection became
		// free before the deadline. Nothing was read or written.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"the change was not applied because the server could not start it in time. Try again.", true)
	case identity.IsLockTimeout(err):
		// A lock wait exceeded its limit, on the account lock or on a
		// later row lock, and the transaction rolled back.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"the change was not applied because a lock could not be acquired in time. Try again.", true)
	case errors.Is(err, context.DeadlineExceeded):
		// The deadline expired after the transaction began and before its
		// commit, so it rolled back: a transaction that never reached
		// COMMIT cannot have committed.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"the change was not applied because it did not complete in time. Try again.", true)
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
	// The user comes back from the locked transaction, returned only after
	// its commit is confirmed. No read follows the commit, so a committed
	// disable cannot be reported as not applied or not found. api-users C-08.
	u, err := h.users.DisableUser(r.Context(), uuid.UUID(id))
	if mapUserAdminErr(w, err) {
		return
	}
	emitAudit(r, audit.AdminUserDisabled, caller, map[string]any{"target_user_id": id.String()})
	writeJSON(w, http.StatusOK, userResponse(u))
}

// PostUserEnable implements api.ServerInterface.
// Spec api-users (disable/enable).
func (h *handlers) PostUserEnable(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AdminUserManage); denied {
		return
	}
	u, transitioned, err := h.users.EnableUser(r.Context(), uuid.UUID(id))
	if mapUserAdminErr(w, err) {
		return
	}
	// The transition comes from the locked transaction itself, not from a
	// later read. A real transition revoked the user's interactive
	// credentials; a call on an account that was not disabled revoked
	// nothing. Service-account tokens are outside both. Spec api-users C-08.
	scope := "none"
	if transitioned {
		scope = "interactive"
	}
	caller := auth.FromContext(r.Context()).ID
	emitAudit(r, audit.AdminUserEnabled, caller, map[string]any{
		"target_user_id":   id.String(),
		"transition":       transitioned,
		"revocation_scope": scope,
	})
	writeJSON(w, http.StatusOK, userResponse(u))
}
