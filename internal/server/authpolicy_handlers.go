package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/authpolicy"
	"github.com/Hanalyx/openwatch/internal/server/api"
	openapitypes "github.com/oapi-codegen/runtime/types"
)

// GetAuthPolicy returns the workspace authentication policy.
// Spec api-auth-policy AC-01.
func (h *handlers) GetAuthPolicy(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemAuthPolicyRead); denied {
		return
	}
	p, err := h.authPolicySvc.Get(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"load auth policy failed", true)
		return
	}
	writeJSON(w, http.StatusOK, toAPIAuthPolicy(p))
}

// PutAuthPolicy replaces the workspace authentication policy.
// Spec api-auth-policy AC-02, AC-03.
func (h *handlers) PutAuthPolicy(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemAuthPolicyWrite); denied {
		return
	}
	var req api.AuthPolicyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"require_mfa and both timeouts are required", false)
		return
	}
	p, err := h.authPolicySvc.Update(r.Context(), authpolicy.UpdateParams{
		RequireMFA:      req.RequireMfa,
		IdleTimeout:     time.Duration(req.SessionIdleTimeoutSeconds) * time.Second,
		AbsoluteTimeout: time.Duration(req.SessionAbsoluteTimeoutSeconds) * time.Second,
		UpdatedBy:       callerUUID(r),
	})
	if err != nil {
		if errors.Is(err, authpolicy.ErrInvalidParams) {
			writeError(w, http.StatusBadRequest, "auth_policy.invalid", "client",
				err.Error(), false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"update auth policy failed", true)
		return
	}
	emitAudit(r, audit.AuthPolicyUpdated, auth.FromContext(r.Context()).ID, map[string]any{
		"require_mfa":                      p.RequireMFA,
		"session_idle_timeout_seconds":     int(p.IdleTimeout.Seconds()),
		"session_absolute_timeout_seconds": int(p.AbsoluteTimeout.Seconds()),
	})
	writeJSON(w, http.StatusOK, toAPIAuthPolicy(p))
}

func toAPIAuthPolicy(p authpolicy.Policy) api.AuthPolicy {
	out := api.AuthPolicy{
		RequireMfa:                    p.RequireMFA,
		SessionIdleTimeoutSeconds:     int(p.IdleTimeout.Seconds()),
		SessionAbsoluteTimeoutSeconds: int(p.AbsoluteTimeout.Seconds()),
		UpdatedAt:                     p.UpdatedAt,
	}
	if p.UpdatedBy != nil {
		u := openapitypes.UUID(*p.UpdatedBy)
		out.UpdatedBy = &u
	}
	return out
}
