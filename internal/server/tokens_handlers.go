package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/apitoken"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/google/uuid"
)

// GetAPITokens lists API tokens (metadata only). Spec api-tokens AC-01.
func (h *handlers) GetAPITokens(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.TokenRead); denied {
		return
	}
	list, err := h.apiTokenSvc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"list tokens failed", true)
		return
	}
	out := make([]api.ApiToken, len(list))
	for i, t := range list {
		out[i] = toAPIToken(t)
	}
	writeJSON(w, http.StatusOK, api.ApiTokenList{Tokens: out})
}

// PostAPIToken creates a token and returns the raw secret ONCE.
// Spec api-tokens AC-02.
func (h *handlers) PostAPIToken(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.TokenWrite); denied {
		return
	}
	var req api.ApiTokenCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"name, role_id required", false)
		return
	}
	p := apitoken.CreateParams{
		Name:      req.Name,
		RoleID:    auth.RoleID(req.RoleId),
		ExpiresAt: req.ExpiresAt,
		CreatedBy: callerUUID(r),
	}
	raw, t, err := h.apiTokenSvc.Create(r.Context(), p)
	if err != nil {
		if errors.Is(err, apitoken.ErrInvalidParams) {
			writeError(w, http.StatusBadRequest, "tokens.invalid", "client",
				"invalid token parameters (check name + role_id)", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"create token failed", true)
		return
	}
	writeJSON(w, http.StatusCreated, api.ApiTokenCreated{Token: raw, ApiToken: toAPIToken(t)})
}

// DeleteAPIToken revokes a token (idempotent). Spec api-tokens AC-03.
func (h *handlers) DeleteAPIToken(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.TokenDelete); denied {
		return
	}
	if err := h.apiTokenSvc.Revoke(r.Context(), uuid.UUID(id)); err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"revoke token failed", true)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toAPIToken(t apitoken.Token) api.ApiToken {
	return api.ApiToken{
		Id:         openapitypes.UUID(t.ID),
		Name:       t.Name,
		Prefix:     t.Prefix,
		RoleId:     t.RoleID,
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
	}
}

// callerUUID returns the authenticated user's id as a *uuid.UUID, or nil
// when the identity id is not a UUID (e.g. an API token acting on behalf
// of automation).
func callerUUID(r *http.Request) *uuid.UUID {
	id := auth.FromContext(r.Context())
	if u, err := uuid.Parse(id.ID); err == nil {
		return &u
	}
	return nil
}
