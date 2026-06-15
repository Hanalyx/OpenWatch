package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/sso"
	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"
)

// ssoOrUnavailable returns the SSO service or writes a 503 when it isn't
// wired (e.g. tests that don't exercise SSO).
func (h *handlers) ssoOrUnavailable(w http.ResponseWriter) (*sso.Service, bool) {
	if h.ssoSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"SSO is not configured", true)
		return nil, false
	}
	return h.ssoSvc, true
}

// GetSSOProviders lists providers (metadata only). Spec api-sso AC-01.
func (h *handlers) GetSSOProviders(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.AdminSsoProvider); denied {
		return
	}
	svc, ok := h.ssoOrUnavailable(w)
	if !ok {
		return
	}
	list, err := svc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "list providers failed", true)
		return
	}
	out := make([]api.SSOProvider, len(list))
	for i, p := range list {
		out[i] = toAPISSOProvider(p)
	}
	writeJSON(w, http.StatusOK, api.SSOProviderList{Providers: out})
}

// PostSSOProvider creates a provider. Spec api-sso AC-02.
func (h *handlers) PostSSOProvider(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.AdminSsoProvider); denied {
		return
	}
	svc, ok := h.ssoOrUnavailable(w)
	if !ok {
		return
	}
	var req api.SSOProviderCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"name, issuer, client_id, client_secret required", false)
		return
	}
	p, err := svc.Create(r.Context(), sso.CreateParams{
		Name:         req.Name,
		Issuer:       req.Issuer,
		ClientID:     req.ClientId,
		ClientSecret: req.ClientSecret,
		Scopes:       deref(req.Scopes),
		DefaultRole:  derefOr(req.DefaultRole, "viewer"),
		Enabled:      derefBool(req.Enabled),
		CreatedBy:    callerUUID(r),
	})
	if err != nil {
		if errors.Is(err, sso.ErrInvalidParams) {
			writeError(w, http.StatusBadRequest, "sso.invalid", "client", err.Error(), false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "create provider failed", true)
		return
	}
	emitAudit(r, audit.AdminSsoProviderCreated, auth.FromContext(r.Context()).ID, map[string]any{
		"provider_id": p.ID.String(), "name": p.Name, "issuer": p.Issuer,
	})
	writeJSON(w, http.StatusCreated, toAPISSOProvider(p))
}

// GetSSOProvider returns one provider. Spec api-sso AC-01.
func (h *handlers) GetSSOProvider(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AdminSsoProvider); denied {
		return
	}
	svc, ok := h.ssoOrUnavailable(w)
	if !ok {
		return
	}
	p, err := svc.Get(r.Context(), uuid.UUID(id))
	if err != nil {
		if errors.Is(err, sso.ErrProviderNotFound) {
			writeError(w, http.StatusNotFound, "sso.not_found", "client", "provider not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "get provider failed", true)
		return
	}
	writeJSON(w, http.StatusOK, toAPISSOProvider(p))
}

// PutSSOProvider updates a provider. Spec api-sso AC-03.
func (h *handlers) PutSSOProvider(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AdminSsoProvider); denied {
		return
	}
	svc, ok := h.ssoOrUnavailable(w)
	if !ok {
		return
	}
	var req api.SSOProviderUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"name, issuer, client_id required", false)
		return
	}
	p, err := svc.Update(r.Context(), uuid.UUID(id), sso.UpdateParams{
		Name:         req.Name,
		Issuer:       req.Issuer,
		ClientID:     req.ClientId,
		ClientSecret: deref(req.ClientSecret),
		Scopes:       deref(req.Scopes),
		DefaultRole:  derefOr(req.DefaultRole, "viewer"),
		Enabled:      derefBool(req.Enabled),
	})
	if err != nil {
		switch {
		case errors.Is(err, sso.ErrProviderNotFound):
			writeError(w, http.StatusNotFound, "sso.not_found", "client", "provider not found", false)
		case errors.Is(err, sso.ErrInvalidParams):
			writeError(w, http.StatusBadRequest, "sso.invalid", "client", err.Error(), false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server", "update provider failed", true)
		}
		return
	}
	emitAudit(r, audit.AdminSsoProviderUpdated, auth.FromContext(r.Context()).ID, map[string]any{
		"provider_id": p.ID.String(), "name": p.Name, "enabled": p.Enabled,
	})
	writeJSON(w, http.StatusOK, toAPISSOProvider(p))
}

// DeleteSSOProvider removes a provider. Spec api-sso AC-04.
func (h *handlers) DeleteSSOProvider(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.AdminSsoProvider); denied {
		return
	}
	svc, ok := h.ssoOrUnavailable(w)
	if !ok {
		return
	}
	if err := svc.Delete(r.Context(), uuid.UUID(id)); err != nil {
		if errors.Is(err, sso.ErrProviderNotFound) {
			writeError(w, http.StatusNotFound, "sso.not_found", "client", "provider not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server", "delete provider failed", true)
		return
	}
	emitAudit(r, audit.AdminSsoProviderDeleted, auth.FromContext(r.Context()).ID, map[string]any{
		"provider_id": uuid.UUID(id).String(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// GetSSOProvidersEnabled lists enabled providers for the anonymous login
// picker (id + name only). Spec api-sso AC-05.
func (h *handlers) GetSSOProvidersEnabled(w http.ResponseWriter, r *http.Request) {
	if h.ssoSvc == nil {
		// No SSO wired → empty list (the login page simply renders no buttons).
		writeJSON(w, http.StatusOK, api.SSOEnabledList{Providers: []api.SSOEnabledProvider{}})
		return
	}
	list, err := h.ssoSvc.ListEnabled(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server", "list providers failed", true)
		return
	}
	out := make([]api.SSOEnabledProvider, len(list))
	for i, p := range list {
		out[i] = api.SSOEnabledProvider{Id: openapitypes.UUID(p.ID), Name: p.Name}
	}
	writeJSON(w, http.StatusOK, api.SSOEnabledList{Providers: out})
}

// GetAuthSSOLogin begins sign-in: builds the IdP authorization URL, persists
// the per-login state, and 302-redirects. Anonymous. Spec api-sso AC-06.
func (h *handlers) GetAuthSSOLogin(w http.ResponseWriter, r *http.Request, id openapitypes.UUID, params api.GetAuthSSOLoginParams) {
	if h.ssoSvc == nil {
		http.Redirect(w, r, "/login?sso_error=unavailable", http.StatusFound)
		return
	}
	redirectURI := ssoCallbackURI(r, id)
	returnTo := ssoSafeReturnTo(params.ReturnTo)
	authURL, err := h.ssoSvc.BuildAuthURL(r.Context(), uuid.UUID(id).String(), redirectURI, returnTo)
	if err != nil {
		emitLoginFailure(r, "sso_login_init_failed", "")
		http.Redirect(w, r, "/login?sso_error=provider", http.StatusFound)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GetAuthSSOCallback completes sign-in: validates state, exchanges the code,
// provisions/links the user, issues a session, and redirects into the app.
// Anonymous. Spec api-sso AC-07.
func (h *handlers) GetAuthSSOCallback(w http.ResponseWriter, r *http.Request, id openapitypes.UUID, params api.GetAuthSSOCallbackParams) {
	if h.ssoSvc == nil {
		http.Redirect(w, r, "/login?sso_error=unavailable", http.StatusFound)
		return
	}
	// IdP-reported error (user denied consent, etc.).
	if params.Error != nil && *params.Error != "" {
		emitLoginFailure(r, "sso_idp_error", "")
		http.Redirect(w, r, "/login?sso_error=denied", http.StatusFound)
		return
	}
	if params.Code == nil || *params.Code == "" || params.State == nil || *params.State == "" {
		http.Redirect(w, r, "/login?sso_error=invalid", http.StatusFound)
		return
	}

	redirectURI := ssoCallbackURI(r, id)
	provision := func(ctx context.Context, username, email, role string) (uuid.UUID, error) {
		u, err := h.users.CreateFederatedUser(ctx, username, email, auth.RoleID(role))
		if err != nil {
			return uuid.Nil, err
		}
		return u.ID, nil
	}
	result, err := h.ssoSvc.HandleCallback(r.Context(), *params.State, redirectURI, *params.Code, provision)
	if err != nil {
		emitLoginFailure(r, ssoFailureReason(err), "")
		http.Redirect(w, r, "/login?sso_error=signin", http.StatusFound)
		return
	}

	// Mint the session + refresh cookies (the session cookie is the
	// credential; no JSON body on a redirect). Mirrors PostAuthLogin.
	sessionToken, _, err := identity.IssueSession(r.Context(), h.pool, result.UserID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		http.Redirect(w, r, "/login?sso_error=session", http.StatusFound)
		return
	}
	refresh, err := identity.IssueRefreshToken(r.Context(), h.pool, result.UserID)
	if err != nil {
		http.Redirect(w, r, "/login?sso_error=session", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: identity.SessionCookieName, Value: sessionToken, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: identity.RefreshCookieName, Value: refresh, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(identity.RefreshTokenWindow.Seconds()),
	})
	emitAudit(r, audit.AuthLoginSuccess, result.UserID.String(), map[string]any{
		"method": "sso", "provider_id": uuid.UUID(id).String(), "provisioned": result.Provisioned,
	})
	http.Redirect(w, r, ssoSafeReturnTo(&result.RedirectTo), http.StatusFound)
}

func toAPISSOProvider(p sso.Provider) api.SSOProvider {
	updated := p.UpdatedAt
	return api.SSOProvider{
		Id:          openapitypes.UUID(p.ID),
		Name:        p.Name,
		Type:        p.Type,
		Issuer:      p.Issuer,
		ClientId:    p.ClientID,
		Scopes:      p.Scopes,
		DefaultRole: p.DefaultRole,
		Enabled:     p.Enabled,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   &updated,
	}
}

// ssoCallbackURI builds the absolute redirect_uri for a provider. It MUST
// be byte-identical between the login redirect and the callback (the IdP
// matches it), so both call this. Honors X-Forwarded-Proto/Host behind a
// proxy; defaults to https (the app serves TLS).
func ssoCallbackURI(r *http.Request, id openapitypes.UUID) string {
	scheme := "https"
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if xh := r.Header.Get("X-Forwarded-Host"); xh != "" {
		host = xh
	}
	return scheme + "://" + host + "/api/v1/auth/sso/" + uuid.UUID(id).String() + "/callback"
}

// ssoSafeReturnTo prevents open redirects: only same-site absolute paths
// are allowed; anything else falls back to /dashboard.
func ssoSafeReturnTo(raw *string) string {
	const def = "/dashboard"
	if raw == nil {
		return def
	}
	p := *raw
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return def
	}
	return p
}

func ssoFailureReason(err error) string {
	switch {
	case errors.Is(err, sso.ErrStateExpired):
		return "sso_state_expired"
	case errors.Is(err, sso.ErrStateNotFound):
		return "sso_state_invalid"
	case errors.Is(err, sso.ErrTokenValidation):
		return "sso_token_invalid"
	case errors.Is(err, sso.ErrDiscovery):
		return "sso_discovery_failed"
	default:
		return "sso_signin_failed"
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefOr(p *string, def string) string {
	if p == nil || *p == "" {
		return def
	}
	return *p
}

func derefBool(p *bool) bool {
	return p != nil && *p
}
