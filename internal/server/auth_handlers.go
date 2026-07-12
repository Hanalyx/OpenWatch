// Auth handlers implement the api-auth spec endpoints. Login is
// single-step with an optional otp; the openwatch_session cookie + a
// Bearer JWT are returned together so cookie and bearer paths share
// the same users row.
//
// Spec: app/specs/api/auth.spec.yaml.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"
)

// PostAuthLogin implements POST /auth/login.
// Spec api-auth/AC-01..AC-06, C-01..C-03.
func (h *handlers) PostAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req api.AuthLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"username and password are required", false)
		return
	}

	// Verify username/password. We treat "user not found" and "wrong
	// password" identically per spec C-02 — no enumeration oracle.
	u, err := h.users.VerifyUserPassword(r.Context(), req.Username, req.Password)
	if err != nil {
		reason := "wrong_password"
		if errors.Is(err, users.ErrUserNotFound) {
			reason = "unknown_user"
		}
		emitLoginFailure(r, reason, req.Username)
		writeError(w, http.StatusUnauthorized, "auth.invalid_credentials", "client",
			"invalid username or password", false)
		return
	}

	// A disabled account cannot authenticate. The client gets the same
	// generic "invalid username or password" (no account-state enumeration);
	// the audit trail records the specific reason.
	if u.DisabledAt != nil {
		emitLoginFailure(r, "account_disabled", req.Username)
		writeError(w, http.StatusUnauthorized, "auth.invalid_credentials", "client",
			"invalid username or password", false)
		return
	}

	// Check MFA enrollment. If enrolled, the otp is required.
	enrolled, err := mfaEnrolled(r.Context(), h, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"mfa lookup failed", true)
		return
	}
	if enrolled {
		otp := ""
		if req.Otp != nil {
			otp = *req.Otp
		}
		if otp == "" {
			emitLoginFailure(r, "mfa_required", req.Username)
			writeError(w, http.StatusUnauthorized, "auth.mfa_required", "client",
				"MFA OTP is required for this user", false)
			return
		}
		if err := identity.VerifyMFA(r.Context(), h.pool, u.ID, otp); err != nil {
			emitLoginFailure(r, "mfa_invalid", req.Username)
			emitAudit(r, audit.AuthMfaFailed, u.ID.String(), map[string]any{
				"reason": "otp_invalid_or_replayed",
			})
			writeError(w, http.StatusUnauthorized, "auth.mfa_invalid", "client",
				"MFA OTP invalid", false)
			return
		}
	}

	// Soft require-MFA enforcement: when workspace policy requires MFA but
	// this user has not enrolled, still issue the session (so they can reach
	// the auth-gated enrollment endpoint) but flag the response so the
	// client forces enrollment before anything else. Hard-blocking here
	// would lock out a user whose only path to enroll is behind login.
	// Spec system-auth-policy AC-03, AC-04.
	mfaEnrollmentRequired := false
	if !enrolled && h.authPolicySvc != nil {
		if pol, err := h.authPolicySvc.Get(r.Context()); err == nil && pol.RequireMFA {
			mfaEnrollmentRequired = true
		}
	}

	// Mint session + refresh + access tokens. All three share this users row.
	sessionToken, sess, err := identity.IssueSession(r.Context(), h.pool, u.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"session issue failed", true)
		return
	}
	role, _ := h.users.PrimaryRoleFor(r.Context(), u.ID)
	access, _, err := identity.IssueJWT(u.ID, string(role))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"jwt issue failed", true)
		return
	}
	// AUTH-1 (b): anchor the refresh lineage to the session's absolute deadline
	// so refreshing cannot extend the session past its absolute timeout.
	refresh, err := identity.IssueRefreshToken(r.Context(), h.pool, u.ID, sess.AbsoluteExpiresAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"refresh issue failed", true)
		return
	}

	// Set the session cookie. HttpOnly + Secure + SameSite=Lax per C-03.
	http.SetCookie(w, &http.Cookie{
		Name:     identity.SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Issue the double-submit CSRF token alongside the session so the SPA can
	// echo it on subsequent unsafe requests. Spec system-http-server C-14.
	setCSRFCookie(w, newCSRFToken())

	// Set the refresh cookie so the browser can call /auth/refresh-cookie
	// when the session expires. JS cannot read this cookie; only the
	// refresh-cookie endpoint consumes it. Same lifetime as the refresh
	// token itself (7 days, identity.RefreshTokenWindow).
	// Spec C-13 / AC-22.
	http.SetCookie(w, &http.Cookie{
		Name:     identity.RefreshCookieName,
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(identity.RefreshTokenWindow.Seconds()),
	})

	emitAudit(r, audit.AuthLoginSuccess, u.ID.String(), map[string]any{
		"username": u.Username,
	})

	resp := api.AuthLoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		User:         userToMe(u, string(role)),
	}
	if mfaEnrollmentRequired {
		resp.MfaEnrollmentRequired = &mfaEnrollmentRequired
	}
	writeJSON(w, http.StatusOK, resp)
}

// PostAuthLogout revokes the calling session by reading the cookie and
// deleting the session row. Also revokes the refresh token presented
// via the openwatch_refresh cookie so a stolen refresh cookie can't
// outlive an explicit logout. Always returns 204 (no oracle on whether
// the session/refresh existed).
//
// Spec api-auth + system-auth-identity AC-24.
func (h *handlers) PostAuthLogout(w http.ResponseWriter, r *http.Request) {
	id := auth.FromContext(r.Context())
	// If anonymous, this is a no-op — still 204 (logout is idempotent).
	if !id.IsAnonymous {
		// Find the session by cookie token and revoke it.
		if cookie, err := r.Cookie(identity.SessionCookieName); err == nil && cookie.Value != "" {
			if sess, err := identity.VerifySession(r.Context(), h.pool, cookie.Value); err == nil {
				_ = identity.RevokeSession(r.Context(), h.pool, sess.ID)
				emitAudit(r, audit.AuthLogout, id.ID, nil)
			}
		}
	}
	// Revoke the refresh token if the cookie carries one, regardless of
	// session state — explicit logout invalidates everything the user
	// was holding. Best-effort: an unparseable / unknown refresh cookie
	// is silently ignored (no oracle).
	if rc, err := r.Cookie(identity.RefreshCookieName); err == nil && rc.Value != "" {
		_ = identity.RevokeRefreshToken(r.Context(), h.pool, rc.Value)
	}
	// Clear both cookies in the same response.
	http.SetCookie(w, &http.Cookie{
		Name:     identity.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     identity.RefreshCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// PostAuthRefresh rotates the supplied refresh token.
// Spec AC-08, AC-09, C-04.
func (h *handlers) PostAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req api.AuthRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"refresh_token is required", false)
		return
	}

	// We don't know the user's role until after consume; pass "" and
	// let the package's reuse-detection cascade still fire.
	pair, err := identity.ConsumeRefreshToken(r.Context(), h.pool, req.RefreshToken, "")
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrRefreshTokenReused):
			writeError(w, http.StatusUnauthorized, "auth.refresh_reused", "policy",
				"refresh token reuse detected; all sessions revoked", false)
		case errors.Is(err, identity.ErrRefreshTokenExpired),
			errors.Is(err, identity.ErrRefreshTokenRevoked),
			errors.Is(err, identity.ErrRefreshTokenNotFound),
			errors.Is(err, identity.ErrRefreshSessionExpired):
			writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
				"refresh token invalid or expired", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"refresh failed", true)
		}
		return
	}

	// Re-mint the JWT with the current role (the role baked into pair.Claims
	// was empty because we passed "" above; that's the contract).
	userID, _ := uuid.Parse(pair.Claims.Subject)
	role, _ := h.users.PrimaryRoleFor(r.Context(), userID)
	access, _, err := identity.IssueJWT(userID, string(role))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"jwt issue failed", true)
		return
	}
	u, _ := h.users.GetUserByID(r.Context(), userID)
	writeJSON(w, http.StatusOK, api.AuthLoginResponse{
		AccessToken:  access,
		RefreshToken: pair.RefreshToken,
		User:         userToMe(u, string(role)),
	})
}

// PostAuthRefreshCookie consumes the openwatch_refresh cookie, rotates
// the refresh token, mints a new session, and Set-Cookies both. The
// browser uses this on transparent retry from its API client when a
// regular request returns 401 — it never has to redirect to /login as
// long as the refresh window (7 days) is still open.
//
// Spec system-auth-identity AC-23, C-14.
func (h *handlers) PostAuthRefreshCookie(w http.ResponseWriter, r *http.Request) {
	rc, err := r.Cookie(identity.RefreshCookieName)
	if err != nil || rc.Value == "" {
		clearAuthCookies(w)
		writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
			"refresh cookie missing", false)
		return
	}

	pair, err := identity.ConsumeRefreshToken(r.Context(), h.pool, rc.Value, "")
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrRefreshTokenReused):
			clearAuthCookies(w)
			writeError(w, http.StatusUnauthorized, "auth.refresh_reused", "policy",
				"refresh token reuse detected; all sessions revoked", false)
		case errors.Is(err, identity.ErrRefreshTokenExpired),
			errors.Is(err, identity.ErrRefreshTokenRevoked),
			errors.Is(err, identity.ErrRefreshTokenNotFound):
			clearAuthCookies(w)
			writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
				"refresh token invalid or expired", false)
		case errors.Is(err, identity.ErrRefreshSessionExpired):
			// AUTH-1 (b): the session's absolute timeout has passed. Refusing to
			// refresh is the whole point — clear cookies and make the browser
			// re-authenticate rather than silently extend past the ceiling.
			clearAuthCookies(w)
			writeError(w, http.StatusUnauthorized, "auth.session_expired", "client",
				"session absolute timeout reached; please sign in again", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"refresh failed", true)
		}
		return
	}

	userID, _ := uuid.Parse(pair.Claims.Subject)
	role, _ := h.users.PrimaryRoleFor(r.Context(), userID)

	// Mint a new session, but carry the ORIGINAL absolute deadline so the
	// refresh cannot reset the absolute ceiling (AUTH-1 b). Legacy refresh
	// tokens (minted before migration 0047, no carried deadline) fall back to a
	// fresh window until they age out within 7 days.
	var sessionToken string
	if pair.AbsoluteExpiresAt.IsZero() {
		sessionToken, _, err = identity.IssueSession(r.Context(), h.pool, userID, r.RemoteAddr, r.UserAgent())
	} else {
		sessionToken, _, err = identity.IssueSessionWithAbsolute(r.Context(), h.pool, userID, r.RemoteAddr, r.UserAgent(), pair.AbsoluteExpiresAt)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"session issue failed", true)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     identity.SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// Rotate the CSRF token with the session. Spec system-http-server C-14.
	setCSRFCookie(w, newCSRFToken())
	http.SetCookie(w, &http.Cookie{
		Name:     identity.RefreshCookieName,
		Value:    pair.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(identity.RefreshTokenWindow.Seconds()),
	})

	u, _ := h.users.GetUserByID(r.Context(), userID)
	writeJSON(w, http.StatusOK, userToMe(u, string(role)))
}

// clearAuthCookies emits Set-Cookie headers that delete both auth
// cookies. Used by the refresh-cookie endpoint on any rejection so
// the browser doesn't keep re-presenting a known-bad refresh cookie.
func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     identity.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     identity.RefreshCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetAuthMe returns the calling identity.
// Spec AC-10, C-06.
func (h *handlers) GetAuthMe(w http.ResponseWriter, r *http.Request) {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"authentication required", false)
		return
	}
	userID, err := uuid.Parse(id.ID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity id is not a UUID", false)
		return
	}
	u, err := h.users.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity user not found", false)
		return
	}
	writeJSON(w, http.StatusOK, userToMe(u, string(id.RoleID)))
}

// PostAuthMFAEnroll enrolls the calling user in TOTP.
// Spec AC-11.
func (h *handlers) PostAuthMFAEnroll(w http.ResponseWriter, r *http.Request) {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"authentication required", false)
		return
	}
	userID, err := uuid.Parse(id.ID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity id is not a UUID", false)
		return
	}
	u, err := h.users.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity user not found", false)
		return
	}
	uri, err := identity.EnrollMFA(r.Context(), h.pool, userID, u.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"mfa enroll failed", true)
		return
	}
	emitAudit(r, audit.AuthMfaEnrolled, id.ID, nil)
	writeJSON(w, http.StatusOK, api.AuthMFAEnrollResponse{ProvisioningUri: uri})
}

// PostAuthMFAVerify is the confirmation step after enroll: the user
// enters the first OTP from their authenticator app to prove the
// secret was loaded correctly.
func (h *handlers) PostAuthMFAVerify(w http.ResponseWriter, r *http.Request) {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"authentication required", false)
		return
	}
	var req api.AuthMFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Otp == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"otp is required", false)
		return
	}
	userID, _ := uuid.Parse(id.ID)
	if err := identity.VerifyMFA(r.Context(), h.pool, userID, req.Otp); err != nil {
		emitAudit(r, audit.AuthMfaFailed, id.ID, nil)
		writeError(w, http.StatusUnauthorized, "auth.mfa_invalid", "client",
			"OTP invalid or replayed", false)
		return
	}
	emitAudit(r, audit.AuthMfaValidated, id.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// PostAuthPasswordChange updates the calling user's password.
// Spec AC-12, C-05.
func (h *handlers) PostAuthPasswordChange(w http.ResponseWriter, r *http.Request) {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"authentication required", false)
		return
	}
	var req api.AuthPasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"current_password and new_password are required", false)
		return
	}
	userID, _ := uuid.Parse(id.ID)
	u, err := h.users.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity user not found", false)
		return
	}
	// Verify current password.
	if _, err := h.users.VerifyUserPassword(r.Context(), u.Username, req.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "auth.invalid_credentials", "client",
			"current password is wrong", false)
		return
	}
	// Apply new password — re-runs the NIST policy validator inside.
	if err := h.users.UpdatePassword(r.Context(), userID, req.NewPassword); err != nil {
		// Map policy errors to 400; everything else to 500.
		writeError(w, http.StatusBadRequest, "auth.password_policy", "client",
			err.Error(), false)
		return
	}
	emitAudit(r, audit.AuthPasswordChanged, id.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// userToMe maps a users.User + role string into the AuthMeResponse shape.
// Admin status is implicit in role == "admin"; no separate field is
// surfaced.
func userToMe(u users.User, role string) api.AuthMeResponse {
	return api.AuthMeResponse{
		Id:          openapitypes.UUID(u.ID),
		Username:    u.Username,
		Email:       u.Email,
		Role:        role,
		FullName:    &u.FullName,
		DisplayName: &u.DisplayName,
		JobTitle:    &u.JobTitle,
		Timezone:    &u.Timezone,
		Phone:       &u.Phone,
	}
}

// PatchAuthMe applies a partial self-profile update for the calling user.
// Spec api-auth AC (patchAuthMe): present fields update, omitted stay;
// email must be unique among active users (409). Username/role/password
// are not editable here.
func (h *handlers) PatchAuthMe(w http.ResponseWriter, r *http.Request) {
	id := auth.FromContext(r.Context())
	if id.IsAnonymous {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"authentication required", false)
		return
	}
	userID, err := uuid.Parse(id.ID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity id is not a UUID", false)
		return
	}
	var req api.AuthMeUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.malformed", "client",
			"malformed request body", false)
		return
	}
	u, err := h.users.UpdateProfile(r.Context(), userID, users.ProfileUpdate{
		Email:       req.Email,
		FullName:    req.FullName,
		DisplayName: req.DisplayName,
		JobTitle:    req.JobTitle,
		Timezone:    req.Timezone,
		Phone:       req.Phone,
	})
	switch {
	case errors.Is(err, users.ErrEmailTaken):
		writeError(w, http.StatusConflict, "users.email_taken", "client",
			"that email is already in use by another account", false)
		return
	case errors.Is(err, users.ErrInvalidProfile):
		writeError(w, http.StatusBadRequest, "validation.field_invalid", "client",
			"invalid profile field", false)
		return
	case errors.Is(err, users.ErrUserNotFound):
		writeError(w, http.StatusUnauthorized, "auth.required", "client",
			"identity user not found", false)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal.error", "server",
			"failed to update profile", false)
		return
	}
	writeJSON(w, http.StatusOK, userToMe(u, string(id.RoleID)))
}

// mfaEnrolled returns whether the user has a VERIFIED MFA secret. A secret
// row alone is not enough: EnrollMFA writes the secret with last_verified_at
// NULL when a user *begins* enrollment, and VerifyMFA stamps last_verified_at
// once they prove they hold the authenticator. Gating login on mere row
// presence would lock out a user who started enrollment but never verified
// (e.g. closed the QR before scanning) — they would be asked for an OTP they
// cannot produce, with no recovery codes to fall back on. Only a verified
// secret requires an OTP at sign-in.
func mfaEnrolled(ctx context.Context, h *handlers, userID uuid.UUID) (bool, error) {
	var count int64
	err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM auth_mfa_secrets WHERE user_id = $1 AND last_verified_at IS NOT NULL`, userID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// emitLoginFailure is the audit-emission helper for the various login
// rejection paths. Centralized so the detail.reason vocabulary stays
// consistent across paths.
func emitLoginFailure(r *http.Request, reason, username string) {
	emitAudit(r, audit.AuthLoginFailure, "anonymous", map[string]any{
		"reason":   reason,
		"username": audit.ClipDetail(username),
	})
}

// emitAudit wraps audit.Emit with the canonical detail shape.
func emitAudit(r *http.Request, code audit.Code, actorID string, detail map[string]any) {
	var detailBytes []byte
	if detail != nil {
		detailBytes, _ = json.Marshal(detail)
	}
	audit.Emit(r.Context(), code, audit.Event{
		ActorType: "user",
		ActorID:   actorID,
		Detail:    detailBytes,
	})
}
