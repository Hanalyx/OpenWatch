// Auth handlers implement the api-auth spec endpoints. Login is
// single-step with an optional otp; the openwatch_session cookie + a
// Bearer JWT are returned together so cookie and bearer paths share
// the same users row.
//
// Spec: specs/api/auth.spec.yaml.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	// Check MFA enrollment. If enrolled, the otp is required. Enrollment
	// is a read, so it happens before the transaction; the OTP itself is
	// CONSUMED inside it (C-35).
	enrolled, err := mfaEnrolled(r.Context(), h, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"mfa lookup failed", true)
		return
	}
	otp := ""
	if req.Otp != nil {
		otp = *req.Otp
	}
	// Answer the "you need an OTP" case before the transaction so the
	// client gets it without a lock round trip. The AUTHORITATIVE
	// enrollment read happens under the lock below, because this one can
	// be stale by the time anything is issued.
	if enrolled && otp == "" {
		emitLoginFailure(r, "mfa_required", req.Username)
		writeError(w, http.StatusUnauthorized, "auth.mfa_required", "client",
			"MFA OTP is required for this user", false)
		return
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

	// Everything that reads account state and then issues runs in ONE
	// transaction that holds the per-user lock. Password verification
	// stayed outside it on purpose: Argon2id is deliberately expensive and
	// holding a row lock across it would serialize every login for the
	// user behind one key-stretching cost. Spec C-34.
	var (
		sessionToken string
		sess         identity.Session
		access       string
		refresh      string
		role         auth.RoleID
		loginRefused string
	)
	txErr := identity.RunSerialized(r.Context(), h.serialized(), u.ID, func(ctx context.Context, tx pgx.Tx) error {
		// Reset per attempt: RunSerialized may restart the whole
		// transaction, and a value carried over from a rolled-back
		// attempt would be reported as if it were durable.
		sessionToken, access, refresh, loginRefused = "", "", "", ""
		sess = identity.Session{}

		// Revalidate account state UNDER the lock. The check before the
		// transaction is not enough: a disable can commit between the
		// password check and here, and that window is exactly the race
		// an administrator's lockout must not lose. Spec C-34.
		status, err := identity.ReadAccountStatus(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if !status.MayAuthenticate() {
			loginRefused = status.Reason()
			return nil
		}
		// Account state is not the only stale input. The password was
		// verified BEFORE this transaction and MFA enrollment was read
		// before it too, and both can change in between. Re-read them
		// under the lock and let the locked values decide. Spec C-39.
		inputs, err := identity.ReadAuthInputs(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		// An administrative reset (or a self-service change) that commits
		// between the password check and here invalidates the credential
		// this request presented. Issuing now would hand out fresh
		// credentials on the strength of a password that no longer opens
		// the account. last_password_change_at is bumped by the only
		// statement that writes password_hash, so a change is always
		// visible here.
		if !inputs.PasswordUnchangedSince(u.LastPasswordChangeAt) {
			loginRefused = "password_changed_during_login"
			return nil
		}
		// The locked enrollment value is authoritative in BOTH
		// directions. Enrollment completing mid-login must not let a
		// login through without an OTP; enrollment being removed
		// mid-login must not fail a login on an OTP that no longer has a
		// secret to verify against.
		if inputs.MFAEnrolled && otp == "" {
			loginRefused = "mfa_required_during_login"
			return nil
		}
		// The OTP is consumed HERE, inside the issuing transaction. On the
		// pool it would be burned by a later issuance failure and the user
		// could not retry with the code still on their screen. Spec C-35.
		if inputs.MFAEnrolled {
			if err := identity.VerifyMFA(ctx, tx, u.ID, otp); err != nil {
				// Only a REFUSAL is a login refusal. A failure to find
				// out goes back to the runner so the transaction rolls
				// back and the commit outcome is classified, rather than
				// being reported to the user as a bad code. Spec C-32.
				if !identity.IsMFARejection(err) {
					return err
				}
				loginRefused = "mfa_invalid"
				return nil
			}
		}
		var err2 error
		sessionToken, sess, err2 = identity.IssueSession(ctx, tx, u.ID, r.RemoteAddr, r.UserAgent())
		if err2 != nil {
			return err2
		}
		role, _ = h.users.PrimaryRoleFor(ctx, u.ID)
		access, _, err2 = identity.IssueJWTForSession(u.ID, string(role), sess.ID)
		if err2 != nil {
			return err2
		}
		// AUTH-1 (b): anchor the refresh lineage to the session's absolute
		// deadline so refreshing cannot extend past the absolute timeout.
		refresh, err2 = identity.IssueRefreshTokenForSession(ctx, tx, u.ID, sess.ID, sess.AbsoluteExpiresAt)
		return err2
	})
	switch {
	case errors.Is(txErr, identity.ErrCommitUnknown):
		// Neither result is asserted: a session may or may not exist.
		// NOT retryable, and the message says nothing about retrying. An
		// automatic replay could issue a second set of credentials for a
		// first set that already committed. Spec C-37, C-40.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"the sign-in outcome is unknown; sign in again to obtain a known credential", false)
		return
	case txErr != nil:
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"sign-in temporarily unavailable", true)
		return
	}
	if loginRefused != "" {
		emitLoginFailure(r, loginRefused, req.Username)
		if loginRefused == "mfa_required_during_login" {
			// Enrollment completed while this login was in flight. Same
			// answer as the pre-transaction case: the client needs an OTP.
			writeError(w, http.StatusUnauthorized, "auth.mfa_required", "client",
				"MFA OTP is required for this user", false)
			return
		}
		if loginRefused == "mfa_invalid" {
			emitAudit(r, audit.AuthMfaFailed, u.ID.String(), map[string]any{
				"reason": "otp_invalid_or_replayed",
			})
			writeError(w, http.StatusUnauthorized, "auth.mfa_invalid", "client",
				"MFA OTP invalid", false)
			return
		}
		writeError(w, http.StatusUnauthorized, "auth.invalid_credentials", "client",
			"invalid username or password", false)
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
	// revokeFailed tracks whether we could NOT guarantee the credential is
	// dead server-side. Logout previously discarded both revoke errors and
	// answered 204 unconditionally. That is a lie with consequences: the
	// cookies are cleared either way, so the user sees a successful logout and
	// stops worrying, while a stolen session or refresh token stays valid.
	// Someone logging out on a shared or compromised machine is exactly the
	// person who cannot afford that.
	revokeFailed := false
	// revokeUnknown is set when the revocation transaction's commit outcome
	// is indeterminate. It is NOT a failure: the family may already be
	// revoked. Spec C-37, C-40.
	revokeUnknown := false

	// Logout ends ONE login family, located by the cookies the request
	// carries. The session cookie is consulted first: that is the
	// target-precedence policy, not a claim that it is the more
	// trustworthy credential. An idle-expired or otherwise unusable
	// session cookie still LOCATES its family here, so the identity the
	// binder attached is deliberately not required; the lookup is scoped
	// to logout and authorizes nothing else. Spec C-41.
	var anchors identity.LogoutAnchors
	if c, err := r.Cookie(identity.SessionCookieName); err == nil {
		anchors.SessionToken = c.Value
	}
	if c, err := r.Cookie(identity.RefreshCookieName); err == nil {
		anchors.RefreshToken = c.Value
	}

	// CSRF, enforced HERE. The middleware exempts every /api/v1/auth/*
	// route, every request carrying an Authorization header, and every
	// request without a session cookie, so none of its checks reach this
	// handler. When either credential cookie selects what to revoke, the
	// cookie is the authority and a cross-site request could carry it, so
	// the double-submit token is required. An Authorization header does not
	// change that: it authenticates nothing here, because the cookies pick
	// the target.
	//
	// The refusal comes before any revocation and before the cookies are
	// cleared, so a refused request changes nothing on either side.
	//
	// Known limitation, accepted: the XSRF cookie is a browser-session
	// cookie and the refresh cookie lasts seven days, so after a browser
	// restart a client can hold a refresh cookie and no XSRF cookie. That
	// client cannot complete this request until it obtains an XSRF cookie
	// some other way. Nothing here assumes a startup refresh supplies one.
	// Spec C-42.
	if anchors.SessionToken != "" || anchors.RefreshToken != "" {
		if !validDoubleSubmit(r) {
			writeCSRFInvalid(w)
			return
		}
	}

	owner, found, lerr := identity.LocateLogoutOwner(r.Context(), h.pool, anchors)
	switch {
	case lerr != nil:
		revokeFailed = true
		slog.ErrorContext(r.Context(), "logout: could not locate the family to revoke",
			slog.String("error", lerr.Error()))
	case found:
		// Resolution and revocation run in ONE transaction under the
		// same per-user lock as rotation, so a concurrent refresh cannot
		// add a live member to the family between the walk and the
		// revoke. Any failure rolls back every revocation: there is no
		// partial success and no fallback to revoking the whole user.
		var target identity.LogoutTarget
		txErr := identity.RunSerialized(r.Context(), h.serialized(), owner, func(ctx context.Context, tx pgx.Tx) error {
			target = identity.LogoutTarget{}
			t, err := identity.ResolveLogoutFamily(ctx, tx, owner, anchors)
			if err != nil {
				return err
			}
			target = t
			return identity.RevokeLogoutFamily(ctx, tx, t)
		})
		switch {
		case errors.Is(txErr, identity.ErrCommitUnknown):
			// The commit may have applied. Neither success nor rollback
			// is asserted, here or in the response.
			revokeUnknown = true
			slog.ErrorContext(r.Context(), "logout: revocation outcome unknown; the family may or may not be revoked",
				slog.String("user_id", owner.String()),
				slog.String("error", txErr.Error()))
		case txErr != nil:
			// A determinate failure: the transaction rolled back, so
			// nothing was revoked. No credential values are logged.
			revokeFailed = true
			slog.ErrorContext(r.Context(), "logout: family revocation failed and rolled back; nothing was revoked",
				slog.String("user_id", owner.String()),
				slog.String("error", txErr.Error()))
		case target.Anchor != "":
			// target_conflict records that the two cookies named
			// different families and only the session cookie's was
			// ended. It carries no token material.
			emitAudit(r, audit.AuthLogout, owner.String(), map[string]any{
				"anchor":          target.Anchor,
				"target_conflict": target.Conflict,
			})
		}
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
	// Cookies are cleared above regardless, so the browser stops presenting
	// the credential either way. But if the server could not revoke, say so
	// rather than reporting a clean logout: the client needs to know the
	// credential may still be live so a human can revoke the session
	// explicitly or rotate.
	if revokeUnknown {
		// Not retryable, and no claim either way. Spec C-40.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"signed out on this device, but revocation of your session could not be confirmed. Check your active sessions in Settings.", false)
		return
	}
	if revokeFailed {
		writeError(w, http.StatusInternalServerError, "auth.logout_incomplete", "server",
			"signed out on this device, but the server could not revoke the session. It may remain valid until it expires. Revoke it from Settings or contact an administrator.", true)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PostAuthRefresh rotates the supplied refresh token.
// refreshResult is what a serialized refresh transaction produced. The
// zero value carries no credentials and an undetermined outcome, so a
// caller that forgets a branch cannot answer 200 with nothing.
type refreshResult struct {
	outcome  identity.RefreshOutcome
	pair     *identity.TokenPair
	userID   uuid.UUID
	role     auth.RoleID
	refused  string // account-state refusal reason, "" when the account is fine
	newToken string // session cookie value, cookie path only
}

// runSerializedRefresh is the shared body of both refresh paths: resolve
// the owner, take the per-user lock, revalidate account state under it,
// rotate, and issue. The rotation helper owns no transaction, so the
// rotated row and whatever is issued from it commit together or not at
// all. Spec C-34.
//
// issue runs after a successful rotation and inside the same
// transaction, so the cookie path can mint its session there.
func (h *handlers) runSerializedRefresh(
	r *http.Request,
	presented string,
	issue func(ctx context.Context, tx pgx.Tx, res *refreshResult) error,
) (refreshResult, error) {
	var res refreshResult
	owner, err := identity.UserIDForRefreshToken(r.Context(), h.pool, presented)
	if err != nil {
		// An unknown token has no owner to lock. Answer from the
		// outcome rather than inventing a user.
		if errors.Is(err, identity.ErrRefreshTokenNotFound) {
			res.outcome = identity.RefreshNotFound
			return res, nil
		}
		return res, err
	}
	txErr := identity.RunSerialized(r.Context(), h.serialized(), owner, func(ctx context.Context, tx pgx.Tx) error {
		// Reset per attempt: RunSerialized may restart the transaction
		// and a value from a rolled-back attempt is not durable.
		res = refreshResult{}

		status, err := identity.ReadAccountStatus(ctx, tx, owner)
		if err != nil {
			return err
		}
		if !status.MayAuthenticate() {
			// Refuse before rotating. Rotating first would consume the
			// user's token to no purpose and, on a later retry, look
			// like reuse.
			res.refused = status.Reason()
			return nil
		}
		outcome, pair, err := identity.ConsumeRefreshTokenTx(ctx, tx, presented, "")
		if err != nil {
			return err
		}
		res.outcome, res.pair, res.userID = outcome, pair, owner
		if outcome != identity.RefreshRotated {
			// Reuse revoked the family inside this transaction; letting
			// it commit is the point. MustCommit says so.
			return nil
		}
		res.role, _ = h.users.PrimaryRoleFor(ctx, owner)
		if issue != nil {
			return issue(ctx, tx, &res)
		}
		return nil
	})
	return res, txErr
}

// writeRefreshTxError maps a failed refresh transaction onto a response.
// An unknown commit outcome asserts neither result. Spec C-37.
func writeRefreshTxError(w http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrCommitUnknown) {
		// The rotation may ALREADY have committed. Presenting the
		// predecessor again is indistinguishable from theft and revokes
		// the whole family, so this outcome must not invite a retry:
		// retryable is false and the message tells the client to
		// re-authenticate rather than replay. Spec C-37, C-40.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"the refresh outcome is unknown; sign in again rather than presenting the same token", false)
		return
	}
	writeError(w, http.StatusServiceUnavailable, "server.error", "server",
		"refresh temporarily unavailable", true)
}

// PostAuthRefresh implements POST /auth/refresh (body token).
func (h *handlers) PostAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req api.AuthRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"refresh_token is required", false)
		return
	}

	res, txErr := h.runSerializedRefresh(r, req.RefreshToken, nil)
	if txErr != nil {
		writeRefreshTxError(w, txErr)
		return
	}
	// A refused account gets the same generic answer as an invalid token:
	// the refresh surface is not an account-state oracle.
	if res.refused != "" {
		emitLoginFailure(r, res.refused, "")
		writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
			"refresh token invalid or expired", false)
		return
	}
	switch res.outcome {
	case identity.RefreshRotated:
	case identity.RefreshReused:
		writeError(w, http.StatusUnauthorized, "auth.refresh_reused", "policy",
			"refresh token reuse detected; all sessions revoked", false)
		return
	case identity.RefreshExpired, identity.RefreshRevoked,
		identity.RefreshNotFound, identity.RefreshSessionExpired,
		identity.RefreshSessionRevoked:
		writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
			"refresh token invalid or expired", false)
		return
	default:
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"refresh outcome undetermined", true)
		return
	}

	// Re-mint the JWT with the current role (the role baked into
	// pair.Claims was empty because we passed "" above; that's the
	// contract). This is a pure computation over an already-committed
	// rotation, so it stays outside the transaction.
	// Preserve the session binding the rotation established. Re-minting
	// with IssueJWT would drop `sid` and hand back an unbound token,
	// which the binder refuses. Spec C-38.
	access, _, err := identity.IssueJWTForSession(res.userID, string(res.role), res.pair.SessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"jwt issue failed", true)
		return
	}
	u, _ := h.users.GetUserByID(r.Context(), res.userID)
	writeJSON(w, http.StatusOK, api.AuthLoginResponse{
		AccessToken:  access,
		RefreshToken: res.pair.RefreshToken,
		User:         userToMe(u, string(res.role)),
	})
}

// PostAuthRefreshCookie implements POST /auth/refresh-cookie.
func (h *handlers) PostAuthRefreshCookie(w http.ResponseWriter, r *http.Request) {
	rc, err := r.Cookie(identity.RefreshCookieName)
	if err != nil || rc.Value == "" {
		clearAuthCookies(w)
		writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
			"refresh cookie missing", false)
		return
	}

	res, txErr := h.runSerializedRefresh(r, rc.Value, func(ctx context.Context, tx pgx.Tx, res *refreshResult) error {
		// Mint the new session INSIDE the rotation's transaction, and
		// carry the ORIGINAL absolute deadline so a refresh cannot reset
		// the absolute ceiling (AUTH-1 b). Legacy tokens with no carried
		// deadline fall back to a fresh window until they age out.
		var err error
		var newSess identity.Session
		if res.pair.AbsoluteExpiresAt.IsZero() {
			res.newToken, newSess, err = identity.IssueSession(ctx, tx, res.userID, r.RemoteAddr, r.UserAgent())
		} else {
			res.newToken, newSess, err = identity.IssueSessionWithAbsolute(ctx, tx, res.userID,
				r.RemoteAddr, r.UserAgent(), res.pair.AbsoluteExpiresAt)
		}
		newSessionID := newSess.ID
		if err != nil {
			return err
		}
		// The rotation carried the OLD session id onto the new row. This
		// path just minted a new session, so the row must follow it.
		return identity.RebindRefreshToSession(ctx, tx, res.pair.NewRefreshID, newSessionID)
	})
	if txErr != nil {
		writeRefreshTxError(w, txErr)
		return
	}
	if res.refused != "" {
		emitLoginFailure(r, res.refused, "")
		clearAuthCookies(w)
		writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
			"refresh token invalid or expired", false)
		return
	}
	switch res.outcome {
	case identity.RefreshRotated:
	case identity.RefreshReused:
		clearAuthCookies(w)
		writeError(w, http.StatusUnauthorized, "auth.refresh_reused", "policy",
			"refresh token reuse detected; all sessions revoked", false)
		return
	case identity.RefreshSessionExpired:
		// AUTH-1 (b): refusing to refresh past the ceiling is the point.
		clearAuthCookies(w)
		writeError(w, http.StatusUnauthorized, "auth.session_expired", "client",
			"session absolute timeout reached; please sign in again", false)
		return
	case identity.RefreshExpired, identity.RefreshRevoked,
		identity.RefreshNotFound, identity.RefreshSessionRevoked:
		clearAuthCookies(w)
		writeError(w, http.StatusUnauthorized, "auth.refresh_invalid", "client",
			"refresh token invalid or expired", false)
		return
	default:
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"refresh outcome undetermined", true)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     identity.SessionCookieName,
		Value:    res.newToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// Rotate the CSRF token with the session. Spec system-http-server C-14.
	setCSRFCookie(w, newCSRFToken())
	http.SetCookie(w, &http.Cookie{
		Name:     identity.RefreshCookieName,
		Value:    res.pair.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(identity.RefreshTokenWindow.Seconds()),
	})

	u, _ := h.users.GetUserByID(r.Context(), res.userID)
	writeJSON(w, http.StatusOK, userToMe(u, string(res.role)))
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
	// Under the per-user lock, so enrollment serializes against an
	// in-flight login. Login re-reads enrollment under the same lock and
	// lets the locked value decide; without taking it here the two could
	// interleave so that a login observes neither the old state nor the
	// new one consistently. Spec C-34, C-39.
	var uri string
	err = identity.RunSerialized(r.Context(), h.serialized(), userID, func(ctx context.Context, tx pgx.Tx) error {
		var ierr error
		uri, ierr = identity.EnrollMFA(ctx, tx, userID, u.Username)
		return ierr
	})
	if err != nil {
		// An unknown commit outcome is NOT a failed enrollment: the
		// secret may already be stored. Saying "enroll failed" would
		// invite the user to enroll again and, if the first attempt did
		// commit, replace a secret their authenticator app already
		// holds. Spec C-40.
		if errors.Is(err, identity.ErrCommitUnknown) {
			writeError(w, http.StatusServiceUnavailable, "server.error", "server",
				"the enrollment outcome is unknown; check whether MFA is enrolled before enrolling again", false)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"mfa enrollment is temporarily unavailable", true)
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
	// Under the per-user lock: this call is what CONFIRMS enrollment (it
	// stamps last_verified_at), so it is the mutation a concurrent login
	// must not straddle. Spec C-34, C-39.
	// Three outcomes, and they must not be conflated. An OTP the server
	// REJECTED is a client failure and is audited as one. An
	// infrastructure failure is not: calling a database outage an invalid
	// OTP sends the user to their authenticator app for a code that was
	// never the problem, and writes an authentication-failure event that
	// did not happen. An UNKNOWN outcome is neither, because the
	// confirmation may already have committed.
	var otpRejected bool
	txErr := identity.RunSerialized(r.Context(), h.serialized(), userID, func(ctx context.Context, tx pgx.Tx) error {
		// Reset per attempt: RunSerialized may restart the transaction.
		otpRejected = false
		if err := identity.VerifyMFA(ctx, tx, userID, req.Otp); err != nil {
			if !identity.IsMFARejection(err) {
				// A failure to find out. Hand it back so the runner
				// rolls back and classifies it. Spec C-32.
				return err
			}
			// The OTP itself was refused: determinate, nothing to retry.
			otpRejected = true
			return nil
		}
		return nil
	})
	// The transaction outcome is read FIRST. A recorded rejection must
	// not conceal a transaction that failed or whose result is unknown:
	// answering 401 would tell the user their code was bad while the
	// server has no idea what it committed.
	switch {
	case errors.Is(txErr, identity.ErrCommitUnknown):
		// The confirmation may have committed. Claiming it failed is
		// wrong in the direction that matters: the user would retry a
		// code that is now consumed and be told it is invalid.
		// Spec C-40.
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"the confirmation outcome is unknown; check whether MFA is enrolled before trying another code", false)
		return
	case txErr != nil:
		writeError(w, http.StatusServiceUnavailable, "server.error", "server",
			"mfa confirmation is temporarily unavailable", true)
		return
	case otpRejected:
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
	emitAudit(r, audit.AuthProfileUpdated, id.ID, map[string]any{
		"email_changed": req.Email != nil,
	})
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
