package identity

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionCookieName is the cookie the browser path uses for session
// presentation tokens. Server-set; client reads it back over HTTPS.
const SessionCookieName = "openwatch_session"

// BackgroundRefreshHeader marks a request as NOT user-initiated (a background
// poll, an SSE reconnect) so the binder verifies the session without sliding
// its idle window. The SPA sets it on recurring/background fetches; ordinary
// user-driven navigation and mutations omit it and slide as before. AUTH-1 (c).
const BackgroundRefreshHeader = "X-Background-Refresh"

// sseEventsPath is the live-events SSE stream. EventSource cannot set custom
// headers, so it can never send BackgroundRefreshHeader; yet it is a long-lived
// background subscription that reconnects (often through a proxy idle-timeout).
// Treating it as user activity would let an open SPA keep an unattended session
// alive forever, defeating the idle timeout — so the binder never slides for it.
// AUTH-1 (c).
const sseEventsPath = "/api/v1/events"

// authBypassPaths are credential-lifecycle endpoints where the binder
// MUST NOT 401 on a stale session cookie — they handle their own
// credential semantics. Login does not need any cookie; logout is
// idempotent for stale sessions; the refresh-cookie endpoint reads
// the refresh cookie, not the session cookie, so a stale session
// presented alongside is not an error there.
//
// Spec system-auth-identity C-12 / AC-21 (bypass list).
// logoutPath is the one credential route that verifies without sliding.
const logoutPath = "/api/v1/auth/logout"

// boundedOperation reports whether a request's handler runs credential or
// account-state transactions, and so inherits the binder's deadline.
func boundedOperation(r *http.Request) bool {
	p := r.URL.Path
	if _, ok := authBypassPaths[p]; ok {
		return true
	}
	switch p {
	case "/api/v1/auth/mfa:enroll", "/api/v1/auth/mfa:verify":
		return true
	}
	if strings.HasPrefix(p, "/api/v1/auth/sso/") && strings.HasSuffix(p, "/callback") {
		return true
	}
	if rest, ok := strings.CutPrefix(p, "/api/v1/users/"); ok && !strings.Contains(rest, "/") {
		switch {
		case r.Method == http.MethodPost && (strings.HasSuffix(rest, ":disable") ||
			strings.HasSuffix(rest, ":enable") || strings.HasSuffix(rest, ":reset-password")):
			return true
		case r.Method == http.MethodDelete && !strings.Contains(rest, ":"):
			return true
		}
	}
	return false
}

var authBypassPaths = map[string]struct{}{
	"/api/v1/auth/login":          {},
	"/api/v1/auth/logout":         {},
	"/api/v1/auth/refresh":        {},
	"/api/v1/auth/refresh-cookie": {},
}

// Lookups is the interface the binder uses to translate a user_id into
// the role it needs to attach to auth.Identity. Decoupled from the
// users package (which doesn't exist yet — Week 1 Day 2 task) so the
// binder + its tests can wire up before that package lands.
//
// Implementation lives in Slice A Week 1 Day 2 (`internal/users`).
type Lookups interface {
	RoleForUser(ctx context.Context, userID uuid.UUID) (auth.RoleID, error)
	// AccountStatusFor reports whether the account behind a credential
	// may authenticate. It is REQUIRED rather than an optional
	// interface: an optional check is one a future implementation can
	// omit without anything noticing, and this one is the independent
	// protection that covers a credential issued during a disabled
	// window, which revocation never reaches. Spec C-31.
	//
	// A returned error means the state could not be determined. It is an
	// infrastructure failure and the binder answers 503, not 401. Spec C-32.
	AccountStatusFor(ctx context.Context, userID uuid.UUID) (AccountStatus, error)
}

// GrantLookups is the optional second half of Lookups: what a CUSTOM role
// (one auth.BuiltInRoles does not resolve) confers, read from the roles
// table. users.Service implements it. When the binder's Lookups value
// also implements this, every binding path (session cookie, session JWT,
// API token) resolves a non-built-in role's permission set into
// auth.Identity.Grants. Without it a custom role binds with no
// permissions, which is the pre-2.3.0 behavior and is logged.
//
// The three-state result mirrors users.Service.RolePermissions: found with
// perms, provably absent, or indeterminate (err). Spec system-rbac C-11.
type GrantLookups interface {
	RolePermissions(ctx context.Context, roleID string) ([]string, bool, error)
}

// TokenAuthenticator resolves a raw API token (auth.APITokenPrefix-prefixed
// bearer value) to an identity. Optional: when nil, bearer values are
// treated only as JWTs.
type TokenAuthenticator interface {
	AuthenticateToken(ctx context.Context, raw string) (auth.Identity, error)
}

// Owner-state refusals for a service-account token. An authenticator
// wraps one of these when a token is otherwise valid but its owner may not
// authenticate, so the audit record can say why. Spec system-api-tokens
// C-04.
var (
	ErrTokenOwnerDisabled = errors.New("identity: api token owner is disabled")
	ErrTokenOwnerDeleted  = errors.New("identity: api token owner is deleted")
	ErrTokenOwnerAbsent   = errors.New("identity: api token has no owner")
)

// BinderOption configures optional binder behavior.
type BinderOption func(*binderConfig)

type binderConfig struct {
	tokenAuth TokenAuthenticator
}

// WithTokenAuth enables API-token (owk_) authentication on the bearer
// path. Tokens carrying auth.APITokenPrefix route here; everything else
// stays on the JWT path.
func WithTokenAuth(ta TokenAuthenticator) BinderOption {
	return func(c *binderConfig) { c.tokenAuth = ta }
}

// Binder is the production identity-binding middleware. Reads either:
//
//	Cookie "openwatch_session"   → looks up via VerifySession
//	Authorization "Bearer <jwt>" → verifies via VerifyJWT, claims.Role
//
// Cookie path wins if both are present (browser sign-in is more
// authoritative than a leaked bearer token). On any rejection emits
// auth.login.failure with detail.reason populated, then falls through
// to anonymous. Anonymous identities are denied by RBAC middleware
// downstream.
//
// Spec system-auth-identity AC-17, AC-18, AC-21, C-11, C-12.
func Binder(pool *pgxpool.Pool, lookups Lookups, opts ...BinderOption) func(http.Handler) http.Handler {
	var cfg binderConfig
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// One budget for the request's credential work. Verification
			// runs under it, never beyond an earlier deadline the request
			// already carries. On the credential and account-mutation
			// routes it is handed on, so the handler's transaction spends
			// what is left rather than starting a fresh budget. Other
			// routes keep their own context: a report or an event stream
			// must not inherit a credential deadline. Spec C-43, C-44.
			ctx, cancel := WithOperationDeadline(r.Context())
			defer cancel()
			id, reason := resolveIdentity(ctx, pool, lookups, cfg, r)
			if unavailableReason(reason) {
				// The credential was not rejected: the server could not
				// tell. Answering 401 here would tell every signed-in
				// browser its session ended and turn a transient outage
				// into a fleet-wide forced re-login. Spec C-32.
				emitLoginFailure(r, reason)
				writeStateUnavailable(w, r)
				return
			}
			if reason != "" {
				emitLoginFailure(r, reason)
				// Credential was presented but rejected. Short-circuit with
				// 401 so the frontend can call /auth/refresh-cookie and
				// retry. Exception: credential-lifecycle endpoints (login,
				// logout, both refresh paths) bypass this — they manage
				// credentials themselves and should run anonymously when
				// a stale session is presented alongside.
				// Spec C-12 / AC-21.
				if _, bypass := authBypassPaths[r.URL.Path]; !bypass {
					writeSessionInvalid(w, r, reason)
					return
				}
			}
			handlerCtx := r.Context()
			if boundedOperation(r) {
				handlerCtx = ctx
			}
			next.ServeHTTP(w, r.WithContext(auth.SetIdentity(handlerCtx, id)))
		})
	}
}

// reasonStateUnavailable is the one reason that is NOT a rejected
// credential. It means account state could not be determined, and it
// answers 503. Spec C-32.
const reasonStateUnavailable = "account_state_unavailable"

// reasonSessionLookupFailed is the Bearer arm's equivalent: the binding
// query could not be answered. Also 503, never 401. Spec C-32.
const reasonSessionLookupFailed = "session_lookup_failed"

// reasonRoleLookupUnavailable is the cookie arm's role lookup failing to
// answer. Also 503, never 401. Spec C-45.
const reasonRoleLookupUnavailable = "role_lookup_unavailable"

// ErrNoRoles is a role lookup's confirmed answer that the user holds no
// role. Any other lookup error means the answer is unknown.
var ErrNoRoles = errors.New("identity: user has no roles")

// unavailableReason reports whether a rejection reason means "could not
// determine" rather than "refused", which is what separates 503 from 401.
func unavailableReason(reason string) bool {
	return reason == reasonStateUnavailable || reason == reasonSessionLookupFailed ||
		reason == reasonRoleLookupUnavailable
}

// writeStateUnavailable emits the 503 envelope for an infrastructure
// failure during identity binding. It deliberately does not carry
// auth.session_invalid: the frontend reacts to that code by refreshing
// and retrying, which is the wrong response to a database outage.
//
// Spec C-32.
func writeStateUnavailable(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"code":          "server.error",
		"fault":         "server",
		"retryable":     true,
		"human_message": "could not verify your account right now; please retry",
	}
	if cid, ok := correlation.From(r.Context()); ok {
		body["correlation_id"] = cid
	}
	payload, _ := json.Marshal(map[string]any{"error": body})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(payload)
}

// writeSessionInvalid emits the 401 envelope used when a credential
// was presented but rejected. The frontend's API client onResponse
// middleware reacts to this code by calling /auth/refresh-cookie and
// retrying once.
//
// Spec C-12 / AC-21.
func writeSessionInvalid(w http.ResponseWriter, r *http.Request, reason string) {
	body := map[string]any{
		"code":          "auth.session_invalid",
		"fault":         "client",
		"retryable":     true,
		"human_message": "your session is invalid or expired; please sign in again",
		"detail": map[string]any{
			"reason": reason,
		},
	}
	if cid, ok := correlation.From(r.Context()); ok {
		body["correlation_id"] = cid
	}
	envelope := map[string]any{"error": body}
	payload, _ := json.Marshal(envelope)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write(payload)
}

// resolveIdentity inspects the request for a session cookie or bearer
// token. Returns (identity, "") on success, (anonymous, reason) on any
// rejection. Anonymous-because-nothing-was-presented also returns "" for
// reason (no audit emission for unauthenticated probes; only for
// presented-but-rejected credentials).
// checkAccountState is the account-state arm shared by the cookie and
// the session-JWT binders. It returns a refusal reason, or "" to allow,
// and reports separately whether the state could not be determined.
//
// It is called on both arms on purpose. Element 3 revokes credentials
// when an account is disabled, but a credential ISSUED during a disabled
// window is never revoked, so revocation alone cannot refuse it. Spec C-31.
func checkAccountState(ctx context.Context, lookups Lookups, userID uuid.UUID) (reason string, unavailable bool) {
	status, err := lookups.AccountStatusFor(ctx, userID)
	if err != nil {
		return "account_state_unavailable", true
	}
	if status.MayAuthenticate() {
		return "", false
	}
	return status.Reason(), false
}

func resolveIdentity(ctx context.Context, pool *pgxpool.Pool, lookups Lookups, cfg binderConfig, r *http.Request) (auth.Identity, string) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		// AUTH-1 (c): the client marks NON-user-initiated requests (background
		// polling, SSE) with X-Background-Refresh so the server does not slide
		// the idle window for them — idle then tracks real user activity, not
		// HTTP traffic. Fail-safe: an unmarked request slides as before, so a
		// client that does not send the header is unaffected.
		var vopts []VerifyOption
		//
		// Logout verifies without sliding too. Extending a session a moment
		// before ending it serves nothing, and the slide is the one write
		// on this path that can wait on a row a revocation holds. Logout
		// still reaches its own hash lookup, CSRF check and bounded
		// revocation. Spec C-44.
		if r.Header.Get(BackgroundRefreshHeader) == "1" || r.URL.Path == sseEventsPath || r.URL.Path == logoutPath {
			vopts = append(vopts, WithoutSlide())
		}
		sess, err := VerifySession(ctx, pool, cookie.Value, vopts...)
		switch {
		case errors.Is(err, ErrSessionNotFound):
			return anon(), "invalid_session_token"
		case errors.Is(err, ErrSessionRevoked):
			return anon(), "session_revoked"
		case errors.Is(err, ErrSessionExpired):
			return anon(), "session_expired"
		case err != nil:
			return anon(), "session_lookup_failed"
		}
		// Account state BEFORE role. The role lookup joins users on
		// deleted_at IS NULL and so refuses a deleted account by
		// accident, which reads as enforcement while checking nothing
		// about disabled_at. Checking state first means the refusal
		// reason names the account state rather than the missing role.
		// Spec C-31.
		if reason, unavailable := checkAccountState(ctx, lookups, sess.UserID); reason != "" {
			if unavailable {
				return anon(), reasonStateUnavailable
			}
			return anon(), reason
		}
		role, err := lookups.RoleForUser(ctx, sess.UserID)
		switch {
		case errors.Is(err, ErrNoRoles):
			// Confirmed: the user holds no role. A refused credential.
			return anon(), "session_user_lookup_failed"
		case err != nil:
			// The lookup did not answer, from a deadline or a database
			// failure. That says nothing about the credential, so it is
			// an infrastructure failure: 503, no handler, no cookie
			// change, no refresh. Spec C-45.
			return anon(), reasonRoleLookupUnavailable
		}
		return withGrants(ctx, lookups, auth.Identity{
			ID:     sess.UserID.String(),
			RoleID: role,
		}), ""
	}

	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token := strings.TrimPrefix(h, "Bearer ")
		// API service-account tokens (owk_) route to the token
		// authenticator; everything else is a session JWT.
		if cfg.tokenAuth != nil && strings.HasPrefix(token, auth.APITokenPrefix) {
			id, err := cfg.tokenAuth.AuthenticateToken(ctx, token)
			switch {
			case errors.Is(err, ErrTokenOwnerDisabled):
				return anon(), "api_token_owner_disabled"
			case errors.Is(err, ErrTokenOwnerDeleted):
				return anon(), "api_token_owner_deleted"
			case errors.Is(err, ErrTokenOwnerAbsent):
				return anon(), "api_token_ownerless"
			case err != nil:
				return anon(), "invalid_api_token"
			}
			return withGrants(ctx, lookups, id), ""
		}
		claims, err := VerifyJWT(token)
		switch {
		case errors.Is(err, ErrJWTExpired):
			return anon(), "jwt_expired"
		case errors.Is(err, ErrJWTInvalid):
			return anon(), "invalid_jwt"
		case err != nil:
			return anon(), "jwt_verify_failed"
		}
		// Account state on the Bearer arm too. A JWT stays
		// cryptographically valid for its whole lifetime, so without
		// this a disabled account keeps authenticating until the token
		// expires. Spec C-31.
		uid, perr := uuid.Parse(claims.Subject)
		if perr != nil {
			return anon(), "invalid_jwt_subject"
		}
		// Session binding AND ownership, in one query over sessions
		// joined to users. A signed token is otherwise an independent
		// bearer credential that outlives everything but its own expiry,
		// which is why an administrative password reset left one
		// working: the account stays enabled, so an account-state check
		// alone cannot reach it. And a token naming a session that
		// belongs to somebody else must not bind that session's owner or
		// this subject: nothing legitimate produces that pair, so it is
		// refused rather than reconciled. Spec C-38.
		if claims.SessionID == "" {
			// Unbound token. Refused rather than trusted: after the
			// migration no legitimate interactive token lacks a `sid`.
			return anon(), BearerSIDAbsent.Reason()
		}
		sid, serr := uuid.Parse(claims.SessionID)
		if serr != nil {
			return anon(), "invalid_jwt_session"
		}
		verdict, lerr := EvaluateBearerBinding(ctx, pool, sid, uid)
		if lerr != nil {
			return anon(), reasonSessionLookupFailed
		}
		if !verdict.OK() {
			return anon(), verdict.Reason()
		}
		// The role baked into the JWT is the contract. RBAC middleware
		// downstream re-evaluates whether that role actually grants the
		// request's required permission — so a stale role still gets
		// caught by the registry.
		return withGrants(ctx, lookups, auth.Identity{
			ID:     claims.Subject,
			RoleID: auth.RoleID(claims.Role),
		}), ""
	}

	return anon(), "" // genuinely unauthenticated; no audit
}

// withGrants attaches a custom role's stored permission set to id. A
// built-in role is returned untouched: its permissions come from the
// registry (system-rbac C-02) and Grants is ignored for it. A custom role
// whose lookup is unavailable, fails, or finds no row binds with nil
// Grants, so the identity is authenticated and holds nothing; the warn
// line is the only trace, because the credential itself was valid.
// Spec system-rbac C-11.
func withGrants(ctx context.Context, lookups Lookups, id auth.Identity) auth.Identity {
	if _, builtIn := auth.BuiltInRoles[id.RoleID]; builtIn {
		return id
	}
	gl, ok := lookups.(GrantLookups)
	if !ok {
		slog.WarnContext(ctx, "identity: custom role bound without a grant lookup; it confers nothing",
			slog.String("role_id", string(id.RoleID)))
		return id
	}
	perms, found, err := gl.RolePermissions(ctx, string(id.RoleID))
	switch {
	case err != nil:
		slog.WarnContext(ctx, "identity: custom role permission lookup failed; binding with no permissions",
			slog.String("role_id", string(id.RoleID)), slog.String("error", err.Error()))
		return id
	case !found:
		slog.WarnContext(ctx, "identity: bound role no longer exists; binding with no permissions",
			slog.String("role_id", string(id.RoleID)))
		return id
	}
	id.Grants = make([]auth.Permission, 0, len(perms))
	for _, p := range perms {
		id.Grants = append(id.Grants, auth.Permission(p))
	}
	return id
}

func anon() auth.Identity { return auth.Identity{IsAnonymous: true} }

// emitLoginFailure records the rejection with the canonical reason
// string so operators can grep auth.login.failure events to find
// brute-force / token-theft patterns.
//
// Spec AC-18, C-11.
func emitLoginFailure(r *http.Request, reason string) {
	detail, _ := json.Marshal(map[string]any{
		"reason":      reason,
		"remote_addr": r.RemoteAddr,
		"user_agent":  audit.ClipDetail(r.UserAgent()),
	})
	audit.Emit(r.Context(), audit.AuthLoginFailure, audit.Event{
		ActorType: "anonymous",
		ActorIP:   r.RemoteAddr,
		Detail:    detail,
	})
}
