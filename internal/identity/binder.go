package identity

import (
	"context"
	"encoding/json"
	"errors"
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

// authBypassPaths are credential-lifecycle endpoints where the binder
// MUST NOT 401 on a stale session cookie — they handle their own
// credential semantics. Login does not need any cookie; logout is
// idempotent for stale sessions; the refresh-cookie endpoint reads
// the refresh cookie, not the session cookie, so a stale session
// presented alongside is not an error there.
//
// Spec system-auth-identity C-12 / AC-21 (bypass list).
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
}

// TokenAuthenticator resolves a raw API token (auth.APITokenPrefix-prefixed
// bearer value) to an identity. Optional: when nil, bearer values are
// treated only as JWTs.
type TokenAuthenticator interface {
	AuthenticateToken(ctx context.Context, raw string) (auth.Identity, error)
}

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
			id, reason := resolveIdentity(r.Context(), pool, lookups, cfg, r)
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
			next.ServeHTTP(w, r.WithContext(auth.SetIdentity(r.Context(), id)))
		})
	}
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
func resolveIdentity(ctx context.Context, pool *pgxpool.Pool, lookups Lookups, cfg binderConfig, r *http.Request) (auth.Identity, string) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		sess, err := VerifySession(ctx, pool, cookie.Value)
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
		role, err := lookups.RoleForUser(ctx, sess.UserID)
		if err != nil {
			return anon(), "session_user_lookup_failed"
		}
		return auth.Identity{
			ID:     sess.UserID.String(),
			RoleID: role,
		}, ""
	}

	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token := strings.TrimPrefix(h, "Bearer ")
		// API service-account tokens (owk_) route to the token
		// authenticator; everything else is a session JWT.
		if cfg.tokenAuth != nil && strings.HasPrefix(token, auth.APITokenPrefix) {
			id, err := cfg.tokenAuth.AuthenticateToken(ctx, token)
			if err != nil {
				return anon(), "invalid_api_token"
			}
			return id, ""
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
		// The role baked into the JWT is the contract. RBAC middleware
		// downstream re-evaluates whether that role actually grants the
		// request's required permission — so a stale role still gets
		// caught by the registry.
		return auth.Identity{
			ID:     claims.Subject,
			RoleID: auth.RoleID(claims.Role),
		}, ""
	}

	return anon(), "" // genuinely unauthenticated; no audit
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
		"user_agent":  r.UserAgent(),
	})
	audit.Emit(r.Context(), audit.AuthLoginFailure, audit.Event{
		ActorType: "anonymous",
		ActorIP:   r.RemoteAddr,
		Detail:    detail,
	})
}
