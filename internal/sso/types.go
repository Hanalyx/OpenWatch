// Package sso implements single sign-on via OpenID Connect: admin-managed
// providers (config plane) and the authorization-code sign-in flow
// (runtime plane).
//
// Security model:
//   - The client secret is AES-256-GCM encrypted at rest (the shared DEK)
//     and never returned by any read path.
//   - The authorization-code flow uses PKCE (S256), a CSRF `state`, and a
//     replay-guard `nonce`, all persisted server-side for the redirect
//     round-trip and consumed exactly once at callback.
//   - The ID token's signature is verified against the provider's JWKS
//     (RS256 only); iss, aud, exp, and nonce are all checked before any
//     user is provisioned or any session is issued.
//   - A provisioned user has no usable local password — it authenticates
//     only through the IdP. The federation link is keyed on the stable
//     OIDC `sub`, not the mutable email.
//
// NOTE: the runtime sign-in flow integrates with an external IdP and MUST
// be validated against a live provider and security-reviewed before
// production use. The unit tests exercise the validation logic with a
// locally generated RSA key standing in for the IdP.
//
// Spec: system-sso, api-sso.
package sso

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Errors surfaced to handlers, which map them to canonical envelopes.
var (
	// ErrProviderNotFound — unknown or (for the enabled list) disabled id.
	ErrProviderNotFound = errors.New("sso: provider not found")
	// ErrInvalidParams — provider create/update validation failed.
	ErrInvalidParams = errors.New("sso: invalid parameters")
	// ErrStateNotFound — the callback `state` is unknown or already consumed.
	ErrStateNotFound = errors.New("sso: auth state not found")
	// ErrStateExpired — the login round-trip took too long.
	ErrStateExpired = errors.New("sso: auth state expired")
	// ErrTokenValidation — ID-token signature/claims validation failed.
	ErrTokenValidation = errors.New("sso: id token validation failed")
	// ErrDiscovery — OIDC discovery or a downstream IdP call failed.
	ErrDiscovery = errors.New("sso: provider discovery failed")
)

// AuthStateTTL bounds how long a login round-trip may take. A state row
// older than this is rejected at callback and swept.
const AuthStateTTL = 10 * time.Minute

// Provider is an SSO provider's non-secret metadata. The client secret is
// never carried on this struct — only ProviderConfig (internal) holds the
// decrypted secret, and only on the auth path.
type Provider struct {
	ID          uuid.UUID
	Name        string
	Type        string
	Issuer      string
	ClientID    string
	Scopes      string
	DefaultRole string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateParams is the input to Create.
type CreateParams struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       string
	DefaultRole  string
	Enabled      bool
	CreatedBy    *uuid.UUID
}

// UpdateParams is the input to Update. ClientSecret is optional: an empty
// value leaves the stored secret unchanged (write-only field).
type UpdateParams struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string // empty = keep existing
	Scopes       string
	DefaultRole  string
	Enabled      bool
}

// providerConfig adds the decrypted client secret. Internal to the auth
// path; never returned by the API.
type providerConfig struct {
	Provider
	ClientSecret string
}

// AuthState is the per-login state persisted across the IdP redirect.
type AuthState struct {
	State        string
	ProviderID   uuid.UUID
	Nonce        string
	CodeVerifier string
	RedirectTo   string
	ExpiresAt    time.Time
}

// Claims is the subset of ID-token claims the callback consumes.
type Claims struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	Name              string
}
