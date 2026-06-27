package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/httpclient"
	"github.com/golang-jwt/jwt/v5"
)

// httpDoer is the subset of the outbound client the OIDC flow needs. The
// real implementation is internal/httpclient.Client (forwards the
// correlation id); tests inject a stub.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// defaultHTTP returns the SSRF-guarded outbound client. Discovery, token,
// and JWKS URLs come from IdP-controlled metadata, so the client refuses to
// dial loopback/private/CGNAT/link-local space (incl. the cloud-metadata
// endpoint) — SEC-H2. Tests inject their own client via WithHTTP (their
// httptest server is on loopback, which the guard would otherwise block).
func defaultHTTP() httpDoer { return httpclient.NewGuardedClient(30 * time.Second) }

// discoveryDoc is the subset of the OIDC discovery document we use.
type discoveryDoc struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// discover fetches and validates the provider's discovery document. The
// returned issuer MUST match the configured issuer (mix-up defense).
func (s *Service) discover(ctx context.Context, issuer string) (discoveryDoc, error) {
	var doc discoveryDoc
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	if err := s.getJSON(ctx, u, "", &doc); err != nil {
		return discoveryDoc{}, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	if strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return discoveryDoc{}, fmt.Errorf("%w: issuer mismatch (got %q)", ErrDiscovery, doc.Issuer)
	}
	if doc.AuthEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return discoveryDoc{}, fmt.Errorf("%w: incomplete discovery document", ErrDiscovery)
	}
	return doc, nil
}

// BuildAuthURL discovers the provider, mints PKCE + state + nonce, persists
// the per-login state, and returns the IdP authorization URL to redirect to.
//
// Spec system-sso AC-03, AC-04.
func (s *Service) BuildAuthURL(ctx context.Context, providerID, redirectURI, redirectTo string) (string, error) {
	id, err := parseUUID(providerID)
	if err != nil {
		return "", ErrProviderNotFound
	}
	cfg, err := s.getConfig(ctx, id)
	if err != nil {
		return "", err
	}
	if !cfg.Enabled {
		return "", ErrProviderNotFound
	}
	doc, err := s.discover(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}

	state := randToken()
	nonce := randToken()
	verifier := randToken()
	challenge := pkceChallenge(verifier)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", cfg.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL := doc.AuthEndpoint + "?" + q.Encode()

	st := AuthState{
		State:        state,
		ProviderID:   cfg.ID,
		Nonce:        nonce,
		CodeVerifier: verifier,
		RedirectTo:   redirectTo,
		ExpiresAt:    time.Now().Add(AuthStateTTL),
	}
	if err := s.saveAuthState(ctx, st); err != nil {
		return "", err
	}
	return authURL, nil
}

// Exchange completes the flow: swaps the authorization code for tokens at
// the IdP, verifies the ID token (signature via JWKS, iss/aud/exp, nonce),
// and returns the validated claims.
//
// Spec system-sso AC-06, AC-07.
func (s *Service) Exchange(ctx context.Context, st AuthState, redirectURI, code string) (Claims, error) {
	cfg, err := s.getConfig(ctx, st.ProviderID)
	if err != nil {
		return Claims{}, err
	}
	doc, err := s.discover(ctx, cfg.Issuer)
	if err != nil {
		return Claims{}, err
	}

	// Authorization-code exchange with PKCE verifier and client_secret_basic.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", st.CodeVerifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: build token request: %v", ErrDiscovery, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	resp, err := s.http.Do(req)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: token request: %v", ErrDiscovery, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Claims{}, fmt.Errorf("%w: token endpoint %d", ErrTokenValidation, resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return Claims{}, fmt.Errorf("%w: no id_token in token response", ErrTokenValidation)
	}

	return s.validateIDToken(ctx, cfg, doc, tok.IDToken, st.Nonce)
}

// validateIDToken verifies the ID token's RS256 signature against the
// provider JWKS and checks iss, aud, exp, and nonce before returning claims.
func (s *Service) validateIDToken(ctx context.Context, cfg providerConfig, doc discoveryDoc, idToken, wantNonce string) (Claims, error) {
	keyfunc := func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		return s.jwksKey(ctx, doc.JWKSURI, kid)
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(strings.TrimRight(cfg.Issuer, "/")),
		jwt.WithAudience(cfg.ClientID),
		jwt.WithExpirationRequired(),
	)
	if _, err := parser.ParseWithClaims(idToken, claims, keyfunc); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrTokenValidation, err)
	}
	// Replay guard: the nonce we sent must round-trip in the token.
	if n, _ := claims["nonce"].(string); n == "" || n != wantNonce {
		return Claims{}, fmt.Errorf("%w: nonce mismatch", ErrTokenValidation)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return Claims{}, fmt.Errorf("%w: missing sub", ErrTokenValidation)
	}
	out := Claims{Subject: sub}
	out.Email, _ = claims["email"].(string)
	out.EmailVerified, _ = claims["email_verified"].(bool)
	out.PreferredUsername, _ = claims["preferred_username"].(string)
	out.Name, _ = claims["name"].(string)
	return out, nil
}

// jwksKey fetches the provider JWKS and builds the RSA public key matching
// kid. Re-fetches each call (no cache) — correct over fast; JWKS responses
// are small and key rotation is picked up immediately.
func (s *Service) jwksKey(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := s.getJSON(ctx, jwksURI, "", &set); err != nil {
		return nil, fmt.Errorf("%w: jwks fetch: %v", ErrTokenValidation, err)
	}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		// Match by kid when the token carries one; otherwise accept the sole
		// RSA key (some IdPs omit kid with a single signing key).
		if kid != "" && k.Kid != kid {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("%w: bad jwk modulus", ErrTokenValidation)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("%w: bad jwk exponent", ErrTokenValidation)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}, nil
	}
	return nil, fmt.Errorf("%w: no matching jwks key for kid %q", ErrTokenValidation, kid)
}

// getJSON GETs url and decodes the JSON body into v. bearer is optional.
func (s *Service) getJSON(ctx context.Context, u, bearer string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// randToken returns 32 bytes of base64url entropy (CSRF state, nonce, PKCE
// verifier all use this).
func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// pkceChallenge is the S256 code challenge for a verifier (RFC 7636).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
