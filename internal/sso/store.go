package sso

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service is the SSO provider store + OIDC client. The httpclient is used
// for all outbound IdP calls (discovery, token exchange, JWKS) so they
// forward the correlation id; tests inject a stub transport.
type Service struct {
	pool *pgxpool.Pool
	http httpDoer
}

// NewService binds a Service to a DB pool with the default outbound client.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, http: defaultHTTP()}
}

// WithHTTP overrides the outbound client (tests).
func (s *Service) WithHTTP(h httpDoer) *Service {
	s.http = h
	return s
}

// Create encrypts the client secret and persists a provider.
//
// Spec api-sso AC-02.
func (s *Service) Create(ctx context.Context, p CreateParams) (Provider, error) {
	if err := validateCreate(p); err != nil {
		return Provider{}, err
	}
	enc, err := encryptSecret(p.ClientSecret)
	if err != nil {
		return Provider{}, err
	}
	const stmt = `
		INSERT INTO sso_providers
			(name, issuer, client_id, client_secret_enc, scopes, default_role, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, name, type, issuer, client_id, scopes, default_role, enabled, created_at, updated_at`
	var out Provider
	if err := s.pool.QueryRow(ctx, stmt,
		p.Name, strings.TrimRight(p.Issuer, "/"), p.ClientID, enc,
		normalizeScopes(p.Scopes), p.DefaultRole, p.Enabled, p.CreatedBy,
	).Scan(&out.ID, &out.Name, &out.Type, &out.Issuer, &out.ClientID,
		&out.Scopes, &out.DefaultRole, &out.Enabled, &out.CreatedAt, &out.UpdatedAt); err != nil {
		// FK violation on default_role → unknown role.
		return Provider{}, fmt.Errorf("%w: %v", ErrInvalidParams, err)
	}
	return out, nil
}

// List returns all providers (newest first), without secrets.
func (s *Service) List(ctx context.Context) ([]Provider, error) {
	const stmt = `
		SELECT id, name, type, issuer, client_id, scopes, default_role, enabled, created_at, updated_at
		FROM sso_providers ORDER BY created_at DESC`
	return s.queryProviders(ctx, stmt)
}

// ListEnabled returns enabled providers for the public (anonymous) login
// picker — callers render only ID + Name.
func (s *Service) ListEnabled(ctx context.Context) ([]Provider, error) {
	const stmt = `
		SELECT id, name, type, issuer, client_id, scopes, default_role, enabled, created_at, updated_at
		FROM sso_providers WHERE enabled ORDER BY name`
	return s.queryProviders(ctx, stmt)
}

// Get returns one provider's non-secret metadata.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Provider, error) {
	const stmt = `
		SELECT id, name, type, issuer, client_id, scopes, default_role, enabled, created_at, updated_at
		FROM sso_providers WHERE id = $1`
	rows, err := s.queryProviders(ctx, stmt, id)
	if err != nil {
		return Provider{}, err
	}
	if len(rows) == 0 {
		return Provider{}, ErrProviderNotFound
	}
	return rows[0], nil
}

// Update replaces a provider. An empty ClientSecret leaves the stored
// secret unchanged (write-only field).
//
// Spec api-sso AC-03.
func (s *Service) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (Provider, error) {
	if err := validateUpdate(p); err != nil {
		return Provider{}, err
	}
	// Two statements keep the secret optional without a CASE expression.
	if p.ClientSecret != "" {
		enc, err := encryptSecret(p.ClientSecret)
		if err != nil {
			return Provider{}, err
		}
		if _, err := s.pool.Exec(ctx,
			`UPDATE sso_providers SET client_secret_enc = $1 WHERE id = $2`, enc, id); err != nil {
			return Provider{}, fmt.Errorf("sso: update secret: %w", err)
		}
	}
	const stmt = `
		UPDATE sso_providers
		SET name = $1, issuer = $2, client_id = $3, scopes = $4,
		    default_role = $5, enabled = $6, updated_at = now()
		WHERE id = $7
		RETURNING id, name, type, issuer, client_id, scopes, default_role, enabled, created_at, updated_at`
	var out Provider
	err := s.pool.QueryRow(ctx, stmt,
		p.Name, strings.TrimRight(p.Issuer, "/"), p.ClientID, normalizeScopes(p.Scopes),
		p.DefaultRole, p.Enabled, id,
	).Scan(&out.ID, &out.Name, &out.Type, &out.Issuer, &out.ClientID,
		&out.Scopes, &out.DefaultRole, &out.Enabled, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, fmt.Errorf("%w: %v", ErrInvalidParams, err)
	}
	return out, nil
}

// Delete removes a provider (and, by FK CASCADE, its identities + states).
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM sso_providers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("sso: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// getConfig returns a provider WITH its decrypted client secret — internal,
// auth-path only.
func (s *Service) getConfig(ctx context.Context, id uuid.UUID) (providerConfig, error) {
	const stmt = `
		SELECT id, name, type, issuer, client_id, client_secret_enc, scopes,
		       default_role, enabled, created_at, updated_at
		FROM sso_providers WHERE id = $1`
	var (
		c   providerConfig
		enc []byte
	)
	err := s.pool.QueryRow(ctx, stmt, id).Scan(
		&c.ID, &c.Name, &c.Type, &c.Issuer, &c.ClientID, &enc, &c.Scopes,
		&c.DefaultRole, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return providerConfig{}, ErrProviderNotFound
	}
	if err != nil {
		return providerConfig{}, fmt.Errorf("sso: get config: %w", err)
	}
	secret, err := decryptSecret(enc)
	if err != nil {
		return providerConfig{}, err
	}
	c.ClientSecret = secret
	return c, nil
}

func (s *Service) queryProviders(ctx context.Context, stmt string, args ...any) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("sso: query providers: %w", err)
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.Issuer, &p.ClientID,
			&p.Scopes, &p.DefaultRole, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("sso: scan provider: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// saveAuthState persists per-login state with a TTL. Spec system-sso AC-04.
func (s *Service) saveAuthState(ctx context.Context, st AuthState) error {
	const stmt = `
		INSERT INTO sso_auth_states (state, provider_id, nonce, code_verifier, redirect_to, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := s.pool.Exec(ctx, stmt,
		st.State, st.ProviderID, st.Nonce, st.CodeVerifier, st.RedirectTo, st.ExpiresAt,
	); err != nil {
		return fmt.Errorf("sso: save auth state: %w", err)
	}
	return nil
}

// consumeAuthState atomically fetches and deletes a state row (single-use).
// Returns ErrStateNotFound if unknown/already used, ErrStateExpired if past
// its TTL. Spec system-sso AC-05.
func (s *Service) consumeAuthState(ctx context.Context, state string) (AuthState, error) {
	const stmt = `
		DELETE FROM sso_auth_states WHERE state = $1
		RETURNING state, provider_id, nonce, code_verifier, redirect_to, expires_at`
	var st AuthState
	err := s.pool.QueryRow(ctx, stmt, state).Scan(
		&st.State, &st.ProviderID, &st.Nonce, &st.CodeVerifier, &st.RedirectTo, &st.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthState{}, ErrStateNotFound
	}
	if err != nil {
		return AuthState{}, fmt.Errorf("sso: consume auth state: %w", err)
	}
	if time.Now().After(st.ExpiresAt) {
		return AuthState{}, ErrStateExpired
	}
	return st, nil
}

// linkedUser returns the local user id for a (provider, subject) pair, or
// false if no link exists yet. Stamps last_login_at on a hit.
func (s *Service) linkedUser(ctx context.Context, providerID uuid.UUID, subject string) (uuid.UUID, bool, error) {
	const stmt = `
		UPDATE sso_identities SET last_login_at = now()
		WHERE provider_id = $1 AND subject = $2
		RETURNING user_id`
	var uid uuid.UUID
	err := s.pool.QueryRow(ctx, stmt, providerID, subject).Scan(&uid)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("sso: linked user: %w", err)
	}
	return uid, true, nil
}

// link records a new federation mapping after provisioning.
func (s *Service) link(ctx context.Context, providerID uuid.UUID, subject string, userID uuid.UUID) error {
	const stmt = `
		INSERT INTO sso_identities (provider_id, subject, user_id, last_login_at)
		VALUES ($1, $2, $3, now())`
	if _, err := s.pool.Exec(ctx, stmt, providerID, subject, userID); err != nil {
		return fmt.Errorf("sso: link identity: %w", err)
	}
	return nil
}

// PurgeExpiredStates deletes auth-state rows past their TTL. Called by a
// periodic sweeper.
func (s *Service) PurgeExpiredStates(ctx context.Context) (int64, error) {
	ct, err := s.pool.Exec(ctx, `DELETE FROM sso_auth_states WHERE expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("sso: purge states: %w", err)
	}
	return ct.RowsAffected(), nil
}

func encryptSecret(plain string) ([]byte, error) {
	dek, err := secretkey.Active()
	if err != nil {
		return nil, fmt.Errorf("sso: dek: %w", err)
	}
	enc, err := dek.Encrypt([]byte(plain))
	if err != nil {
		return nil, fmt.Errorf("sso: encrypt secret: %w", err)
	}
	return enc, nil
}

func decryptSecret(enc []byte) (string, error) {
	dek, err := secretkey.Active()
	if err != nil {
		return "", fmt.Errorf("sso: dek: %w", err)
	}
	plain, err := dek.Decrypt(enc)
	if err != nil {
		return "", fmt.Errorf("sso: decrypt secret: %w", err)
	}
	return string(plain), nil
}

// parseUUID is a thin wrapper so the OIDC layer can accept the raw path
// param without importing uuid directly.
func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func normalizeScopes(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "openid email profile"
	}
	if !strings.Contains(" "+s+" ", " openid ") {
		s = "openid " + s
	}
	return s
}

func validateCreate(p CreateParams) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: name required", ErrInvalidParams)
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return fmt.Errorf("%w: client_id required", ErrInvalidParams)
	}
	if strings.TrimSpace(p.ClientSecret) == "" {
		return fmt.Errorf("%w: client_secret required", ErrInvalidParams)
	}
	return validateIssuer(p.Issuer)
}

func validateUpdate(p UpdateParams) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: name required", ErrInvalidParams)
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return fmt.Errorf("%w: client_id required", ErrInvalidParams)
	}
	return validateIssuer(p.Issuer)
}

// validateIssuer requires an https issuer URL — OIDC discovery, token, and
// JWKS calls all ride this origin, so http would expose tokens in transit.
func validateIssuer(issuer string) error {
	issuer = strings.TrimSpace(issuer)
	if !strings.HasPrefix(issuer, "https://") {
		return fmt.Errorf("%w: issuer must be an https URL", ErrInvalidParams)
	}
	return nil
}
