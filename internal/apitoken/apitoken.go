// Package apitoken manages API service-account tokens for automation
// (CI, scripts) that call the REST API without an interactive session.
//
// A token is a high-entropy random secret returned to the operator once
// at creation; only its SHA-256 hash is persisted. The token carries a
// role, and the RBAC middleware re-evaluates that role's permissions on
// every request. AuthenticateToken adapts a raw token to an auth.Identity
// for the identity binder.
//
// Spec: system-api-tokens, api-tokens.
package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTokenNotFound is returned when a token id does not exist.
var ErrTokenNotFound = errors.New("apitoken: not found")

// ErrInvalidToken is returned by AuthenticateToken for an unknown,
// revoked, or expired token.
var ErrInvalidToken = errors.New("apitoken: invalid token")

// ErrInvalidParams is returned when create validation fails.
var ErrInvalidParams = errors.New("apitoken: invalid parameters")

// Token is a stored API token's non-secret metadata.
type Token struct {
	ID         uuid.UUID
	Name       string
	Prefix     string
	RoleID     string
	CreatedBy  *uuid.UUID
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// CreateParams is the input to Create.
type CreateParams struct {
	Name      string
	RoleID    auth.RoleID
	ExpiresAt *time.Time
	CreatedBy *uuid.UUID
}

// Service is the API-token store + authenticator.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds a Service to a DB pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// hashToken returns the SHA-256 of a raw token. High entropy makes a fast
// hash safe and enables an indexed lookup on the auth path.
func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// generateToken returns a fresh token: the raw secret (prefix + 32 random
// bytes, base64url) and a display prefix for the list.
func generateToken() (raw, prefix string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("apitoken: rand: %w", err)
	}
	raw = auth.APITokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	// Display prefix: the literal prefix + the first 8 secret chars.
	prefix = raw[:len(auth.APITokenPrefix)+8]
	return raw, prefix, nil
}

// Create generates and persists a token, returning the raw secret ONCE.
func (s *Service) Create(ctx context.Context, p CreateParams) (string, Token, error) {
	if strings.TrimSpace(p.Name) == "" {
		return "", Token{}, fmt.Errorf("%w: name required", ErrInvalidParams)
	}
	if strings.TrimSpace(string(p.RoleID)) == "" {
		return "", Token{}, fmt.Errorf("%w: role required", ErrInvalidParams)
	}
	raw, prefix, err := generateToken()
	if err != nil {
		return "", Token{}, err
	}
	const stmt = `
		INSERT INTO api_tokens (name, token_hash, prefix, role_id, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`
	var t Token
	if err := s.pool.QueryRow(ctx, stmt,
		p.Name, hashToken(raw), prefix, string(p.RoleID), p.CreatedBy, p.ExpiresAt,
	).Scan(&t.ID, &t.CreatedAt); err != nil {
		// FK violation on role_id → unknown role.
		return "", Token{}, fmt.Errorf("%w: %v", ErrInvalidParams, err)
	}
	t.Name = p.Name
	t.Prefix = prefix
	t.RoleID = string(p.RoleID)
	t.CreatedBy = p.CreatedBy
	t.ExpiresAt = p.ExpiresAt
	return raw, t, nil
}

// List returns all tokens (newest first) without secrets.
func (s *Service) List(ctx context.Context) ([]Token, error) {
	const stmt = `
		SELECT id, name, prefix, role_id, created_by, created_at, expires_at, last_used_at, revoked_at
		FROM api_tokens
		ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("apitoken: list: %w", err)
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.RoleID, &t.CreatedBy,
			&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, fmt.Errorf("apitoken: scan: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke marks a token revoked. Idempotent: revoking an already-revoked
// or missing token is not an error.
func (s *Service) Revoke(ctx context.Context, id uuid.UUID) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id,
	); err != nil {
		return fmt.Errorf("apitoken: revoke: %w", err)
	}
	return nil
}

// AuthenticateToken resolves a raw token to an auth.Identity. Rejects
// unknown, revoked, and expired tokens. Updates last_used_at best-effort.
// Implements the identity binder's TokenAuthenticator.
func (s *Service) AuthenticateToken(ctx context.Context, raw string) (auth.Identity, error) {
	const stmt = `
		SELECT id, role_id, expires_at
		FROM api_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL`
	var (
		id        uuid.UUID
		roleID    string
		expiresAt *time.Time
	)
	err := s.pool.QueryRow(ctx, stmt, hashToken(raw)).Scan(&id, &roleID, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.Identity{}, ErrInvalidToken
		}
		return auth.Identity{}, fmt.Errorf("apitoken: lookup: %w", err)
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return auth.Identity{}, ErrInvalidToken
	}
	// Best-effort usage stamp; never blocks auth on failure.
	_, _ = s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, id)
	return auth.Identity{ID: id.String(), RoleID: auth.RoleID(roleID)}, nil
}
