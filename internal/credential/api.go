// API-facing credential helpers. Returns metadata-only structs and
// runs the list + soft-delete operations. Secret fields (password,
// private key, passphrase) are NEVER read or returned from this file
// — only the credential dial path goes through queryOne which decrypts.
//
// Spec: app/specs/api/credentials.spec.yaml.

package credential

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Metadata is the safe shape returned by every API read. NO ciphertext
// or plaintext secret material is included — see api-credentials C-01.
type Metadata struct {
	ID                uuid.UUID
	Scope             Scope
	ScopeID           *uuid.UUID
	Name              string
	Description       string
	Username          string
	AuthMethod        AuthMethod
	SSHKeyFingerprint string
	SSHKeyType        string
	SSHKeyBits        int
	SSHKeyComment     string
	IsDefault         bool
	IsActive          bool
	CreatedBy         uuid.UUID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ListMetadata returns active credentials as metadata-only rows.
// Inactive (soft-deleted) credentials are excluded. Stable ordering
// by created_at to make the list deterministic for the UI.
func (s *Service) ListMetadata(ctx context.Context) ([]Metadata, error) {
	const stmt = `
		SELECT id, scope, scope_id, name, COALESCE(description, ''),
		       username, auth_method,
		       COALESCE(ssh_key_fingerprint, ''), COALESCE(ssh_key_type, ''),
		       COALESCE(ssh_key_bits, 0), COALESCE(ssh_key_comment, ''),
		       is_default, is_active, created_by, created_at, updated_at
		FROM credentials
		WHERE is_active = true
		ORDER BY created_at ASC`
	rows, err := s.pool.Query(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("credential: list: %w", err)
	}
	defer rows.Close()
	out := []Metadata{}
	for rows.Next() {
		m, err := scanMetadata(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// GetMetadataByID returns one credential's metadata. ErrNotFound if
// the id is unknown or the row is inactive.
func (s *Service) GetMetadataByID(ctx context.Context, id uuid.UUID) (Metadata, error) {
	const stmt = `
		SELECT id, scope, scope_id, name, COALESCE(description, ''),
		       username, auth_method,
		       COALESCE(ssh_key_fingerprint, ''), COALESCE(ssh_key_type, ''),
		       COALESCE(ssh_key_bits, 0), COALESCE(ssh_key_comment, ''),
		       is_default, is_active, created_by, created_at, updated_at
		FROM credentials
		WHERE id = $1 AND is_active = true`
	row := s.pool.QueryRow(ctx, stmt, id)
	m, err := scanMetadata(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Metadata{}, ErrNotFound
		}
		return Metadata{}, err
	}
	return m, nil
}

// ResolveMetadata is Resolve, but returns only metadata. Used by the
// API's "which credential will be used for this host?" endpoint.
func (s *Service) ResolveMetadata(ctx context.Context, hostID uuid.UUID) (Metadata, error) {
	c, err := s.Resolve(ctx, hostID)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{
		ID:                c.ID,
		Scope:             c.Scope,
		ScopeID:           c.ScopeID,
		Name:              c.Name,
		Description:       c.Description,
		Username:          c.Username,
		AuthMethod:        c.AuthMethod,
		SSHKeyFingerprint: c.SSHKeyFingerprint,
		SSHKeyType:        c.SSHKeyType,
		SSHKeyBits:        c.SSHKeyBits,
		SSHKeyComment:     c.SSHKeyComment,
		IsDefault:         c.IsDefault,
		IsActive:          c.IsActive,
		CreatedBy:         c.CreatedBy,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	}, nil
}

// SoftDelete marks a credential inactive. Idempotent — if the row is
// already inactive the call still returns nil. Returns ErrNotFound only
// when the id is unknown.
func (s *Service) SoftDelete(ctx context.Context, id uuid.UUID) error {
	const stmt = `UPDATE credentials SET is_active = false, updated_at = now()
	              WHERE id = $1`
	tag, err := s.pool.Exec(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("credential: soft delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanMetadata works for both pgx.Row (QueryRow) and pgx.Rows iterator
// items — both share the Scan method.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanMetadata(r rowScanner) (Metadata, error) {
	var m Metadata
	var scopeStr, methodStr string
	var scopeID *uuid.UUID
	err := r.Scan(
		&m.ID, &scopeStr, &scopeID, &m.Name, &m.Description,
		&m.Username, &methodStr,
		&m.SSHKeyFingerprint, &m.SSHKeyType, &m.SSHKeyBits, &m.SSHKeyComment,
		&m.IsDefault, &m.IsActive, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		return Metadata{}, err
	}
	m.Scope = Scope(scopeStr)
	m.ScopeID = scopeID
	m.AuthMethod = AuthMethod(methodStr)
	return m, nil
}
