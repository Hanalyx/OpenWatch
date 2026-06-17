// Package credential owns SSH credential storage and the system→host
// resolver. One credentials table backs both scopes. Resolve(hostID)
// is the single entry point for connectivity code — never query the
// table directly.
//
// Spec: app/specs/system/credential-store.spec.yaml.
package credential

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

// Scope is system or host. Host_group reserved for a later slice.
type Scope string

const (
	ScopeSystem Scope = "system"
	ScopeHost   Scope = "host"
)

// AuthMethod is what kind of credential to dial with.
type AuthMethod string

const (
	AuthSSHKey   AuthMethod = "ssh_key"
	AuthPassword AuthMethod = "password"
	AuthBoth     AuthMethod = "both"
)

// Service errors.
var (
	ErrInvalidScope           = errors.New("credential: invalid scope/scope_id combination")
	ErrMissingSecret          = errors.New("credential: required secret missing for auth_method")
	ErrUnknownAuthMethod      = errors.New("credential: unknown auth_method")
	ErrMultipleSystemDefaults = errors.New("credential: another system default already exists")
	ErrNotFound               = errors.New("credential: not found")
	ErrNoCredential           = errors.New("credential: no credential available for host or system default")
)

// NewParams is the input to NewCredential. Plaintext secrets are encrypted
// inside the service; never persisted as-is.
type NewParams struct {
	Scope                Scope
	ScopeID              *uuid.UUID
	Name                 string
	Description          string
	Username             string
	AuthMethod           AuthMethod
	Password             string
	PrivateKey           string
	PrivateKeyPassphrase string
	SSHKeyFingerprint    string
	SSHKeyType           string
	SSHKeyBits           int
	SSHKeyComment        string
	IsDefault            bool
	CreatedBy            uuid.UUID
}

// Credential is the resolved-and-decrypted credential the SSH dial path
// consumes. Plaintext secret fields are populated after Resolve. The
// API surface never returns this struct — only metadata.
type Credential struct {
	ID                   uuid.UUID
	Scope                Scope
	ScopeID              *uuid.UUID
	Name                 string
	Description          string
	Username             string
	AuthMethod           AuthMethod
	Password             string // plaintext, populated by Resolve / GetByID
	PrivateKey           string // plaintext, populated by Resolve / GetByID
	PrivateKeyPassphrase string // plaintext, populated by Resolve / GetByID
	SSHKeyFingerprint    string
	SSHKeyType           string
	SSHKeyBits           int
	SSHKeyComment        string
	IsDefault            bool
	IsActive             bool
	CreatedBy            uuid.UUID
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Service is the credential CRUD + resolver entry point.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds a Service to a DB pool. The DEK is loaded once at
// boot via secretkey.LoadFromFile; the service grabs it per call.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// NewCredential persists a new credential row. Validates scope/scope_id
// match, encrypts secret fields, enforces "only one system default."
//
// Spec AC-02 through AC-08.
func (s *Service) NewCredential(ctx context.Context, p NewParams) (uuid.UUID, error) {
	if err := validateNewParams(p); err != nil {
		return uuid.Nil, err
	}
	dek, err := secretkey.Active()
	if err != nil {
		return uuid.Nil, err
	}

	var encPw, encKey, encPass []byte
	if p.Password != "" {
		encPw, err = dek.Encrypt([]byte(p.Password))
		if err != nil {
			return uuid.Nil, fmt.Errorf("credential: encrypt password: %w", err)
		}
	}
	if p.PrivateKey != "" {
		encKey, err = dek.Encrypt([]byte(p.PrivateKey))
		if err != nil {
			return uuid.Nil, fmt.Errorf("credential: encrypt key: %w", err)
		}
	}
	if p.PrivateKeyPassphrase != "" {
		encPass, err = dek.Encrypt([]byte(p.PrivateKeyPassphrase))
		if err != nil {
			return uuid.Nil, fmt.Errorf("credential: encrypt passphrase: %w", err)
		}
	}

	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("credential: uuid: %w", err)
	}

	const stmt = `
		INSERT INTO credentials (
			id, scope, scope_id, name, description, username, auth_method,
			encrypted_password, encrypted_private_key, encrypted_private_key_passphrase,
			ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
			is_default, is_active, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, true, $16)`

	_, err = s.pool.Exec(ctx, stmt,
		id, string(p.Scope), p.ScopeID, p.Name, nilIfEmpty(p.Description),
		p.Username, string(p.AuthMethod),
		encPw, encKey, encPass,
		nilIfEmpty(p.SSHKeyFingerprint), nilIfEmpty(p.SSHKeyType),
		nilIfZero(p.SSHKeyBits), nilIfEmpty(p.SSHKeyComment),
		p.IsDefault, p.CreatedBy,
	)
	if err != nil {
		// Partial unique index violation on the system-default rule.
		if isUniqueViolation(err) && strings.Contains(err.Error(), "idx_credentials_one_system_default") {
			return uuid.Nil, ErrMultipleSystemDefaults
		}
		return uuid.Nil, fmt.Errorf("credential: insert: %w", err)
	}
	return id, nil
}

// GetByID returns the credential with decrypted secret fields.
//
// Spec AC-09.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*Credential, error) {
	return s.queryOne(ctx, `WHERE id = $1 AND is_active = true`, id)
}

// UpdateParams is the input to Update. Every field is a pointer: nil
// means "leave unchanged" — this is what makes the endpoint a true
// PATCH. scope and scope_id are intentionally absent; a credential's
// scope is immutable (switch a host between default and override by
// creating/cloning/deleting host-scope rows, not by mutating scope).
//
// Secret semantics: a non-nil, non-empty Password / PrivateKey /
// PrivateKeyPassphrase re-encrypts and replaces that secret; a nil
// pointer keeps the existing ciphertext untouched (no re-entry needed).
// When AuthMethod narrows away from a secret (e.g. both -> ssh_key),
// the now-irrelevant ciphertext is nulled regardless of what was sent.
type UpdateParams struct {
	ID                   uuid.UUID
	Name                 *string
	Description          *string
	Username             *string
	AuthMethod           *AuthMethod
	Password             *string
	PrivateKey           *string
	PrivateKeyPassphrase *string
	IsDefault            *bool
}

// UpdateResult reports the post-update shape for audit emission.
type UpdateResult struct {
	Scope         Scope
	AuthMethod    AuthMethod
	SecretRotated bool
}

// Update applies a partial change to an existing active credential.
// Runs in a single transaction with SELECT ... FOR UPDATE so the
// auto-demote of a prior system default and the new default set are
// atomic. Returns ErrNotFound for an unknown or soft-deleted id,
// ErrMissingSecret when the resulting auth_method lacks its secret,
// ErrUnknownAuthMethod for a bad method, and ErrMultipleSystemDefaults
// only as a belt against a concurrent default race.
//
// Spec AC-16..AC-21.
func (s *Service) Update(ctx context.Context, p UpdateParams) (UpdateResult, error) {
	dek, err := secretkey.Active()
	if err != nil {
		return UpdateResult{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("credential: update begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const sel = `
		SELECT scope, name, COALESCE(description, ''), username, auth_method,
		       encrypted_password, encrypted_private_key, encrypted_private_key_passphrase,
		       COALESCE(ssh_key_fingerprint, ''), COALESCE(ssh_key_type, ''),
		       COALESCE(ssh_key_bits, 0), COALESCE(ssh_key_comment, ''),
		       is_default, is_active
		  FROM credentials
		 WHERE id = $1
		 FOR UPDATE`
	var (
		curScope, curName, curDesc, curUser, curMethod string
		curEncPw, curEncKey, curEncPass                []byte
		curKeyFP, curKeyType, curKeyComment            string
		curKeyBits                                     int
		curIsDefault, isActive                         bool
	)
	if err := tx.QueryRow(ctx, sel, p.ID).Scan(
		&curScope, &curName, &curDesc, &curUser, &curMethod,
		&curEncPw, &curEncKey, &curEncPass,
		&curKeyFP, &curKeyType, &curKeyBits, &curKeyComment,
		&curIsDefault, &isActive,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UpdateResult{}, ErrNotFound
		}
		return UpdateResult{}, fmt.Errorf("credential: update select: %w", err)
	}
	if !isActive {
		// A soft-deleted credential is invisible to the API and cannot
		// be revived through PATCH.
		return UpdateResult{}, ErrNotFound
	}

	// Effective auth_method: override or keep.
	method := AuthMethod(curMethod)
	if p.AuthMethod != nil {
		method = *p.AuthMethod
	}
	switch method {
	case AuthSSHKey, AuthPassword, AuthBoth:
	default:
		return UpdateResult{}, ErrUnknownAuthMethod
	}

	// Re-encrypt any freshly supplied secret. A nil pointer keeps the
	// existing ciphertext.
	newEncPw, newEncKey, newEncPass := curEncPw, curEncKey, curEncPass
	secretRotated := false
	if p.Password != nil && *p.Password != "" {
		newEncPw, err = dek.Encrypt([]byte(*p.Password))
		if err != nil {
			return UpdateResult{}, fmt.Errorf("credential: encrypt password: %w", err)
		}
		secretRotated = true
	}
	if p.PrivateKey != nil && *p.PrivateKey != "" {
		newEncKey, err = dek.Encrypt([]byte(*p.PrivateKey))
		if err != nil {
			return UpdateResult{}, fmt.Errorf("credential: encrypt key: %w", err)
		}
		secretRotated = true
	}
	if p.PrivateKeyPassphrase != nil && *p.PrivateKeyPassphrase != "" {
		newEncPass, err = dek.Encrypt([]byte(*p.PrivateKeyPassphrase))
		if err != nil {
			return UpdateResult{}, fmt.Errorf("credential: encrypt passphrase: %w", err)
		}
		secretRotated = true
	}

	// Null the secrets (and key metadata) the effective method no longer
	// uses, so a narrowed credential doesn't keep dead ciphertext around.
	newKeyFP, newKeyType, newKeyComment, newKeyBits := curKeyFP, curKeyType, curKeyComment, curKeyBits
	switch method {
	case AuthSSHKey:
		newEncPw = nil
	case AuthPassword:
		newEncKey, newEncPass = nil, nil
		newKeyFP, newKeyType, newKeyComment, newKeyBits = "", "", "", 0
	}

	// The resulting credential must carry the secret(s) its method needs,
	// from either a fresh value or the retained ciphertext.
	if (method == AuthSSHKey || method == AuthBoth) && newEncKey == nil {
		return UpdateResult{}, ErrMissingSecret
	}
	if (method == AuthPassword || method == AuthBoth) && newEncPw == nil {
		return UpdateResult{}, ErrMissingSecret
	}

	// Metadata overrides.
	name, desc, user := curName, curDesc, curUser
	if p.Name != nil {
		name = *p.Name
	}
	if p.Description != nil {
		desc = *p.Description
	}
	if p.Username != nil {
		user = *p.Username
	}
	if name == "" || user == "" {
		return UpdateResult{}, errors.New("credential: username and name are required")
	}

	isDefault := curIsDefault
	if p.IsDefault != nil {
		isDefault = *p.IsDefault
	}
	// Auto-demote the prior system default before promoting this row, so
	// the one-active-system-default invariant holds at every statement
	// boundary (decision: editing a credential to be the new default
	// silently steps over the old one).
	if isDefault && Scope(curScope) == ScopeSystem {
		const demote = `
			UPDATE credentials SET is_default = false, updated_at = now()
			 WHERE scope = 'system' AND is_default = true AND is_active = true AND id <> $1`
		if _, err := tx.Exec(ctx, demote, p.ID); err != nil {
			return UpdateResult{}, fmt.Errorf("credential: demote default: %w", err)
		}
	}

	const upd = `
		UPDATE credentials SET
			name = $2, description = $3, username = $4, auth_method = $5,
			encrypted_password = $6, encrypted_private_key = $7,
			encrypted_private_key_passphrase = $8,
			ssh_key_fingerprint = $9, ssh_key_type = $10, ssh_key_bits = $11,
			ssh_key_comment = $12, is_default = $13, updated_at = now()
		 WHERE id = $1`
	if _, err := tx.Exec(ctx, upd,
		p.ID, name, nilIfEmpty(desc), user, string(method),
		newEncPw, newEncKey, newEncPass,
		nilIfEmpty(newKeyFP), nilIfEmpty(newKeyType), nilIfZero(newKeyBits), nilIfEmpty(newKeyComment),
		isDefault,
	); err != nil {
		if isUniqueViolation(err) && strings.Contains(err.Error(), "idx_credentials_one_system_default") {
			return UpdateResult{}, ErrMultipleSystemDefaults
		}
		return UpdateResult{}, fmt.Errorf("credential: update exec: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return UpdateResult{}, fmt.Errorf("credential: update commit: %w", err)
	}
	return UpdateResult{Scope: Scope(curScope), AuthMethod: method, SecretRotated: secretRotated}, nil
}

// CloneParams describes the target row CloneCredential should create.
// The source row's secret material (ciphertext columns) is copied
// verbatim — no decrypt/re-encrypt round-trip. This keeps the DEK off
// the call path entirely and avoids re-exposing plaintext anywhere
// outside the original create.
type CloneParams struct {
	SourceID  uuid.UUID
	Scope     Scope
	ScopeID   *uuid.UUID
	Name      string // when "", server appends " (clone)" to the source name
	IsDefault bool
	CreatedBy uuid.UUID
}

// CloneCredential creates a new credential row whose secret material
// (encrypted_password, encrypted_private_key, encrypted_private_key_passphrase)
// and identity fields (username, auth_method, ssh_key_*) match the
// source. The clone gets a fresh id, the caller's scope/scope_id, and
// the caller's choice of name + is_default.
//
// Validates scope/scope_id consistency. Returns:
//   - ErrNotFound when the source id is unknown or inactive
//   - ErrInvalidScope when target scope/scope_id are inconsistent
//   - ErrMultipleSystemDefaults when is_default=true collides with an
//     existing system default
//
// Spec api-credentials C-05 / AC-13..15.
func (s *Service) CloneCredential(ctx context.Context, p CloneParams) (uuid.UUID, error) {
	if err := validateCloneScope(p); err != nil {
		return uuid.Nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("credential: clone begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const srcQuery = `
		SELECT name, COALESCE(description, ''), username, auth_method,
		       encrypted_password, encrypted_private_key, encrypted_private_key_passphrase,
		       COALESCE(ssh_key_fingerprint, ''), COALESCE(ssh_key_type, ''),
		       COALESCE(ssh_key_bits, 0), COALESCE(ssh_key_comment, '')
		  FROM credentials
		 WHERE id = $1 AND is_active = true
		 FOR UPDATE`
	var (
		srcName, srcDesc, srcUser, srcMethod string
		srcEncPw, srcEncKey, srcEncPass      []byte
		srcKeyFP, srcKeyType, srcKeyComment  string
		srcKeyBits                           int
	)
	if err := tx.QueryRow(ctx, srcQuery, p.SourceID).Scan(
		&srcName, &srcDesc, &srcUser, &srcMethod,
		&srcEncPw, &srcEncKey, &srcEncPass,
		&srcKeyFP, &srcKeyType, &srcKeyBits, &srcKeyComment,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("credential: clone source: %w", err)
	}

	newName := p.Name
	if newName == "" {
		newName = srcName + " (clone)"
	}

	newID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("credential: clone uuid: %w", err)
	}

	const insertStmt = `
		INSERT INTO credentials (
			id, scope, scope_id, name, description, username, auth_method,
			encrypted_password, encrypted_private_key, encrypted_private_key_passphrase,
			ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
			is_default, is_active, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, true, $16)`
	_, err = tx.Exec(ctx, insertStmt,
		newID, string(p.Scope), p.ScopeID, newName, nilIfEmpty(srcDesc),
		srcUser, srcMethod,
		srcEncPw, srcEncKey, srcEncPass,
		nilIfEmpty(srcKeyFP), nilIfEmpty(srcKeyType),
		nilIfZero(srcKeyBits), nilIfEmpty(srcKeyComment),
		p.IsDefault, p.CreatedBy,
	)
	if err != nil {
		if isUniqueViolation(err) && strings.Contains(err.Error(), "idx_credentials_one_system_default") {
			return uuid.Nil, ErrMultipleSystemDefaults
		}
		return uuid.Nil, fmt.Errorf("credential: clone insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("credential: clone commit: %w", err)
	}
	return newID, nil
}

// validateCloneScope enforces scope/scope_id consistency for the clone
// target. Mirrors validateNewParams but skips the auth_method/secret
// checks since the source row already satisfied them.
func validateCloneScope(p CloneParams) error {
	switch p.Scope {
	case ScopeSystem:
		if p.ScopeID != nil {
			return ErrInvalidScope
		}
	case ScopeHost:
		if p.ScopeID == nil {
			return ErrInvalidScope
		}
	default:
		return ErrInvalidScope
	}
	return nil
}

// Resolve returns the highest-precedence credential for the given host:
// host-scope row first, then system-default. Returns ErrNoCredential
// when neither is available.
//
// Spec AC-10, AC-11, AC-12, C-06, C-07.
func (s *Service) Resolve(ctx context.Context, hostID uuid.UUID) (*Credential, error) {
	// 1) host-scope first.
	c, err := s.queryOne(ctx,
		`WHERE scope = 'host' AND scope_id = $1 AND is_active = true
		 ORDER BY created_at DESC LIMIT 1`, hostID)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// 2) system default.
	c, err = s.queryOne(ctx,
		`WHERE scope = 'system' AND is_default = true AND is_active = true
		 ORDER BY created_at DESC LIMIT 1`)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return nil, ErrNoCredential
}

// queryOne runs the shared SELECT against a caller-supplied WHERE
// clause and decrypts secret fields.
func (s *Service) queryOne(ctx context.Context, whereClause string, args ...any) (*Credential, error) {
	dek, err := secretkey.Active()
	if err != nil {
		return nil, err
	}
	const baseSelect = `
		SELECT id, scope, scope_id, name, COALESCE(description, ''),
		       username, auth_method,
		       encrypted_password, encrypted_private_key, encrypted_private_key_passphrase,
		       COALESCE(ssh_key_fingerprint, ''), COALESCE(ssh_key_type, ''),
		       COALESCE(ssh_key_bits, 0), COALESCE(ssh_key_comment, ''),
		       is_default, is_active, created_by, created_at, updated_at
		FROM credentials `
	var c Credential
	var scopeStr, methodStr string
	var scopeID *uuid.UUID
	var encPw, encKey, encPass []byte
	err = s.pool.QueryRow(ctx, baseSelect+whereClause, args...).Scan(
		&c.ID, &scopeStr, &scopeID, &c.Name, &c.Description,
		&c.Username, &methodStr,
		&encPw, &encKey, &encPass,
		&c.SSHKeyFingerprint, &c.SSHKeyType, &c.SSHKeyBits, &c.SSHKeyComment,
		&c.IsDefault, &c.IsActive, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("credential: query: %w", err)
	}
	c.Scope = Scope(scopeStr)
	c.ScopeID = scopeID
	c.AuthMethod = AuthMethod(methodStr)
	if encPw != nil {
		pt, err := dek.Decrypt(encPw)
		if err != nil {
			return nil, fmt.Errorf("credential: decrypt password: %w", err)
		}
		c.Password = string(pt)
	}
	if encKey != nil {
		pt, err := dek.Decrypt(encKey)
		if err != nil {
			return nil, fmt.Errorf("credential: decrypt key: %w", err)
		}
		c.PrivateKey = string(pt)
	}
	if encPass != nil {
		pt, err := dek.Decrypt(encPass)
		if err != nil {
			return nil, fmt.Errorf("credential: decrypt passphrase: %w", err)
		}
		c.PrivateKeyPassphrase = string(pt)
	}
	return &c, nil
}

// validateNewParams enforces the spec-level pre-conditions on
// NewCredential inputs. CHECK constraints in the migration are the
// belt; this is the suspenders.
//
// Spec C-03, C-04.
func validateNewParams(p NewParams) error {
	switch p.Scope {
	case ScopeSystem:
		if p.ScopeID != nil {
			return ErrInvalidScope
		}
	case ScopeHost:
		if p.ScopeID == nil {
			return ErrInvalidScope
		}
	default:
		return ErrInvalidScope
	}
	switch p.AuthMethod {
	case AuthSSHKey:
		if p.PrivateKey == "" {
			return ErrMissingSecret
		}
	case AuthPassword:
		if p.Password == "" {
			return ErrMissingSecret
		}
	case AuthBoth:
		if p.PrivateKey == "" || p.Password == "" {
			return ErrMissingSecret
		}
	default:
		return ErrUnknownAuthMethod
	}
	if p.Username == "" || p.Name == "" {
		return errors.New("credential: username and name are required")
	}
	return nil
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nilIfZero(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
