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
