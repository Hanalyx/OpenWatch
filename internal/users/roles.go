package users

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// CustomRole-related errors.
var (
	ErrRoleIDTaken       = errors.New("users: role id collides with a built-in or existing custom role")
	ErrUnknownPermission = errors.New("users: role grants permission not in the registry")
	ErrCustomRoleEmpty   = errors.New("users: custom role must grant at least one permission")
)

// PermissionValidator returns true if a permission id is registered.
// Decoupled so the users package doesn't import internal/auth (which
// would create a cycle: auth → users → auth via tests).
type PermissionValidator func(perm string) bool

// CustomRoleParams is the input to CreateCustomRole.
type CustomRoleParams struct {
	ID          string
	Description string
	Permissions []string
	CreatedBy   uuid.UUID
}

// Role is the on-wire shape for built-in and custom roles.
type Role struct {
	ID          string
	Description string
	IsBuiltIn   bool
	Permissions []string
}

// ListUsers returns all active users. Slice A keeps the result flat —
// cursor pagination lands when scan volumes make it necessary.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	// The roles aggregate is a correlated subquery (one row per user, no
	// join fan-out) so a user with no roles still lists with an empty array.
	const stmt = `
		SELECT u.id, u.username, u.email, u.last_password_change_at, u.created_at, u.updated_at, u.disabled_at,
		       COALESCE(ARRAY(
		         SELECT ur.role_id FROM user_roles ur
		         WHERE ur.user_id = u.id ORDER BY ur.role_id
		       ), '{}') AS roles
		FROM users u
		WHERE u.deleted_at IS NULL
		ORDER BY u.created_at ASC`
	rows, err := s.pool.Query(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("users: list: %w", err)
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Email,
			&u.LastPasswordChangeAt, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt, &u.Roles,
		); err != nil {
			return nil, fmt.Errorf("users: scan: %w", err)
		}
		out = append(out, u)
	}
	return out, nil
}

// CreateCustomRole inserts a new row in roles with is_built_in=false.
// validator must accept every permission in p.Permissions; unknown
// permissions return ErrUnknownPermission with the offending ids
// recoverable from the returned []string.
//
// Spec api-users AC-11, AC-12, C-03, C-04.
func (s *Service) CreateCustomRole(ctx context.Context, p CustomRoleParams, validator PermissionValidator) (Role, []string, error) {
	if len(p.Permissions) == 0 {
		return Role{}, nil, ErrCustomRoleEmpty
	}
	// Validate every permission and collect ALL invalid ids so the
	// API can return a useful detail.invalid_permissions array.
	invalid := []string{}
	for _, perm := range p.Permissions {
		if !validator(perm) {
			invalid = append(invalid, perm)
		}
	}
	if len(invalid) > 0 {
		return Role{}, invalid, ErrUnknownPermission
	}
	// Built-in collision check (cheap; before the SQL round-trip).
	for _, builtin := range []string{"viewer", "auditor", "ops_lead", "security_admin", "admin"} {
		if p.ID == builtin {
			return Role{}, nil, ErrRoleIDTaken
		}
	}
	const stmt = `
		INSERT INTO roles (id, description, is_built_in, permissions)
		VALUES ($1, $2, false, $3)
		RETURNING id, description, is_built_in, permissions`
	var r Role
	err := s.pool.QueryRow(ctx, stmt, p.ID, p.Description, p.Permissions).Scan(
		&r.ID, &r.Description, &r.IsBuiltIn, &r.Permissions,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Role{}, nil, ErrRoleIDTaken
		}
		return Role{}, nil, fmt.Errorf("users: insert role: %w", err)
	}
	return r, nil, nil
}

// isUniqueViolation reports whether err is a pgx unique-constraint
// SQLSTATE (23505). Used by CreateCustomRole to translate a duplicate
// id to ErrRoleIDTaken.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
