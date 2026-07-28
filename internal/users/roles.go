package users

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CustomRole-related errors.
var (
	ErrRoleIDTaken       = errors.New("users: role id collides with a built-in or existing custom role")
	ErrUnknownPermission = errors.New("users: role grants permission not in the registry")
	ErrCustomRoleEmpty   = errors.New("users: custom role must grant at least one permission")
	// ErrRoleExceedsGrant is returned when the caller tries to author a custom
	// role granting a permission they do not themselves hold.
	ErrRoleExceedsGrant = errors.New("users: custom role grants a permission the creator does not hold")
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
	// CallerHolds reports whether the CREATOR holds a permission. Supplied by
	// the handler from the caller's identity so this package need not import
	// internal/auth (which would cycle). A nil CallerHolds skips the
	// subset check and is intended ONLY for trusted internal seeding; every
	// request-driven path must set it.
	CallerHolds func(perm string) bool
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
	// Anti-escalation on the AUTHORING step. Validating that a permission
	// exists is not the same as validating the author may confer it: without
	// this, a caller could author a role granting anything in the registry and
	// then have it assigned, an escalation that neither step catches alone.
	// CallerHolds is supplied by the handler from the caller's identity.
	if p.CallerHolds != nil {
		var exceeds []string
		for _, perm := range p.Permissions {
			if !p.CallerHolds(perm) {
				exceeds = append(exceeds, perm)
			}
		}
		if len(exceeds) > 0 {
			return Role{}, exceeds, ErrRoleExceedsGrant
		}
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

// RolePermissions returns the permissions a role confers, and whether the role
// exists. Built-in roles are answered from the registry by the caller; this
// reads the roles table, which is where a CUSTOM role's permission set lives.
//
// It backs the anti-escalation guard (auth.RoleGrantsWithinResolved). Without
// it the guard can only see built-in roles, and its only safe response to a
// custom role is to deny, which would break legitimate custom-role assignment.
//
// It returns three states. A missing row is (nil, false, nil): provably absent.
// A query failure is (nil, false, err): indeterminate, and the guard denies.
// Collapsing the two would either turn a client typo into a 403 or let a
// database fault open the guard.
func (s *Service) RolePermissions(ctx context.Context, roleID string) ([]string, bool, error) {
	var perms []string
	err := s.pool.QueryRow(ctx,
		`SELECT permissions FROM roles WHERE id = $1`, roleID).Scan(&perms)
	if errors.Is(err, pgx.ErrNoRows) {
		// Provably absent. Not an error: the caller needs to tell this apart
		// from "could not determine" so an unknown role id stays a 400 and
		// does not become a 403.
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("users: role permissions: %w", err)
	}
	return perms, true, nil
}
