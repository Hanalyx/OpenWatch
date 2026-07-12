// Package users owns the users + user_roles tables. CRUD never exposes
// the password hash; role assignment is gated by the roles table FK.
//
// Implements identity.Lookups via PrimaryRoleFor so the identity binder
// can translate a session into auth.Identity.
//
// Spec: app/specs/system/user-management.spec.yaml.
package users

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service errors. Returned from the CRUD + role-mgmt API.
var (
	ErrUserNotFound   = errors.New("users: not found")
	ErrUnknownRole    = errors.New("users: role does not exist")
	ErrUserHasNoRoles = errors.New("users: user has no roles assigned")
	// ErrUserDisabled is returned when an operation targets a disabled
	// account, or (for the login path) when a disabled user authenticates.
	ErrUserDisabled = errors.New("users: account is disabled")
	// ErrCannotDisableSelf guards an admin from disabling their own account
	// (lockout prevention).
	ErrCannotDisableSelf = errors.New("users: cannot disable your own account")
	// ErrEmailTaken is returned by UpdateProfile when the requested email is
	// already used by another active user (the sign-in identity must be
	// unique). Maps to HTTP 409.
	ErrEmailTaken = errors.New("users: email already in use")
	// ErrInvalidProfile is returned for a malformed profile update (e.g. an
	// empty email). Maps to HTTP 400.
	ErrInvalidProfile = errors.New("users: invalid profile update")
)

// User is the safe shape returned by every read API. PasswordHash is
// intentionally NOT a field on this struct — spec C-01 says reads must
// never return it. Use the lower-level repository if you need it for
// password verification at login.
//
// Admin status is derived from user_roles (presence of the "admin"
// role); no separate is_admin flag exists on the wire or the table.
// Callers needing to render "is this user an admin?" should consult
// RolesForUser or PrimaryRoleFor.
type User struct {
	ID                   uuid.UUID
	Username             string
	Email                string
	LastPasswordChangeAt time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	// DisabledAt is non-nil when the account is disabled (cannot
	// authenticate). Distinct from a soft-delete: a disabled account is
	// recoverable via Enable.
	DisabledAt *time.Time
	// Roles holds the role IDs assigned to the user (from user_roles).
	// Populated by ListUsers via an aggregate; other lookups (login path,
	// GetUserByID) leave it nil since they do not need the membership join.
	Roles []string

	// Self-service profile fields (migration 0050). Free text, may be
	// empty. Populated by the queryOne lookups (GetUserByID / by-username);
	// the login-path scan leaves them empty since login does not need them.
	FullName    string
	DisplayName string
	JobTitle    string
	Timezone    string
	Phone       string
}

// CreateParams is the input to CreateUser. Plaintext password is hashed
// and validated inside Create; never persists outside the hash. The
// AdminPolicy flag selects which password-strength policy is applied
// at creation; callers who know the user will hold the admin role set
// it true (the create-admin CLI does this). Role assignment happens
// separately via AssignRole.
type CreateParams struct {
	Username    string
	Email       string
	Password    string
	AdminPolicy bool // true → AdminPolicy at password validation; false → DefaultPolicy
}

// rolePrecedence is the "highest privilege wins" ordering for
// PrimaryRoleFor (spec C-06, AC-11). Higher index = higher precedence.
var rolePrecedence = map[auth.RoleID]int{
	auth.RoleViewer:        1,
	auth.RoleAuditor:       2,
	auth.RoleOpsLead:       3,
	auth.RoleSecurityAdmin: 4,
	auth.RoleAdmin:         5,
}

// Service is the user/role CRUD entry point. Construct via NewService.
type Service struct {
	pool   *pgxpool.Pool
	corpus identity.BreachCorpus // nil = skip breach check (dev mode only)
}

// NewService binds a Service to a DB pool. The breach corpus is
// optional — production deployments wire it in. Tests typically pass nil
// or a small NewMemoryBreachCorpus fixture.
func NewService(pool *pgxpool.Pool, corpus identity.BreachCorpus) *Service {
	return &Service{pool: pool, corpus: corpus}
}

// CreateUser hashes + validates the password, inserts the row.
// Returns the safe User shape — password hash never leaves the package.
//
// Spec AC-01, AC-02, AC-03.
func (s *Service) CreateUser(ctx context.Context, p CreateParams) (User, error) {
	policy := identity.DefaultPolicy()
	if p.AdminPolicy {
		policy = identity.AdminPolicy()
	}
	if err := identity.ValidatePassword(p.Password, policy, s.corpus); err != nil {
		// Surfaces ErrPasswordTooShort/ErrPasswordTooLong/ErrPasswordBreached
		// unchanged so callers can map to their canonical error envelope.
		return User{}, err
	}
	hash, err := identity.HashPassword(p.Password)
	if err != nil {
		return User{}, fmt.Errorf("users: hash password: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, fmt.Errorf("users: uuid: %w", err)
	}
	const stmt = `
		INSERT INTO users (id, username, email, password_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id, username, email, last_password_change_at, created_at, updated_at`
	var u User
	err = s.pool.QueryRow(ctx, stmt, id, p.Username, p.Email, hash).Scan(
		&u.ID, &u.Username, &u.Email,
		&u.LastPasswordChangeAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return User{}, fmt.Errorf("users: insert: %w", err)
	}
	return u, nil
}

// CreateFederatedUser provisions a user authenticated by an external IdP
// (SSO). The account has NO usable password: a random 32-byte secret is
// hashed and discarded, so local password login can never succeed — the
// user authenticates only through the identity provider. The supplied role
// is assigned in the same call. Username/email uniqueness is enforced by
// the DB; a collision with an existing active user surfaces as an error
// (the caller maps it) rather than silently merging accounts.
//
// Spec system-sso AC-08.
func (s *Service) CreateFederatedUser(ctx context.Context, username, email string, role auth.RoleID) (User, error) {
	// Unusable password: 32 bytes of entropy, hashed and never disclosed.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return User{}, fmt.Errorf("users: federated entropy: %w", err)
	}
	hash, err := identity.HashPassword(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		return User{}, fmt.Errorf("users: hash federated password: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, fmt.Errorf("users: uuid: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("users: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var u User
	const insUser = `
		INSERT INTO users (id, username, email, password_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id, username, email, last_password_change_at, created_at, updated_at`
	if err := tx.QueryRow(ctx, insUser, id, username, email, hash).Scan(
		&u.ID, &u.Username, &u.Email,
		&u.LastPasswordChangeAt, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return User{}, fmt.Errorf("users: insert federated: %w", err)
	}
	const insRole = `
		INSERT INTO user_roles (user_id, role_id, granted_by)
		VALUES ($1, $2, NULL)`
	if _, err := tx.Exec(ctx, insRole, u.ID, string(role)); err != nil {
		if isFKViolation(err) {
			return User{}, ErrUnknownRole
		}
		return User{}, fmt.Errorf("users: assign federated role: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("users: commit federated: %w", err)
	}
	return u, nil
}

// GetUserByID returns the user when active; ErrUserNotFound for unknown
// or soft-deleted IDs.
//
// Spec AC-04.
func (s *Service) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	const stmt = `
		SELECT id, username, email, last_password_change_at, created_at, updated_at, disabled_at,
		       full_name, display_name, job_title, timezone, phone
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`
	return s.queryOne(ctx, stmt, id)
}

// GetUserByUsername returns the user when active; ErrUserNotFound for
// unknown or soft-deleted usernames.
//
// Spec AC-05.
func (s *Service) GetUserByUsername(ctx context.Context, username string) (User, error) {
	const stmt = `
		SELECT id, username, email, last_password_change_at, created_at, updated_at, disabled_at,
		       full_name, display_name, job_title, timezone, phone
		FROM users
		WHERE username = $1 AND deleted_at IS NULL`
	return s.queryOne(ctx, stmt, username)
}

// ProfileUpdate is a partial self-profile edit: a nil field is left
// unchanged, a non-nil field replaces the stored value (an empty string
// clears it, except Email which may not be empty).
type ProfileUpdate struct {
	Email       *string
	FullName    *string
	DisplayName *string
	JobTitle    *string
	Timezone    *string
	Phone       *string
}

// UpdateProfile applies a partial profile edit for the user's own account
// (PATCH /auth/me). Email is the sign-in identity: it is trimmed, must be
// non-empty, and must be unique among active users — ErrEmailTaken (409)
// otherwise. Username, role, and password are not editable here. Returns
// the updated user.
func (s *Service) UpdateProfile(ctx context.Context, id uuid.UUID, p ProfileUpdate) (User, error) {
	var emailArg *string
	if p.Email != nil {
		email := strings.TrimSpace(*p.Email)
		if email == "" || !strings.Contains(email, "@") {
			return User{}, fmt.Errorf("%w: email must be a non-empty address", ErrInvalidProfile)
		}
		var taken bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL AND id <> $2)`,
			email, id).Scan(&taken); err != nil {
			return User{}, fmt.Errorf("users: email uniqueness check: %w", err)
		}
		if taken {
			return User{}, ErrEmailTaken
		}
		emailArg = &email
	}

	const stmt = `
		UPDATE users SET
			email        = COALESCE($2, email),
			full_name    = COALESCE($3, full_name),
			display_name = COALESCE($4, display_name),
			job_title    = COALESCE($5, job_title),
			timezone     = COALESCE($6, timezone),
			phone        = COALESCE($7, phone),
			updated_at   = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id, username, email, last_password_change_at, created_at, updated_at, disabled_at,
		          full_name, display_name, job_title, timezone, phone`
	var u User
	err := s.pool.QueryRow(ctx, stmt, id, emailArg, p.FullName, p.DisplayName, p.JobTitle, p.Timezone, p.Phone).Scan(
		&u.ID, &u.Username, &u.Email, &u.LastPasswordChangeAt, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt,
		&u.FullName, &u.DisplayName, &u.JobTitle, &u.Timezone, &u.Phone,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("users: update profile: %w", err)
	}
	return u, nil
}

// VerifyUserPassword is the login-path helper. Looks up the hash and
// runs identity.VerifyPassword. Returns ErrUserNotFound if the user is
// deleted or unknown; identity's own error on bad password. Never
// returns the hash to the caller.
func (s *Service) VerifyUserPassword(ctx context.Context, username, password string) (User, error) {
	const stmt = `
		SELECT id, username, email, last_password_change_at, created_at, updated_at, disabled_at, password_hash
		FROM users
		WHERE username = $1 AND deleted_at IS NULL`
	var u User
	var hash string
	err := s.pool.QueryRow(ctx, stmt, username).Scan(
		&u.ID, &u.Username, &u.Email,
		&u.LastPasswordChangeAt, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt,
		&hash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("users: lookup: %w", err)
	}
	if err := identity.VerifyPassword(password, hash); err != nil {
		return User{}, err
	}
	return u, nil
}

// UpdatePassword re-runs the policy validator and on success updates
// password_hash + bumps last_password_change_at.
//
// Policy selection is derived from the user's primary role at change
// time: admin role → AdminPolicy (15-char minimum), any other role
// (or no role) → DefaultPolicy. Replaces the legacy users.is_admin
// column which had drift-prone semantics.
//
// Spec AC-06.
func (s *Service) UpdatePassword(ctx context.Context, id uuid.UUID, newPassword string) error {
	if _, err := s.GetUserByID(ctx, id); err != nil {
		return err
	}
	policy := identity.DefaultPolicy()
	if role, err := s.PrimaryRoleFor(ctx, id); err == nil && role == auth.RoleAdmin {
		policy = identity.AdminPolicy()
	}
	if err := identity.ValidatePassword(newPassword, policy, s.corpus); err != nil {
		return err
	}
	hash, err := identity.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("users: hash password: %w", err)
	}
	const stmt = `
		UPDATE users SET password_hash = $1, last_password_change_at = now(), updated_at = now()
		WHERE id = $2 AND deleted_at IS NULL`
	tag, err := s.pool.Exec(ctx, stmt, hash, id)
	if err != nil {
		return fmt.Errorf("users: update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SoftDelete sets deleted_at. The user becomes invisible to lookups
// per spec C-05. Username/email can be reused after delete via the
// partial-unique-index pattern from migration 0005.
//
// Spec AC-07.
func (s *Service) SoftDelete(ctx context.Context, id uuid.UUID) error {
	const stmt = `UPDATE users SET deleted_at = now(), updated_at = now()
	              WHERE id = $1 AND deleted_at IS NULL`
	tag, err := s.pool.Exec(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("users: soft delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// AdminResetPassword sets a user's password on an administrator's authority:
// unlike the self-service password change it does NOT require the current
// password. The new password still runs through the role-aware policy +
// breach screen (via UpdatePassword). The target's active sessions are then
// revoked so they must re-authenticate with the new password.
//
// Spec api-users (admin reset-password).
func (s *Service) AdminResetPassword(ctx context.Context, id uuid.UUID, newPassword string) error {
	if err := s.UpdatePassword(ctx, id, newPassword); err != nil {
		return err
	}
	if err := identity.RevokeAllSessionsForUser(ctx, s.pool, id); err != nil {
		return fmt.Errorf("users: revoke sessions after reset: %w", err)
	}
	return nil
}

// Disable marks an account disabled (disabled_at = now). A disabled user
// cannot authenticate: the login path rejects them and disabling revokes
// their active sessions so the cutoff is immediate. Idempotent: disabling an
// already-disabled user refreshes the timestamp. ErrUserNotFound for unknown
// or soft-deleted users.
//
// Spec api-users (disable/enable).
func (s *Service) Disable(ctx context.Context, id uuid.UUID) error {
	const stmt = `UPDATE users SET disabled_at = now(), updated_at = now()
	              WHERE id = $1 AND deleted_at IS NULL`
	tag, err := s.pool.Exec(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("users: disable: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	if err := identity.RevokeAllSessionsForUser(ctx, s.pool, id); err != nil {
		return fmt.Errorf("users: revoke sessions on disable: %w", err)
	}
	return nil
}

// Enable clears the disabled flag. The user can authenticate again with a
// fresh login; sessions revoked while disabled stay dead. ErrUserNotFound for
// unknown or soft-deleted users.
//
// Spec api-users (disable/enable).
func (s *Service) Enable(ctx context.Context, id uuid.UUID) error {
	const stmt = `UPDATE users SET disabled_at = NULL, updated_at = now()
	              WHERE id = $1 AND deleted_at IS NULL`
	tag, err := s.pool.Exec(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("users: enable: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// AssignRole inserts a user_roles row. Role must exist; FK enforcement
// is mandatory (spec C-04). Idempotent — re-assigning an existing role
// is a no-op.
//
// Spec AC-08.
func (s *Service) AssignRole(ctx context.Context, userID uuid.UUID, role auth.RoleID, grantedBy *uuid.UUID) error {
	const stmt = `
		INSERT INTO user_roles (user_id, role_id, granted_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING`
	_, err := s.pool.Exec(ctx, stmt, userID, string(role), grantedBy)
	if err != nil {
		// Foreign-key violation on role_id surfaces as the standard pgx
		// SQLSTATE 23503. Translate to ErrUnknownRole.
		if isFKViolation(err) {
			return ErrUnknownRole
		}
		return fmt.Errorf("users: assign role: %w", err)
	}
	return nil
}

// UnassignRole removes the link. Idempotent — second call returns nil
// (no "wasn't assigned" error).
//
// Spec AC-10.
func (s *Service) UnassignRole(ctx context.Context, userID uuid.UUID, role auth.RoleID) error {
	const stmt = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	_, err := s.pool.Exec(ctx, stmt, userID, string(role))
	if err != nil {
		return fmt.Errorf("users: unassign role: %w", err)
	}
	return nil
}

// RolesForUser returns the active role ids assigned to the user.
// Deleted users return an empty slice (not an error) per spec AC-09.
func (s *Service) RolesForUser(ctx context.Context, userID uuid.UUID) ([]auth.RoleID, error) {
	const stmt = `
		SELECT ur.role_id
		FROM user_roles ur
		JOIN users u ON u.id = ur.user_id
		WHERE ur.user_id = $1 AND u.deleted_at IS NULL`
	rows, err := s.pool.Query(ctx, stmt, userID)
	if err != nil {
		return nil, fmt.Errorf("users: list roles: %w", err)
	}
	defer rows.Close()
	out := []auth.RoleID{}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			return nil, fmt.Errorf("users: scan role: %w", err)
		}
		out = append(out, auth.RoleID(rid))
	}
	return out, nil
}

// PrimaryRoleFor returns the highest-precedence role assigned to the
// user. Implements the identity.Lookups interface so the binder can
// populate auth.Identity from a session.
//
// Spec AC-11, C-06.
func (s *Service) PrimaryRoleFor(ctx context.Context, userID uuid.UUID) (auth.RoleID, error) {
	roles, err := s.RolesForUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if len(roles) == 0 {
		return "", ErrUserHasNoRoles
	}
	var (
		best     auth.RoleID
		bestRank int
	)
	for _, r := range roles {
		if rank := rolePrecedence[r]; rank > bestRank {
			best = r
			bestRank = rank
		}
	}
	if bestRank == 0 {
		// Unknown role assigned (e.g., a custom role not yet in the
		// precedence map). Return the first one as a fallback.
		return roles[0], nil
	}
	return best, nil
}

// RoleForUser is the identity.Lookups adapter. Direct synonym for
// PrimaryRoleFor with the same signature shape.
func (s *Service) RoleForUser(ctx context.Context, userID uuid.UUID) (auth.RoleID, error) {
	return s.PrimaryRoleFor(ctx, userID)
}

// queryOne is the GetByID/GetByUsername shared helper.
func (s *Service) queryOne(ctx context.Context, stmt string, arg any) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, stmt, arg).Scan(
		&u.ID, &u.Username, &u.Email,
		&u.LastPasswordChangeAt, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt,
		&u.FullName, &u.DisplayName, &u.JobTitle, &u.Timezone, &u.Phone,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("users: query: %w", err)
	}
	return u, nil
}

// isFKViolation reports whether err is a pgx foreign-key SQLSTATE
// (23503). Used to translate "role doesn't exist" to ErrUnknownRole.
func isFKViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23503"
	}
	return false
}
