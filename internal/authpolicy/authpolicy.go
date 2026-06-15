// Package authpolicy manages the workspace-wide authentication policy:
// the require-MFA flag and the session idle/absolute timeout windows.
//
// The policy is a single row (migration 0033). Promoting the session
// windows from hard-coded constants to data lets a security admin tune
// them from Settings -> Security without a redeploy. Update re-primes the
// identity package's active windows so the change takes effect for newly
// issued sessions and the rolling idle extension immediately.
//
// Spec: system-auth-policy, api-auth-policy.
package authpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Bounds for the session timeout windows. Enforced in Update so a typo in
// the UI can neither disable session expiry (a zero/huge window) nor set a
// nonsensical absolute < idle. Locked per spec C-03; widen only via spec.
const (
	MinIdleTimeout     = 5 * time.Minute
	MaxIdleTimeout     = 24 * time.Hour
	MinAbsoluteTimeout = 1 * time.Hour
	MaxAbsoluteTimeout = 30 * 24 * time.Hour
)

// ErrInvalidParams is returned when Update validation fails (out-of-bounds
// window, or absolute < idle).
var ErrInvalidParams = errors.New("authpolicy: invalid parameters")

// Policy is the effective authentication policy.
type Policy struct {
	RequireMFA      bool
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	UpdatedAt       time.Time
	UpdatedBy       *uuid.UUID
}

// UpdateParams is the input to Update. All fields are required — the PUT
// replaces the whole policy (there is exactly one).
type UpdateParams struct {
	RequireMFA      bool
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	UpdatedBy       *uuid.UUID
}

// Service is the auth-policy store.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds a Service to a DB pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// Get returns the current policy. The singleton row is seeded by the
// migration, so a missing row is an internal error rather than a normal
// empty state.
//
// Spec api-auth-policy AC-01.
func (s *Service) Get(ctx context.Context) (Policy, error) {
	const stmt = `
		SELECT require_mfa, session_idle_timeout_seconds,
		       session_absolute_timeout_seconds, updated_at, updated_by
		FROM auth_policy
		WHERE id = TRUE`
	var (
		p          Policy
		idleSecs   int
		absSecs    int
		updatedBy  *uuid.UUID
		updatedRow time.Time
	)
	if err := s.pool.QueryRow(ctx, stmt).Scan(
		&p.RequireMFA, &idleSecs, &absSecs, &updatedRow, &updatedBy,
	); err != nil {
		return Policy{}, fmt.Errorf("authpolicy: get: %w", err)
	}
	p.IdleTimeout = time.Duration(idleSecs) * time.Second
	p.AbsoluteTimeout = time.Duration(absSecs) * time.Second
	p.UpdatedAt = updatedRow
	p.UpdatedBy = updatedBy
	return p, nil
}

// Update validates and persists the policy, then re-primes the identity
// package's active session windows so the change takes effect at once.
//
// Spec api-auth-policy AC-02, system-auth-policy AC-05.
func (s *Service) Update(ctx context.Context, p UpdateParams) (Policy, error) {
	if err := validate(p); err != nil {
		return Policy{}, err
	}
	const stmt = `
		UPDATE auth_policy
		SET require_mfa = $1,
		    session_idle_timeout_seconds = $2,
		    session_absolute_timeout_seconds = $3,
		    updated_at = now(),
		    updated_by = $4
		WHERE id = TRUE
		RETURNING require_mfa, session_idle_timeout_seconds,
		          session_absolute_timeout_seconds, updated_at, updated_by`
	var (
		out       Policy
		idleSecs  int
		absSecs   int
		updatedBy *uuid.UUID
		updatedAt time.Time
	)
	if err := s.pool.QueryRow(ctx, stmt,
		p.RequireMFA,
		int(p.IdleTimeout.Seconds()),
		int(p.AbsoluteTimeout.Seconds()),
		p.UpdatedBy,
	).Scan(&out.RequireMFA, &idleSecs, &absSecs, &updatedAt, &updatedBy); err != nil {
		return Policy{}, fmt.Errorf("authpolicy: update: %w", err)
	}
	out.IdleTimeout = time.Duration(idleSecs) * time.Second
	out.AbsoluteTimeout = time.Duration(absSecs) * time.Second
	out.UpdatedAt = updatedAt
	out.UpdatedBy = updatedBy
	s.prime(out)
	return out, nil
}

// Prime loads the persisted policy and installs its windows into the
// identity package. Called once at server startup so sessions honour the
// stored policy from the first request, not just after the first Update.
//
// Spec system-auth-policy AC-06.
func (s *Service) Prime(ctx context.Context) error {
	p, err := s.Get(ctx)
	if err != nil {
		return err
	}
	s.prime(p)
	return nil
}

// prime installs the policy's windows into the identity package.
func (s *Service) prime(p Policy) {
	identity.SetSessionWindows(identity.Windows{
		Idle:     p.IdleTimeout,
		Absolute: p.AbsoluteTimeout,
	})
}

// validate enforces the window bounds and the absolute >= idle invariant.
func validate(p UpdateParams) error {
	if p.IdleTimeout < MinIdleTimeout || p.IdleTimeout > MaxIdleTimeout {
		return fmt.Errorf("%w: idle timeout must be between %s and %s",
			ErrInvalidParams, MinIdleTimeout, MaxIdleTimeout)
	}
	if p.AbsoluteTimeout < MinAbsoluteTimeout || p.AbsoluteTimeout > MaxAbsoluteTimeout {
		return fmt.Errorf("%w: absolute timeout must be between %s and %s",
			ErrInvalidParams, MinAbsoluteTimeout, MaxAbsoluteTimeout)
	}
	if p.AbsoluteTimeout < p.IdleTimeout {
		return fmt.Errorf("%w: absolute timeout cannot be shorter than idle timeout",
			ErrInvalidParams)
	}
	return nil
}
