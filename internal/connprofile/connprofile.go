// Package connprofile is the per-host "last known good" SSH connection
// memory shared by every path that talks to a managed host (the liveness
// privilege probe, OS discovery, OS intelligence collection, and the
// compliance scan).
//
// The problem it solves: without memory, each connection re-discovers how
// to reach the host. It offers the public key to a host that only takes a
// password (a failed publickey attempt that counts against MaxAuthTries
// and can trip fail2ban), and it runs `sudo -n` on a host known to need a
// sudo password (a wasted round-trip before the `sudo -S` retry). This
// package records what actually worked so callers lead with the
// known-good choice.
//
// It is a HINT, never a lock. Callers still attempt the other methods if
// the recorded one fails and overwrite the record when the working choice
// changes, so a stale hint self-heals on the next connection. Treat a
// missing/unknown value as "no preference — try the normal order."
package connprofile

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SSHAuthMethod is the SSH auth method that last authenticated.
type SSHAuthMethod string

const (
	AuthUnknown  SSHAuthMethod = ""
	AuthKey      SSHAuthMethod = "key"
	AuthPassword SSHAuthMethod = "password"
)

// SudoMode is the privilege-escalation mode that last reached root.
type SudoMode string

const (
	SudoUnknown  SudoMode = ""
	SudoRoot     SudoMode = "root"     // login user is already root; no sudo
	SudoNopasswd SudoMode = "nopasswd" // `sudo -n` works (NOPASSWD sudoers)
	SudoPassword SudoMode = "password" // `sudo -S` with the credential password works
)

// Profile is a host's recorded connection preferences. Zero-valued fields
// (AuthUnknown / SudoUnknown) mean "not yet observed — no preference."
type Profile struct {
	SSHAuthMethod SSHAuthMethod
	SudoMode      SudoMode
}

// Store reads and writes host connection profiles.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Get returns the recorded profile for a host. A host with no row yet
// returns a zero Profile (both dimensions unknown) and a nil error — an
// absent hint is not an error, it just means "no preference."
func (s *Store) Get(ctx context.Context, hostID uuid.UUID) (Profile, error) {
	var auth, sudo *string
	err := s.pool.QueryRow(ctx,
		`SELECT ssh_auth_method, sudo_mode FROM host_connection_profile WHERE host_id = $1`,
		hostID,
	).Scan(&auth, &sudo)
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, nil
	}
	if err != nil {
		return Profile{}, fmt.Errorf("connprofile: get %s: %w", hostID, err)
	}
	p := Profile{}
	if auth != nil {
		p.SSHAuthMethod = SSHAuthMethod(*auth)
	}
	if sudo != nil {
		p.SudoMode = SudoMode(*sudo)
	}
	return p, nil
}

// RecordSSHAuth persists the SSH auth method that just worked, leaving the
// sudo_mode column untouched. A no-op for AuthUnknown so callers can call
// it unconditionally. Recording failures are non-fatal to the caller's
// real work (a connection succeeded) — the caller logs and continues.
func (s *Store) RecordSSHAuth(ctx context.Context, hostID uuid.UUID, m SSHAuthMethod) error {
	if m == AuthUnknown {
		return nil
	}
	return s.upsert(ctx, hostID, ptr(string(m)), nil)
}

// RecordSudoMode persists the privilege mode that just reached root,
// leaving the ssh_auth_method column untouched. A no-op for SudoUnknown.
func (s *Store) RecordSudoMode(ctx context.Context, hostID uuid.UUID, m SudoMode) error {
	if m == SudoUnknown {
		return nil
	}
	return s.upsert(ctx, hostID, nil, ptr(string(m)))
}

// upsert writes the provided columns, preserving any column passed as nil
// via COALESCE so a single-dimension record never clobbers the other.
func (s *Store) upsert(ctx context.Context, hostID uuid.UUID, auth, sudo *string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_connection_profile (host_id, ssh_auth_method, sudo_mode, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (host_id) DO UPDATE SET
			ssh_auth_method = COALESCE(EXCLUDED.ssh_auth_method, host_connection_profile.ssh_auth_method),
			sudo_mode       = COALESCE(EXCLUDED.sudo_mode, host_connection_profile.sudo_mode),
			updated_at      = now()`,
		hostID, auth, sudo,
	)
	if err != nil {
		return fmt.Errorf("connprofile: upsert %s: %w", hostID, err)
	}
	return nil
}

func ptr(s string) *string { return &s }
