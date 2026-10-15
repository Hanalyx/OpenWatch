package credprotect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Request asks to reserve one submission of a secret.
type Request struct {
	CredentialID uuid.UUID
	HostID       uuid.UUID
	Secret       Secret
	Kind         Kind
	// Stage is recorded for attribution only: "ssh", "sudo" and so on. The
	// restrictions are the same for every stage (spec C-03).
	Stage string
	Owner Owner
	// TTL is how long the reservation lasts before expiry records unknown.
	TTL time.Duration
}

// Submission is a reserved submission.
type Submission struct {
	ID       uuid.UUID
	Identity uuid.UUID
	Kind     Kind
	Deadline time.Time
	Snapshot []uuid.UUID
}

// refusal maps a mode to the error a reservation of kind gets, or nil when
// the mode allows it (spec C-06).
func refusal(st state, kind Kind) error {
	switch m := st.mode(); {
	case m == ModePaused:
		return ErrPaused
	case m == ModeBlocked:
		return ErrBlocked
	case kind == KindOrdinary && m == ModeVerifying:
		return ErrVerifying
	case kind == KindVerification && m == ModeActive:
		return ErrNotVerifying
	case kind == KindVerification && st.cooldown:
		return ErrCooldown
	case kind == KindVerification && st.allowance:
		return ErrAllowanceUsed
	}
	return nil
}

// Reserve reserves one submission before any network I/O (spec C-06). It
// is refused, reserving nothing, unless the secret's mode allows the kind
// and no other submission on the identity holds a slot. An error of any
// kind, including an unreachable store, means: send nothing.
func (s *Store) Reserve(ctx context.Context, r Request) (Submission, error) {
	if err := r.Secret.valid(); err != nil {
		return Submission{}, err
	}
	if r.Kind != KindOrdinary && r.Kind != KindVerification {
		return Submission{}, fmt.Errorf("%w: kind %q", ErrInvalid, r.Kind)
	}
	if r.TTL <= 0 || r.Stage == "" || !r.Owner.complete() {
		return Submission{}, fmt.Errorf("%w: a reservation needs a TTL, a stage and a complete owner", ErrInvalid)
	}
	var sub Submission
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, r.CredentialID)
		if err != nil {
			return err
		}
		identity, err := s.resolve(ctx, tx, r.CredentialID, r.HostID, username)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		st, err := readState(ctx, tx, identity, r.Secret, now)
		if err != nil {
			return err
		}
		if err := refusal(st, r.Kind); err != nil {
			return err
		}
		sub = Submission{ID: newID(), Identity: identity, Kind: r.Kind, Deadline: now.Add(r.TTL), Snapshot: st.ids()}
		var host *uuid.UUID
		if r.HostID != uuid.Nil {
			host = &r.HostID
		}
		p := r.Secret.primary()
		keys, ids := aliasArrays(r.Secret)
		_, err = tx.Exec(ctx, `
			INSERT INTO credprotect_submissions
			       (id, identity_id, credential_id, host_id, kind, stage, secret_kind, secret_key_id, secret_id,
			        alias_key_ids, alias_ids, owner_machine, owner_pid, owner_start, reserved_at, deadline, snapshot,
			        slot_held)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, true)`,
			sub.ID, identity, r.CredentialID, host, string(r.Kind), r.Stage, string(r.Secret.Kind), p.KeyID, p.ID[:],
			keys, ids, r.Owner.Machine, r.Owner.PID, r.Owner.Start, now, sub.Deadline, sub.Snapshot)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// K = 1 is the unique index uq_credprotect_submissions_slot:
			// another submission on this identity holds the slot.
			return ErrSlotBusy
		}
		if err != nil {
			return fmt.Errorf("credprotect: reserve: %w", err)
		}
		return nil
	})
	if err != nil {
		return Submission{}, err
	}
	return sub, nil
}

// Current is the credential as the caller read it just before the fence.
type Current struct {
	Active bool
	Secret Secret
}

// submissionRow is a submission as stored.
type submissionRow struct {
	id           uuid.UUID
	identity     uuid.UUID
	credentialID *uuid.UUID
	hostID       *uuid.UUID
	kind         Kind
	secret       Secret
	ownerMachine string
	ownerPID     int
	ownerStart   string
	deadline     time.Time
	snapshot     []uuid.UUID
	slotHeld     bool
	ended        bool
	overridden   bool
	outcome      *string
	outcomeBy    *string
	lateOutcome  *string
}

// lockSubmission takes the lock for a submission's username and reads the
// submission under it, row-locked.
func lockSubmission(ctx context.Context, tx pgx.Tx, id uuid.UUID) (submissionRow, error) {
	var identity uuid.UUID
	err := tx.QueryRow(ctx, `SELECT identity_id FROM credprotect_submissions WHERE id = $1`, id).Scan(&identity)
	if errors.Is(err, pgx.ErrNoRows) {
		return submissionRow{}, fmt.Errorf("%w: submission", ErrNotFound)
	}
	if err != nil {
		return submissionRow{}, fmt.Errorf("credprotect: read submission: %w", err)
	}
	if err := lockIdentity(ctx, tx, identity); err != nil {
		return submissionRow{}, err
	}
	var r submissionRow
	var secretKind string
	var keyIDs []string
	var ids [][]byte
	err = tx.QueryRow(ctx, `
		SELECT id, identity_id, credential_id, host_id, kind, secret_kind, alias_key_ids, alias_ids,
		       owner_machine, owner_pid, owner_start, deadline, snapshot, slot_held,
		       ended_at IS NOT NULL, overridden_at IS NOT NULL, outcome, outcome_by, late_outcome
		  FROM credprotect_submissions WHERE id = $1 FOR UPDATE`, id).Scan(
		&r.id, &r.identity, &r.credentialID, &r.hostID, &r.kind, &secretKind, &keyIDs, &ids,
		&r.ownerMachine, &r.ownerPID, &r.ownerStart, &r.deadline, &r.snapshot, &r.slotHeld,
		&r.ended, &r.overridden, &r.outcome, &r.outcomeBy, &r.lateOutcome)
	if err != nil {
		return submissionRow{}, fmt.Errorf("credprotect: read submission: %w", err)
	}
	if len(keyIDs) != len(ids) || len(ids) == 0 {
		return submissionRow{}, errors.New("credprotect: stored aliases are incomplete")
	}
	r.secret = Secret{Kind: SecretKind(secretKind)}
	for i := range ids {
		if len(ids[i]) != IDLen {
			return submissionRow{}, errors.New("credprotect: stored identifier has the wrong length")
		}
		var a Alias
		a.KeyID = keyIDs[i]
		copy(a.ID[:], ids[i])
		r.secret.Aliases = append(r.secret.Aliases, a)
	}
	return r, nil
}

// Fence runs immediately before the secret is handed to a transport (spec
// C-07). Any error means: send nothing.
func (s *Store) Fence(ctx context.Context, id uuid.UUID, cur Current) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := lockSubmission(ctx, tx, id)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		switch {
		case !r.slotHeld:
			return fmt.Errorf("%w: the submission no longer holds its slot", ErrFenceRefused)
		case !now.Before(r.deadline):
			return fmt.Errorf("%w: the reservation's deadline has passed", ErrFenceRefused)
		case !cur.Active:
			return fmt.Errorf("%w: the credential is not active", ErrFenceRefused)
		case cur.Secret.valid() != nil || !cur.Secret.Same(r.secret):
			return fmt.Errorf("%w: the credential's secret changed", ErrFenceRefused)
		case r.credentialID == nil:
			return fmt.Errorf("%w: the credential was deleted", ErrFenceRefused)
		}
		// The credential must still be for the account it was checked for. A
		// username edit since reserve would send the secret for another
		// account. Classification cannot move it meanwhile: it is refused
		// while this submission holds its slot or counts in o.
		username, err := credentialUsername(ctx, tx, *r.credentialID)
		if err != nil {
			return err
		}
		owner, err := identityUsername(ctx, tx, r.identity)
		if err != nil {
			return err
		}
		if username != owner {
			return fmt.Errorf("%w: the credential's username changed", ErrFenceRefused)
		}
		st, err := readState(ctx, tx, r.identity, r.secret, now)
		if err != nil {
			return err
		}
		if err := refusal(st, r.kind); err != nil {
			return fmt.Errorf("%w: %w", ErrFenceRefused, err)
		}
		return nil
	})
}
