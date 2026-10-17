package credprotect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	Class    Class
	Kind     Kind
	Deadline time.Time
	Snapshot []uuid.UUID
}

// refusal maps a state to the error a reservation of kind gets, or nil when
// it allows it (spec C-05, C-06).
func refusal(st state, kind Kind) error {
	switch m := st.mode(); {
	case m == ModePaused:
		return ErrPaused
	case st.stuck:
		return ErrLateralBlock
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

// conflict is the SQL condition, over a submission s for the same username
// holding a slot, that it may reach the same account as a new attempt for
// the target in $2 (scope), $3 (class) and $4 (host) (spec C-06):
//
//   - a directory attempt conflicts with its own directory and with every
//     unconfirmed attempt;
//   - an unconfirmed attempt conflicts with every unconfirmed and every
//     directory attempt, and with a confirmed-local attempt on its host;
//   - a confirmed-local attempt conflicts with its own host record and with
//     an unconfirmed attempt on its host.
const conflict = `(
	($3 = 'directory' AND (s.identity_id = $2 OR s.class = 'unconfirmed'))
 OR ($3 = 'unconfirmed' AND (s.class IN ('unconfirmed', 'directory')
                             OR (s.class = 'confirmed_local' AND s.host_id = $4)))
 OR ($3 = 'confirmed_local' AND (s.identity_id = $2 OR (s.class = 'unconfirmed' AND s.host_id = $4))))`

// Reserve reserves one submission before any network I/O (spec C-06). It
// is refused, reserving nothing, unless the secret's mode for the attempt's
// target allows the kind and no attempt that may reach the same account
// holds a slot. An error of any kind, including an unreachable store,
// means: send nothing.
func (s *Store) Reserve(ctx context.Context, r Request) (Submission, error) {
	if err := r.Secret.valid(); err != nil {
		return Submission{}, err
	}
	if r.Kind != KindOrdinary && r.Kind != KindVerification {
		return Submission{}, fmt.Errorf("%w: kind %q", ErrInvalid, r.Kind)
	}
	if r.TTL <= 0 || r.Stage == "" || !r.Owner.complete() || r.HostID == uuid.Nil {
		return Submission{}, fmt.Errorf("%w: a reservation needs a host, a TTL, a stage and a complete owner",
			ErrInvalid)
	}
	var sub Submission
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, r.CredentialID)
		if err != nil {
			return err
		}
		if err := checkKeyring(ctx, tx, r.Secret); err != nil {
			return err
		}
		t, err := s.resolveTarget(ctx, tx, r.CredentialID, r.HostID, username)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		if t.class == ClassDirectory {
			if err := checkBinding(ctx, tx, t); err != nil {
				return err
			}
		}
		st, err := readState(ctx, tx, t, r.Secret, now)
		if err != nil {
			return err
		}
		if err := refusal(st, r.Kind); err != nil {
			return err
		}
		var busy bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM credprotect_submissions s
			                WHERE s.username = $1 AND s.slot_held AND `+conflict+`)`,
			username, t.scope, string(t.class), t.host).Scan(&busy); err != nil {
			return fmt.Errorf("credprotect: check slots: %w", err)
		}
		if busy {
			return ErrSlotBusy
		}
		sub = Submission{ID: newID(), Identity: t.scope, Class: t.class, Kind: r.Kind, Deadline: now.Add(r.TTL),
			Snapshot: st.ids()}
		keys, ids := aliasArrays(r.Secret)
		_, err = tx.Exec(ctx, `
			INSERT INTO credprotect_submissions
			       (id, identity_id, class, username, credential_id, host_id, kind, stage, secret_kind,
			        alias_key_ids, alias_ids, owner_machine, owner_pid, owner_start, reserved_at, deadline, snapshot,
			        slot_held)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, true)`,
			sub.ID, t.scope, string(t.class), username, r.CredentialID, r.HostID, string(r.Kind), r.Stage,
			string(r.Secret.Kind), keys, ids, r.Owner.Machine, r.Owner.PID, r.Owner.Start, now, sub.Deadline,
			sub.Snapshot)
		// The conflict check above already covers the scope's own slot under
		// the username's lock; uq_credprotect_submissions_slot backs it as a
		// database invariant, and if it ever fires the error refuses too.
		if err != nil {
			return fmt.Errorf("credprotect: reserve: %w", err)
		}
		if t.class == ClassDirectory {
			if _, err := tx.Exec(ctx, `
				INSERT INTO credprotect_directory_bindings (host_id, username, directory_id, created_at)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT DO NOTHING`, t.host, username, t.scope, now); err != nil {
				return fmt.Errorf("credprotect: record binding intent: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return Submission{}, err
	}
	return sub, nil
}

// checkBinding refuses a directory attempt on a host account that is
// confirmed local, or that another directory already recorded binding
// intent for: one directory per host account (spec C-14).
func checkBinding(ctx context.Context, tx pgx.Tx, t target) error {
	if t.hostRecord != uuid.Nil {
		r, err := readIdentity(ctx, tx, t.hostRecord)
		if err != nil {
			return err
		}
		if r.confirmed {
			return fmt.Errorf("%w: the host account is confirmed local", ErrBinding)
		}
	}
	var bound uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT directory_id FROM credprotect_directory_bindings WHERE host_id = $1 AND username = $2`,
		t.host, t.username).Scan(&bound)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("credprotect: read binding intent: %w", err)
	}
	if bound != t.scope {
		return fmt.Errorf("%w: another directory identity is bound to this host account", ErrBinding)
	}
	return nil
}

// Reader runs one query on the fence's transaction. It is all of the
// transaction a read callback gets: a callback reads, and cannot commit,
// roll back or start another transaction.
type Reader interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Current is the credential as Fence's read callback found it, under the
// fence's lock on the credential row.
type Current struct {
	Active bool
	Secret Secret
}

// submissionRow is a submission as stored.
type submissionRow struct {
	id           uuid.UUID
	identity     uuid.UUID
	class        Class
	username     string
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
	var username string
	err := tx.QueryRow(ctx, `SELECT username FROM credprotect_submissions WHERE id = $1`, id).Scan(&username)
	if errors.Is(err, pgx.ErrNoRows) {
		return submissionRow{}, fmt.Errorf("%w: submission", ErrNotFound)
	}
	if err != nil {
		return submissionRow{}, fmt.Errorf("credprotect: read submission: %w", err)
	}
	if err := lockUsername(ctx, tx, username); err != nil {
		return submissionRow{}, err
	}
	var r submissionRow
	var secretKind string
	var keyIDs []string
	var ids [][]byte
	err = tx.QueryRow(ctx, `
		SELECT id, identity_id, class, username, credential_id, host_id, kind, secret_kind, alias_key_ids, alias_ids,
		       owner_machine, owner_pid, owner_start, deadline, snapshot, slot_held,
		       ended_at IS NOT NULL, overridden_at IS NOT NULL, outcome, outcome_by, late_outcome
		  FROM credprotect_submissions WHERE id = $1 FOR UPDATE`, id).Scan(
		&r.id, &r.identity, &r.class, &r.username, &r.credentialID, &r.hostID, &r.kind, &secretKind, &keyIDs, &ids,
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

// targetOf is a submission's recorded target, with its host record and the
// lateral identities read as they are now: the attempt keeps its account
// and coordination scope, and is re-evaluated against current protection
// (spec C-07, C-10).
func (s *Store) targetOf(ctx context.Context, tx pgx.Tx, r submissionRow) (target, error) {
	root, err := ensureRoot(ctx, tx, r.username, s.clock.Now())
	if err != nil {
		return target{}, err
	}
	t := target{class: r.class, scope: r.identity, root: root, username: r.username}
	if r.hostID != nil {
		t.host = *r.hostID
		if t.hostRecord, _, err = hostRecord(ctx, tx, t.host, r.username); err != nil {
			return target{}, err
		}
	}
	return t, nil
}

// Fence runs immediately before the secret is handed to a transport (spec
// C-07). read reads the credential again from its store and identifies the
// secret it holds now. Fence calls it while holding the credential's row
// FOR SHARE, after the username's lock, so an edit committed before the
// read is seen, and one not yet committed waits until the fence has
// passed. An edit after that is the window the contract accepts between
// the fence and the transmission. Any error means: send nothing.
//
// Lock order: the username, then the credential row, then the keyring. A
// credential edit that consults protection must take the username's lock
// before it writes the row. read gets the fence's own transaction as a
// Reader, so the fence never asks the pool for a second connection: fences
// that each held one and waited for another would exhaust any pool.
func (s *Store) Fence(ctx context.Context, id uuid.UUID, read func(context.Context, Reader) (Current, error)) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := lockSubmission(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.credentialID == nil {
			return fmt.Errorf("%w: the credential was deleted", ErrFenceRefused)
		}
		var username string
		var active bool
		err = tx.QueryRow(ctx, `SELECT username, is_active FROM credentials WHERE id = $1 FOR SHARE`,
			*r.credentialID).Scan(&username, &active)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: the credential was deleted", ErrFenceRefused)
		}
		if err != nil {
			return fmt.Errorf("credprotect: read credential: %w", err)
		}
		cur, err := read(ctx, tx)
		if err != nil {
			return fmt.Errorf("%w: read the credential: %w", ErrFenceRefused, err)
		}
		if cur.Active {
			if err := checkKeyring(ctx, tx, cur.Secret); err != nil {
				return err
			}
		}
		now := s.clock.Now()
		switch {
		case !r.slotHeld:
			return fmt.Errorf("%w: the submission no longer holds its slot", ErrFenceRefused)
		case !now.Before(r.deadline):
			return fmt.Errorf("%w: the reservation's deadline has passed", ErrFenceRefused)
		case !active || !cur.Active:
			return fmt.Errorf("%w: the credential is not active", ErrFenceRefused)
		case cur.Secret.valid() != nil || !cur.Secret.Same(r.secret):
			return fmt.Errorf("%w: the credential's secret changed", ErrFenceRefused)
		case normalizeUsername(username) != r.username:
			// Binding changes cannot happen meanwhile: they wait while this
			// submission holds its slot.
			return fmt.Errorf("%w: the credential's username changed", ErrFenceRefused)
		}
		t, err := s.targetOf(ctx, tx, r)
		if err != nil {
			return err
		}
		st, err := readState(ctx, tx, t, r.secret, now)
		if err != nil {
			return err
		}
		if err := refusal(st, r.kind); err != nil {
			return fmt.Errorf("%w: %w", ErrFenceRefused, err)
		}
		// A restriction that applies now and was not in the snapshot refuses
		// the transmission, whatever the mode: a verification pending on an
		// earlier request stays VERIFYING after a new block, but its secret
		// must not be sent past that block (spec C-07).
		snap := make(map[uuid.UUID]bool, len(r.snapshot))
		for _, id := range r.snapshot {
			snap[id] = true
		}
		for _, x := range st.applies {
			if !snap[x.id] {
				return fmt.Errorf("%w: a %s applies that was not in force at reserve", ErrFenceRefused, x.kind)
			}
		}
		return nil
	})
}
