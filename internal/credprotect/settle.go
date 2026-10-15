package credprotect

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Result is what settling did.
type Result struct {
	// Duplicate: this outcome was already recorded; nothing changed.
	Duplicate bool
	// Late: recorded after the deadline, or after expiry recorded unknown.
	// A late outcome never has permissive effects.
	Late bool
	// Released: the submission's slot, or its count in o, was released.
	Released bool
	// Blocks are the blocks this outcome created.
	Blocks []uuid.UUID
	// Recovery is the recovery record written on an exact match.
	Recovery uuid.UUID
}

// Settle records the owner's outcome for a submission and applies its
// effects (spec C-08 to C-10): record, release the slot, change protection,
// each conditional.
func (s *Store) Settle(ctx context.Context, id uuid.UUID, outcome Outcome) (Result, error) {
	if !outcome.valid() {
		return Result{}, fmt.Errorf("%w: outcome %q", ErrInvalid, outcome)
	}
	var res Result
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := lockSubmission(ctx, tx, id)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		switch {
		case r.outcome == nil:
			res.Late = !now.Before(r.deadline)
			if _, err := tx.Exec(ctx, `
				UPDATE credprotect_submissions
				   SET outcome = $2, outcome_by = 'owner', outcome_at = $3, late = $4
				 WHERE id = $1 AND outcome IS NULL`, id, string(outcome), now, res.Late); err != nil {
				return fmt.Errorf("credprotect: record outcome: %w", err)
			}
		case *r.outcome == string(outcome) && *r.outcomeBy == "owner":
			res.Duplicate = true
			return nil
		case *r.outcome == string(OutcomeUnknown) && *r.outcomeBy == "expiry" && r.lateOutcome == nil:
			// The owner's real outcome after expiry recorded unknown: kept
			// once, as late (spec C-08).
			res.Late = true
			if _, err := tx.Exec(ctx, `
				UPDATE credprotect_submissions SET late_outcome = $2, late_outcome_at = $3
				 WHERE id = $1 AND late_outcome IS NULL`, id, string(outcome), now); err != nil {
				return fmt.Errorf("credprotect: record late outcome: %w", err)
			}
		case r.lateOutcome != nil && *r.lateOutcome == string(outcome):
			res.Duplicate = true
			return nil
		default:
			slog.WarnContext(ctx, "credprotect: conflicting outcome refused",
				"submission", id, "recorded", *r.outcome, "refused", string(outcome))
			return ErrOutcomeConflict
		}
		// The owner reported, so the attempt has ended: release the slot,
		// and stop counting it in o (spec C-08).
		if !r.ended {
			if _, err := tx.Exec(ctx, `
				UPDATE credprotect_submissions SET slot_held = false, ended_at = $2 WHERE id = $1`,
				id, now); err != nil {
				return fmt.Errorf("credprotect: release slot: %w", err)
			}
			res.Released = true
		}
		return s.applyEffects(ctx, tx, r, outcome, res.Late, now, &res)
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// applyEffects changes protection for an outcome (spec C-09, C-10).
// Restrictive effects always apply. Permissive effects apply only on an
// exact match.
func (s *Store) applyEffects(ctx context.Context, tx pgx.Tx, r submissionRow, outcome Outcome, late bool,
	now time.Time, res *Result) error {
	if outcome.restrictive() {
		var secret *Secret
		if outcome != OutcomeAmbiguous {
			secret = &r.secret
		}
		b, err := addRestriction(ctx, tx, r.identity, "block", secret, string(outcome), r.id, now, nil)
		if err != nil {
			return err
		}
		res.Blocks = append(res.Blocks, b)
		if r.kind == KindVerification {
			until := now.Add(Cooldown)
			if _, err := addRestriction(ctx, tx, r.identity, "cooldown", &r.secret, string(outcome), r.id, now,
				&until); err != nil {
				return err
			}
			if _, err := addRestriction(ctx, tx, r.identity, "allowance_used", &r.secret, string(outcome), r.id,
				now, nil); err != nil {
				return err
			}
			if err := endRequest(ctx, tx, r.identity, r.secret, r.id, now); err != nil {
				return err
			}
		}
		return nil
	}
	if outcome != OutcomeVerified || r.kind != KindVerification || late {
		return nil // evidence only
	}
	st, err := readState(ctx, tx, r.identity, r.secret, now)
	if err != nil {
		return err
	}
	// A pause needs no separate check: Reserve refuses while paused, so no
	// snapshot holds one, and a pause that began since makes the sets differ.
	if !sameIDs(st.ids(), r.snapshot) {
		return nil // not an exact match: evidence only, the request stays
	}
	rec := newID()
	lifted := st.blockIDs()
	if lifted == nil {
		lifted = []uuid.UUID{}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_recoveries (id, identity_id, submission_id, lifted, created_at)
		VALUES ($1, $2, $3, $4, $5)`, rec, r.identity, r.id, lifted, now); err != nil {
		return fmt.Errorf("credprotect: record recovery: %w", err)
	}
	p := r.secret.primary()
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_verified_secrets (identity_id, secret_kind, secret_key_id, secret_id, recovery_id, verified_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT DO NOTHING`, r.identity, string(r.secret.Kind), p.KeyID, p.ID[:], rec, now); err != nil {
		return fmt.Errorf("credprotect: record verified secret: %w", err)
	}
	if err := endRequest(ctx, tx, r.identity, r.secret, r.id, now); err != nil {
		return err
	}
	res.Recovery = rec
	return nil
}

// sameIDs compares two sorted id sets.
func sameIDs(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[uuid.UUID]bool, len(a))
	for _, x := range a {
		seen[x] = true
	}
	for _, y := range b {
		if !seen[y] {
			return false
		}
	}
	return true
}

// addRestriction records a restriction on an identity. A nil secret means
// every secret.
func addRestriction(ctx context.Context, tx pgx.Tx, identity uuid.UUID, kind string, secret *Secret,
	reason string, submission uuid.UUID, now time.Time, expires *time.Time) (uuid.UUID, error) {
	id := newID()
	var sk, kid *string
	var sid []byte
	if secret != nil { // pragma: allowlist secret
		p := secret.primary()
		k := string(secret.Kind)
		sk, kid, sid = &k, &p.KeyID, p.ID[:]
	}
	var sub *uuid.UUID
	if submission != uuid.Nil {
		sub = &submission
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_restrictions
		       (id, identity_id, kind, secret_kind, secret_key_id, secret_id, reason, submission_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, identity, kind, sk, kid, sid, reason, sub, now, expires); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: record %s: %w", kind, err)
	}
	return id, nil
}

// endRequest ends a pending verification request for a secret.
func endRequest(ctx context.Context, tx pgx.Tx, identity uuid.UUID, secret Secret, submission uuid.UUID,
	now time.Time) error {
	keys, ids := aliasArrays(secret)
	if _, err := tx.Exec(ctx, `
		UPDATE credprotect_verification_requests v SET ended_at = $5, ended_by_submission = $6
		 WHERE v.identity_id = $1 AND v.ended_at IS NULL AND `+matchSecret("v."),
		identity, string(secret.Kind), keys, ids, now, submission); err != nil {
		return fmt.Errorf("credprotect: end verification request: %w", err)
	}
	return nil
}

// Expire records unknown for every submission past its deadline with no
// outcome, and applies unknown's restrictive effects. It keeps their slots:
// the attempt may still be running (spec C-08). It returns how many it
// expired.
func (s *Store) Expire(ctx context.Context) (int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("credprotect: begin: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT id FROM credprotect_submissions WHERE outcome IS NULL AND deadline <= $1`, s.clock.Now())
	if err != nil {
		_ = tx.Rollback(ctx)
		return 0, fmt.Errorf("credprotect: find expired: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	_ = tx.Rollback(ctx)
	if err != nil {
		return 0, fmt.Errorf("credprotect: find expired: %w", err)
	}
	n := 0
	for _, id := range ids {
		expired, err := s.expireOne(ctx, id)
		if err != nil {
			return n, err
		}
		if expired {
			n++
		}
	}
	return n, nil
}

// expireOne records unknown for one submission if it still has no outcome
// and its deadline has passed. The conditional update decides, under the
// username's lock: a submission settled since Expire's scan is left alone,
// and gets no second set of effects.
func (s *Store) expireOne(ctx context.Context, id uuid.UUID) (bool, error) {
	expired := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := lockSubmission(ctx, tx, id)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		tag, err := tx.Exec(ctx, `
			UPDATE credprotect_submissions SET outcome = 'unknown', outcome_by = 'expiry', outcome_at = $2
			 WHERE id = $1 AND outcome IS NULL AND deadline <= $2`, id, now)
		if err != nil {
			return fmt.Errorf("credprotect: record unknown: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		expired = true
		var res Result
		return s.applyEffects(ctx, tx, r, OutcomeUnknown, true, now, &res)
	})
	return expired, err
}

// ReleaseIfTerminated releases a submission's slot, and its count in o,
// when its owner ran on this machine and that process no longer exists
// (spec C-08). If no outcome was recorded, it records unknown first, with
// its restrictive effects, so the slot is never freed while a possible
// rejection is unrecorded. It returns ErrNotTerminated when it cannot
// verify that the owner has ended.
func (s *Store) ReleaseIfTerminated(ctx context.Context, id uuid.UUID) (Result, error) {
	var res Result
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := lockSubmission(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.ended {
			return nil
		}
		if r.ownerMachine != s.procs.Machine() {
			return fmt.Errorf("%w: the owner ran on another machine", ErrNotTerminated)
		}
		alive, err := s.procs.Alive(r.ownerPID, r.ownerStart)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrNotTerminated, err)
		}
		if alive {
			return fmt.Errorf("%w: the owner is still running", ErrNotTerminated)
		}
		now := s.clock.Now()
		if r.outcome == nil {
			if _, err := tx.Exec(ctx, `
				UPDATE credprotect_submissions SET outcome = 'unknown', outcome_by = 'termination', outcome_at = $2
				 WHERE id = $1 AND outcome IS NULL`, id, now); err != nil {
				return fmt.Errorf("credprotect: record unknown: %w", err)
			}
			if err := s.applyEffects(ctx, tx, r, OutcomeUnknown, true, now, &res); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE credprotect_submissions SET slot_held = false, ended_at = $2 WHERE id = $1`, id, now); err != nil {
			return fmt.Errorf("credprotect: release slot: %w", err)
		}
		res.Released = true
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// Override frees a submission's slot without knowing that its attempt has
// ended. It needs a reason and the operator's confirmation. The submission
// stays counted in o until its owner reports or is verified ended, so an
// identity never has more than K + o transmissions (spec C-08). The
// caller checks the credential:verify permission and audits the action.
func (s *Store) Override(ctx context.Context, id, actor uuid.UUID, reason string, confirmed bool) error {
	if reason == "" || !confirmed || actor == uuid.Nil {
		return ErrOverride
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := lockSubmission(ctx, tx, id)
		if err != nil {
			return err
		}
		if !r.slotHeld {
			return nil // already free: ended, or overridden
		}
		if _, err := tx.Exec(ctx, `
			UPDATE credprotect_submissions
			   SET slot_held = false, overridden_at = $2, override_by = $3, override_reason = $4
			 WHERE id = $1`, id, s.clock.Now(), actor, reason); err != nil {
			return fmt.Errorf("credprotect: override: %w", err)
		}
		return nil
	})
}
