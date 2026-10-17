package credprotect

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The operator actions. Each caller checks its permission and audits the
// action; that, the API and notifications are slice 7.

// Pause stops every submission that consults this identity, through
// lineage or laterally, until the pause is ended on the same identity
// (spec C-04). A candidate or retired directory identity takes no pause.
func (s *Store) Pause(ctx context.Context, identity uuid.UUID, reason string) (uuid.UUID, error) {
	if reason == "" {
		return uuid.Nil, fmt.Errorf("%w: a pause needs a reason", ErrInvalid)
	}
	var id uuid.UUID
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := lockIdentity(ctx, tx, identity)
		if err != nil {
			return err
		}
		if err := refuseUnusable(r); err != nil {
			return err
		}
		id, err = addRestriction(ctx, tx, identity, "pause", nil, reason, uuid.Nil, s.clock.Now(), nil)
		return err
	})
	return id, err
}

// EndPause ends the pauses set on this identity. A pause set on another
// identity, the root included, is not ended here (spec C-11). It returns
// how many pauses it ended.
func (s *Store) EndPause(ctx context.Context, identity uuid.UUID) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := lockIdentity(ctx, tx, identity); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE credprotect_restrictions SET ended_at = $2
			 WHERE identity_id = $1 AND kind = 'pause' AND ended_at IS NULL`, identity, s.clock.Now())
		if err != nil {
			return fmt.Errorf("credprotect: end pause: %w", err)
		}
		n = int(tag.RowsAffected())
		return nil
	})
	return n, err
}

// RequestVerification asks to verify one blocked secret for the attempts
// credentialID makes on host (spec C-11). The request is recorded on their
// scope; while it is pending, the secret's mode there is VERIFYING and only
// a verification reservation is allowed. A repeat while one is pending
// changes nothing and returns the pending request. It is refused while a
// cooldown or a used allowance applies to the secret, while a block applies
// that this target's verification cannot lift, and when no block applies.
func (s *Store) RequestVerification(ctx context.Context, credentialID, hostID uuid.UUID, secret Secret,
	actor uuid.UUID) (uuid.UUID, error) {
	if err := secret.valid(); err != nil {
		return uuid.Nil, err
	}
	if actor == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: a request needs the requesting operator", ErrInvalid)
	}
	var id uuid.UUID
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		if err := checkKeyring(ctx, tx, secret); err != nil {
			return err
		}
		t, err := s.resolveTarget(ctx, tx, credentialID, hostID, username)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		st, err := readState(ctx, tx, t, secret, now)
		if err != nil {
			return err
		}
		keys, ids := aliasArrays(secret)
		err = tx.QueryRow(ctx, `
			SELECT v.id FROM credprotect_verification_requests v
			 WHERE v.identity_id = $1 AND v.ended_at IS NULL AND `+matchSecret("v."),
			t.scope, string(secret.Kind), keys, ids).Scan(&id)
		if err == nil {
			return nil // already pending
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("credprotect: read verification request: %w", err)
		}
		switch {
		case st.cooldown:
			return ErrCooldown
		case st.allowance:
			return ErrAllowanceUsed
		case st.stuck:
			return ErrLateralBlock
		case !st.blocked:
			return ErrNotVerifying
		}
		id = newID()
		if _, err := tx.Exec(ctx, `
			INSERT INTO credprotect_verification_requests
			       (id, identity_id, secret_kind, alias_key_ids, alias_ids, requested_by, requested_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			id, t.scope, string(secret.Kind), keys, ids, actor, now); err != nil {
			return fmt.Errorf("credprotect: record verification request: %w", err)
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}
