package credprotect

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// restriction is one restriction that applies to a secret on an identity.
type restriction struct {
	id   uuid.UUID
	kind string
}

// state is everything that decides a secret's mode on an identity.
type state struct {
	applies   []restriction // every applicable restriction: unlifted blocks, pauses, cooldowns, allowances
	paused    bool
	blocked   bool // an unlifted block applies
	cooldown  bool
	allowance bool
	requested bool // a verification request is pending on this identity
	verified  bool // the secret has been verified on this identity
}

func (st state) mode() Mode {
	switch {
	case st.paused:
		return ModePaused
	case st.blocked && !st.requested:
		return ModeBlocked
	case st.blocked, !st.verified:
		return ModeVerifying
	}
	return ModeActive
}

// ids returns the applicable restriction ids, sorted, for a snapshot.
func (st state) ids() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(st.applies))
	for _, r := range st.applies {
		out = append(out, r.id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// blockIDs returns the applicable block ids: what a recovery would lift.
func (st state) blockIDs() []uuid.UUID {
	var out []uuid.UUID
	for _, r := range st.applies {
		if r.kind == "block" {
			out = append(out, r.id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// aliasArrays turns a secret's aliases into parallel arrays for SQL.
func aliasArrays(s Secret) ([]string, [][]byte) {
	keys := make([]string, len(s.Aliases))
	ids := make([][]byte, len(s.Aliases))
	for i, a := range s.Aliases {
		keys[i] = a.KeyID
		id := a.ID
		ids[i] = id[:]
	}
	return keys, ids
}

// matchSecret is the SQL condition that a row's secret columns, prefixed by
// p, are this secret: kind $2, aliases $3 and $4.
func matchSecret(p string) string {
	return fmt.Sprintf(`(%[1]ssecret_kind = $2 AND EXISTS (
		SELECT 1 FROM unnest($3::text[], $4::bytea[]) AS a(key_id, id)
		 WHERE a.key_id = %[1]ssecret_key_id AND a.id = %[1]ssecret_id))`, p)
}

// readState reads a secret's state on an identity at now. The caller holds
// the username's lock (spec C-04, C-05).
func readState(ctx context.Context, tx pgx.Tx, identity uuid.UUID, secret Secret, now time.Time) (state, error) {
	keys, ids := aliasArrays(secret)
	var st state
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE above(id) AS (
			SELECT $1::uuid
			UNION
			SELECT e.parent_id FROM credprotect_identity_edges e JOIN above a ON e.child_id = a.id
		),
		lifted AS (
			SELECT unnest(lifted) AS id FROM credprotect_recoveries WHERE identity_id = $1
		)
		SELECT r.id, r.kind
		  FROM credprotect_restrictions r
		 WHERE r.identity_id IN (SELECT id FROM above)
		   AND (r.secret_kind IS NULL OR `+matchSecret("r.")+`)
		   AND NOT (r.kind = 'pause' AND r.ended_at IS NOT NULL)
		   AND NOT (r.kind = 'cooldown' AND r.expires_at <= $5)
		   AND NOT (r.kind = 'block' AND r.id IN (SELECT id FROM lifted))`,
		identity, string(secret.Kind), keys, ids, now)
	if err != nil {
		return state{}, fmt.Errorf("credprotect: read restrictions: %w", err)
	}
	for rows.Next() {
		var r restriction
		if err := rows.Scan(&r.id, &r.kind); err != nil {
			rows.Close()
			return state{}, fmt.Errorf("credprotect: read restrictions: %w", err)
		}
		st.applies = append(st.applies, r)
		switch r.kind {
		case "pause":
			st.paused = true
		case "block":
			st.blocked = true
		case "cooldown":
			st.cooldown = true
		case "allowance_used":
			st.allowance = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return state{}, fmt.Errorf("credprotect: read restrictions: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM credprotect_verification_requests v
		                WHERE v.identity_id = $1 AND v.ended_at IS NULL AND `+matchSecret("v.")+`),
		       EXISTS (SELECT 1 FROM credprotect_verified_secrets v
		                WHERE v.identity_id = $1 AND `+matchSecret("v.")+`)`,
		identity, string(secret.Kind), keys, ids).Scan(&st.requested, &st.verified); err != nil {
		return state{}, fmt.Errorf("credprotect: read verification state: %w", err)
	}
	return st, nil
}

// Status is a secret's mode on an identity, and the bound on its
// transmissions: K, plus o overridden submissions not yet known to have
// ended.
type Status struct {
	Mode Mode
	K    int
	O    int
}

// Status reads a secret's mode on an identity now.
func (s *Store) Status(ctx context.Context, identity uuid.UUID, secret Secret) (Status, error) {
	if err := secret.valid(); err != nil {
		return Status{}, err
	}
	var out Status
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockIdentity(ctx, tx, identity); err != nil {
			return err
		}
		st, err := readState(ctx, tx, identity, secret, s.clock.Now())
		if err != nil {
			return err
		}
		o, err := overridesOutstanding(ctx, tx, identity)
		if err != nil {
			return err
		}
		out = Status{Mode: st.mode(), K: K, O: o}
		return nil
	})
	return out, err
}

func overridesOutstanding(ctx context.Context, tx pgx.Tx, identity uuid.UUID) (int, error) {
	var o int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM credprotect_submissions
		 WHERE identity_id = $1 AND overridden_at IS NOT NULL AND ended_at IS NULL`,
		identity).Scan(&o); err != nil {
		return 0, fmt.Errorf("credprotect: count overrides: %w", err)
	}
	return o, nil
}
