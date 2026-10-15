package credprotect

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// restriction is one restriction that applies to a secret for a target.
type restriction struct {
	id       uuid.UUID
	kind     string
	identity uuid.UUID
}

// state is everything that decides a secret's mode for a target.
type state struct {
	applies   []restriction // every applicable restriction: unlifted blocks, pauses, cooldowns, allowances
	paused    bool
	blocked   bool // an unlifted block applies that this target's verification can lift
	stuck     bool // an unlifted block applies that it cannot: one living on a directory it is not bound to
	cooldown  bool
	allowance bool
	requested bool // a verification request is pending on the target's scope
	verified  bool // the secret has been verified on the target's scope
}

func (st state) mode() Mode {
	switch {
	case st.paused:
		return ModePaused
	case st.stuck:
		return ModeBlocked
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
	return sortedIDs(out)
}

// blocksOn returns the applicable block ids living on the identities for
// which on reports true.
func (st state) blocksOn(on func(uuid.UUID) bool) []uuid.UUID {
	out := []uuid.UUID{}
	for _, r := range st.applies {
		if r.kind == "block" && on(r.identity) {
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

// matchSecret is the SQL condition that a row's secret, prefixed by p, is
// this secret: kind $2, and the row's aliases overlap the aliases in $3 and
// $4 (spec C-03).
func matchSecret(p string) string {
	return fmt.Sprintf(`(%[1]ssecret_kind = $2 AND EXISTS (
		SELECT 1 FROM unnest(%[1]salias_key_ids, %[1]salias_ids) AS r(key_id, id)
		  JOIN unnest($3::text[], $4::bytea[]) AS a(key_id, id) ON a.key_id = r.key_id AND a.id = r.id))`, p)
}

// laterals returns the identities whose restrictions a target must respect
// although they are not in its lineage (spec C-04): its host's record, and
// for an unconfirmed attempt every usable directory for its username.
func laterals(ctx context.Context, tx pgx.Tx, t target) ([]uuid.UUID, error) {
	var out []uuid.UUID
	if t.hostRecord != uuid.Nil && t.hostRecord != t.scope {
		out = append(out, t.hostRecord)
	}
	if t.class == ClassUnconfirmed {
		dirs, err := usableDirectories(ctx, tx, t.username)
		if err != nil {
			return nil, err
		}
		out = append(out, dirs...)
	}
	return out, nil
}

// readState reads a secret's state for a target at now. The caller holds
// the username's lock (spec C-04, C-05).
//
// The target consults its lineage (its scope and the root) and its lateral
// identities. A block in its lineage is lifted by a recovery on its scope
// that names it. A lateral block is lifted only by a recovery on the
// identity it lives on. Of the lateral blocks, the host record's can be
// lifted by this target's own verification (a host-plus-scope recovery); a
// directory's cannot.
func readState(ctx context.Context, tx pgx.Tx, t target, secret Secret, now time.Time) (state, error) {
	keys, ids := aliasArrays(secret)
	lat, err := laterals(ctx, tx, t)
	if err != nil {
		return state{}, err
	}
	consulted := append([]uuid.UUID{t.scope, t.root}, lat...)
	if lat == nil {
		lat = []uuid.UUID{}
	}
	var st state
	rows, err := tx.Query(ctx, `
		SELECT r.id, r.kind, r.identity_id
		  FROM credprotect_restrictions r
		 WHERE r.identity_id = ANY($6)
		   AND (r.secret_kind IS NULL OR `+matchSecret("r.")+`)
		   AND NOT (r.kind = 'pause' AND r.ended_at IS NOT NULL)
		   AND NOT (r.kind = 'cooldown' AND r.expires_at <= $5)
		   AND NOT (r.kind = 'block' AND EXISTS (
		         SELECT 1 FROM credprotect_recoveries c
		          WHERE c.identity_id = CASE WHEN r.identity_id = ANY($7) THEN r.identity_id ELSE $1 END
		            AND r.id = ANY(c.lifted)))`,
		t.scope, string(secret.Kind), keys, ids, now, consulted, lat)
	if err != nil {
		return state{}, fmt.Errorf("credprotect: read restrictions: %w", err)
	}
	for rows.Next() {
		var r restriction
		if err := rows.Scan(&r.id, &r.kind, &r.identity); err != nil {
			rows.Close()
			return state{}, fmt.Errorf("credprotect: read restrictions: %w", err)
		}
		st.applies = append(st.applies, r)
		switch r.kind {
		case "pause":
			st.paused = true
		case "block":
			if r.identity == t.scope || r.identity == t.root || r.identity == t.hostRecord {
				st.blocked = true
			} else {
				st.stuck = true // a directory's block, lateral to an unconfirmed attempt
			}
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
		t.scope, string(secret.Kind), keys, ids).Scan(&st.requested, &st.verified); err != nil {
		return state{}, fmt.Errorf("credprotect: read verification state: %w", err)
	}
	return st, nil
}

// Status is a secret's mode for an attempt, and the bound on its scope's
// transmissions: K, plus o overridden submissions not yet known to have
// ended.
type Status struct {
	Mode  Mode
	Class Class
	Scope uuid.UUID
	K     int
	O     int
}

// Status reads the mode an attempt by credentialID on host would have now.
func (s *Store) Status(ctx context.Context, credentialID, hostID uuid.UUID, secret Secret) (Status, error) {
	if err := secret.valid(); err != nil {
		return Status{}, err
	}
	var out Status
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		t, err := s.resolveTarget(ctx, tx, credentialID, hostID, username)
		if err != nil {
			return err
		}
		st, err := readState(ctx, tx, t, secret, s.clock.Now())
		if err != nil {
			return err
		}
		o, err := overridesOutstanding(ctx, tx, t.scope)
		if err != nil {
			return err
		}
		out = Status{Mode: st.mode(), Class: t.class, Scope: t.scope, K: K, O: o}
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
