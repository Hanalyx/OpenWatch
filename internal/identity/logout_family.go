package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrFamilyInconsistent reports that the links around a logout target do
// not describe one user's login family: a row owned by a different user,
// or more rows than any real family could hold. Logout then revokes
// NOTHING. It never falls back to user-wide revocation and never revokes
// the part it could resolve, because either would be a silent widening
// or a partial success reported as a logout. Spec C-41.
var ErrFamilyInconsistent = errors.New("identity: logout family links are inconsistent")

// maxFamilyNodes bounds the traversal. A real family grows by one session
// and one refresh row per cookie rotation inside a 12-hour absolute
// window, so this is far above anything legitimate. Reaching it means
// the links are corrupt, and the walk stops rather than run unbounded.
const maxFamilyNodes = 4096

// LogoutAnchors are the credentials a logout request presented. Either,
// both or neither may be empty.
type LogoutAnchors struct {
	SessionToken string
	RefreshToken string
}

// LogoutTarget is one login family resolved for revocation.
type LogoutTarget struct {
	Owner         uuid.UUID
	Sessions      []uuid.UUID
	RefreshTokens []uuid.UUID
	// Anchor names which credential selected the family: "session",
	// "refresh", or "" when neither resolved.
	Anchor string
	// Conflict is true when both cookies resolved and the refresh cookie
	// belongs to a different family than the session cookie. The session
	// cookie's family is the one revoked; the other is left untouched.
	Conflict bool
}

type anchorRow struct {
	id    uuid.UUID
	owner uuid.UUID
	found bool
}

func findSessionByToken(ctx context.Context, q DBTX, token string) (anchorRow, error) {
	if token == "" {
		return anchorRow{}, nil
	}
	h := sha256.Sum256([]byte(token))
	var r anchorRow
	err := q.QueryRow(ctx, `SELECT id, user_id FROM sessions WHERE token_hash = $1`, h[:]).Scan(&r.id, &r.owner)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return anchorRow{}, nil
	case err != nil:
		return anchorRow{}, fmt.Errorf("identity: locate logout session: %w", err)
	}
	r.found = true
	return r, nil
}

func findRefreshByToken(ctx context.Context, q DBTX, token string) (anchorRow, error) {
	if token == "" {
		return anchorRow{}, nil
	}
	h := sha256.Sum256([]byte(token))
	var r anchorRow
	err := q.QueryRow(ctx, `SELECT id, user_id FROM refresh_tokens WHERE token_hash = $1`, h[:]).Scan(&r.id, &r.owner)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return anchorRow{}, nil
	case err != nil:
		return anchorRow{}, fmt.Errorf("identity: locate logout refresh token: %w", err)
	}
	r.found = true
	return r, nil
}

// LocateLogoutOwner finds whose per-user lock a logout must take, before
// the transaction starts. The session cookie is consulted first, which is
// the target-precedence policy for logout and nothing more.
//
// The lookup matches on the token hash ALONE: an idle-expired, absolutely
// expired or already revoked session is still found. That is correct for
// logout, where the cookie only LOCATES what to end, and wrong for any
// other purpose. Nothing but logout may use it to authorize a request.
func LocateLogoutOwner(ctx context.Context, q DBTX, a LogoutAnchors) (uuid.UUID, bool, error) {
	s, err := findSessionByToken(ctx, q, a.SessionToken)
	if err != nil {
		return uuid.Nil, false, err
	}
	if s.found {
		return s.owner, true, nil
	}
	r, err := findRefreshByToken(ctx, q, a.RefreshToken)
	if err != nil {
		return uuid.Nil, false, err
	}
	if r.found {
		return r.owner, true, nil
	}
	return uuid.Nil, false, nil
}

// ResolveLogoutFamily resolves the login family to end, inside the
// caller's transaction, which must already hold owner's per-user lock.
//
// A family is the connected set of sessions and refresh rows reachable
// through refresh_tokens.session_id and refresh_tokens.rotated_to_id, in
// BOTH directions. Both are needed: the cookie path rebinds each rotated
// successor to the session it mints, so from an old credential the live
// successor lies forward, and from a new one the predecessor lies
// backward. A lineage does not keep one session id.
//
// Isolation is ENFORCED, not assumed: every row reached must belong to
// owner, or the whole resolution fails with ErrFamilyInconsistent and
// nothing is revoked. Spec C-41.
func ResolveLogoutFamily(ctx context.Context, tx pgx.Tx, owner uuid.UUID, a LogoutAnchors) (LogoutTarget, error) {
	t := LogoutTarget{Owner: owner}
	s, err := findSessionByToken(ctx, tx, a.SessionToken)
	if err != nil {
		return t, err
	}
	r, err := findRefreshByToken(ctx, tx, a.RefreshToken)
	if err != nil {
		return t, err
	}

	var fam familySets
	switch {
	case s.found:
		if s.owner != owner {
			return t, fmt.Errorf("%w: session anchor owned by another user", ErrFamilyInconsistent)
		}
		t.Anchor = "session"
		fam, err = walkFamily(ctx, tx, owner, []uuid.UUID{s.id}, nil)
		if err != nil {
			return t, err
		}
		// Both cookies resolved: the refresh cookie either belongs to
		// this family or it does not. If not, it is recorded as a
		// conflict and its family is NOT revoked. Unioning the two would
		// let one logout end a second, unrelated login.
		if r.found {
			if _, in := fam.refresh[r.id]; !in {
				t.Conflict = true
			}
		}
	case r.found:
		if r.owner != owner {
			return t, fmt.Errorf("%w: refresh anchor owned by another user", ErrFamilyInconsistent)
		}
		t.Anchor = "refresh"
		fam, err = walkFamily(ctx, tx, owner, nil, []uuid.UUID{r.id})
		if err != nil {
			return t, err
		}
	default:
		return t, nil
	}
	t.Sessions = fam.sessionList()
	t.RefreshTokens = fam.refreshList()
	return t, nil
}

type familySets struct {
	sessions map[uuid.UUID]struct{}
	refresh  map[uuid.UUID]struct{}
}

func (f familySets) sessionList() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(f.sessions))
	for id := range f.sessions {
		out = append(out, id)
	}
	return out
}

func (f familySets) refreshList() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(f.refresh))
	for id := range f.refresh {
		out = append(out, id)
	}
	return out
}

// walkFamily is a breadth-first walk over the family graph. The visited
// sets are what make a cycle in rotated_to_id terminate; the node bound
// is what makes corrupt data fail instead of running unbounded.
func walkFamily(ctx context.Context, tx pgx.Tx, owner uuid.UUID, seedSessions, seedRefresh []uuid.UUID) (familySets, error) {
	fam := familySets{sessions: map[uuid.UUID]struct{}{}, refresh: map[uuid.UUID]struct{}{}}
	sessQ := append([]uuid.UUID(nil), seedSessions...)
	refQ := append([]uuid.UUID(nil), seedRefresh...)

	for len(sessQ) > 0 || len(refQ) > 0 {
		if len(fam.sessions)+len(fam.refresh) > maxFamilyNodes {
			return fam, fmt.Errorf("%w: more than %d linked rows", ErrFamilyInconsistent, maxFamilyNodes)
		}
		if len(sessQ) > 0 {
			sid := sessQ[0]
			sessQ = sessQ[1:]
			if _, seen := fam.sessions[sid]; seen {
				continue
			}
			var sOwner uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT user_id FROM sessions WHERE id = $1`, sid).Scan(&sOwner); err != nil {
				return fam, fmt.Errorf("identity: walk session %s: %w", sid, err)
			}
			if sOwner != owner {
				return fam, fmt.Errorf("%w: session %s owned by another user", ErrFamilyInconsistent, sid)
			}
			fam.sessions[sid] = struct{}{}
			ids, err := collectIDs(ctx, tx, `SELECT id FROM refresh_tokens WHERE session_id = $1`, sid)
			if err != nil {
				return fam, err
			}
			refQ = append(refQ, ids...)
			continue
		}
		rid := refQ[0]
		refQ = refQ[1:]
		if _, seen := fam.refresh[rid]; seen {
			continue
		}
		var (
			rOwner    uuid.UUID
			sessionID *uuid.UUID
			next      *uuid.UUID
		)
		if err := tx.QueryRow(ctx,
			`SELECT user_id, session_id, rotated_to_id FROM refresh_tokens WHERE id = $1`, rid).
			Scan(&rOwner, &sessionID, &next); err != nil {
			return fam, fmt.Errorf("identity: walk refresh %s: %w", rid, err)
		}
		if rOwner != owner {
			return fam, fmt.Errorf("%w: refresh %s owned by another user", ErrFamilyInconsistent, rid)
		}
		fam.refresh[rid] = struct{}{}
		if sessionID != nil {
			sessQ = append(sessQ, *sessionID)
		}
		if next != nil {
			refQ = append(refQ, *next)
		}
		prev, err := collectIDs(ctx, tx, `SELECT id FROM refresh_tokens WHERE rotated_to_id = $1`, rid)
		if err != nil {
			return fam, err
		}
		refQ = append(refQ, prev...)
	}
	return fam, nil
}

func collectIDs(ctx context.Context, tx pgx.Tx, stmt string, arg uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, stmt, arg)
	if err != nil {
		return nil, fmt.Errorf("identity: walk family: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("identity: walk family scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RevokeLogoutFamily revokes every session and refresh row in the target,
// inside the caller's transaction. Both statements commit together or
// not at all: a failure in either rolls back the other, so logout never
// reports a family ended when half of it is still live. Spec C-41.
func RevokeLogoutFamily(ctx context.Context, tx pgx.Tx, t LogoutTarget) error {
	if len(t.Sessions) > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at = now() WHERE id = ANY($1) AND revoked_at IS NULL`,
			t.Sessions); err != nil {
			return fmt.Errorf("identity: revoke family sessions: %w", err)
		}
	}
	if len(t.RefreshTokens) > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE refresh_tokens SET revoked_at = now() WHERE id = ANY($1) AND revoked_at IS NULL`,
			t.RefreshTokens); err != nil {
			return fmt.Errorf("identity: revoke family refresh tokens: %w", err)
		}
	}
	return nil
}
