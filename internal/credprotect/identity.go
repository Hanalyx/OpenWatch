package credprotect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Identity depths (spec C-02).
const depthDirectory = 2

// credentialUsername reads a credential's normalized username. It runs
// before the lock is taken, to learn which lock to take; callers re-check it
// under the lock with credentialUnderLock.
func credentialUsername(ctx context.Context, q pgx.Tx, credentialID uuid.UUID) (string, error) {
	var u string
	err := q.QueryRow(ctx, `SELECT username FROM credentials WHERE id = $1`, credentialID).Scan(&u)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: credential", ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("credprotect: read credential: %w", err)
	}
	return normalizeUsername(u), nil
}

// lockCredential takes the lock for the credential's username and returns
// the username, read again under the lock: a username edited in between
// would otherwise leave the caller holding another account's lock.
func lockCredential(ctx context.Context, tx pgx.Tx, credentialID uuid.UUID) (string, error) {
	username, err := credentialUsername(ctx, tx, credentialID)
	if err != nil {
		return "", err
	}
	if err := lockUsername(ctx, tx, username); err != nil {
		return "", err
	}
	again, err := credentialUsername(ctx, tx, credentialID)
	if err != nil {
		return "", err
	}
	if again != username {
		return "", fmt.Errorf("%w: the credential's username changed; retry", ErrInvalid)
	}
	return username, nil
}

// identityUsername reads an identity's username, for taking its lock.
func identityUsername(ctx context.Context, q pgx.Tx, id uuid.UUID) (string, error) {
	var u string
	err := q.QueryRow(ctx, `SELECT username FROM credprotect_identities WHERE id = $1`, id).Scan(&u)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: identity", ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("credprotect: read identity: %w", err)
	}
	return u, nil
}

// lockIdentity takes the lock for an identity's username.
func lockIdentity(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	username, err := identityUsername(ctx, tx, id)
	if err != nil {
		return err
	}
	return lockUsername(ctx, tx, username)
}

// ensureRoot returns the root identity for a username, creating it.
func ensureRoot(ctx context.Context, tx pgx.Tx, username string, now time.Time) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_identities (id, scope, username, depth, created_at)
		VALUES ($1, 'unconfirmed', $2, 1, $3)
		ON CONFLICT DO NOTHING`, newID(), username, now); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: create root: %w", err)
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM credprotect_identities WHERE scope = 'unconfirmed' AND username = $1`,
		username).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: read root: %w", err)
	}
	return id, nil
}

// ensureLocal returns the local identity for (host, username), creating it,
// and gives it a lineage edge to parent. Its depth is one more than its
// deepest parent's. Classify only ever records a root or a directory as the
// parent, so that is at most 3 (spec C-02), and the depth CHECK in
// migration 0067 refuses anything deeper.
func ensureLocal(ctx context.Context, tx pgx.Tx, hostID uuid.UUID, username string, parent uuid.UUID,
	now time.Time) (uuid.UUID, error) {
	var parentDepth int
	if err := tx.QueryRow(ctx, `SELECT depth FROM credprotect_identities WHERE id = $1`,
		parent).Scan(&parentDepth); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: read parent identity: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_identities (id, scope, username, host_id, depth, created_at)
		VALUES ($1, 'local', $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`, newID(), username, hostID, parentDepth+1, now); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: create local identity: %w", err)
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		UPDATE credprotect_identities SET depth = GREATEST(depth, $3)
		 WHERE scope = 'local' AND host_id = $1 AND username = $2
		RETURNING id`, hostID, username, parentDepth+1).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: read local identity: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_identity_edges (child_id, parent_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, id, parent); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: link local identity: %w", err)
	}
	return id, nil
}

// class is a credential's classification; a zero value is unconfirmed.
type class struct {
	scope     Scope
	directory uuid.UUID
	parent    uuid.UUID
}

func readClass(ctx context.Context, tx pgx.Tx, credentialID uuid.UUID) (class, error) {
	var c class
	var dir *uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT scope, directory_identity_id, parent_identity_id
		  FROM credprotect_credential_classes WHERE credential_id = $1`,
		credentialID).Scan(&c.scope, &dir, &c.parent)
	if errors.Is(err, pgx.ErrNoRows) {
		return class{scope: ScopeUnconfirmed}, nil
	}
	if err != nil {
		return class{}, fmt.Errorf("credprotect: read classification: %w", err)
	}
	if dir != nil {
		c.directory = *dir
	}
	return c, nil
}

// resolve returns the identity a credential resolves to on a host, creating
// identities as needed. The caller holds the username's lock (spec C-01).
func (s *Store) resolve(ctx context.Context, tx pgx.Tx, credentialID, hostID uuid.UUID,
	username string) (uuid.UUID, error) {
	now := s.clock.Now()
	root, err := ensureRoot(ctx, tx, username, now)
	if err != nil {
		return uuid.Nil, err
	}
	c, err := readClass(ctx, tx, credentialID)
	if err != nil {
		return uuid.Nil, err
	}
	switch c.scope {
	case ScopeUnconfirmed:
		return root, nil
	case ScopeDirectory:
		return c.directory, nil
	case ScopeLocal:
		if hostID == uuid.Nil {
			return uuid.Nil, fmt.Errorf("%w: a local credential resolves only for a host", ErrInvalid)
		}
		return ensureLocal(ctx, tx, hostID, username, c.parent, now)
	}
	return uuid.Nil, fmt.Errorf("credprotect: unknown scope %q", c.scope)
}

// Resolve returns the identity a credential resolves to on a host. A local
// credential needs a host; the others resolve the same on every host.
func (s *Store) Resolve(ctx context.Context, credentialID, hostID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		id, err = s.resolve(ctx, tx, credentialID, hostID, username)
		return err
	})
	return id, err
}

// CreateDirectory creates an operator-named directory identity for a
// username. Its only parent is that username's root (spec C-02).
func (s *Store) CreateDirectory(ctx context.Context, name, username string) (uuid.UUID, error) {
	username = normalizeUsername(username)
	if name == "" || username == "" {
		return uuid.Nil, fmt.Errorf("%w: a directory identity needs a name and a username", ErrInvalid)
	}
	id := newID()
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockUsername(ctx, tx, username); err != nil {
			return err
		}
		now := s.clock.Now()
		root, err := ensureRoot(ctx, tx, username, now)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO credprotect_identities (id, scope, username, directory_name, depth, created_at)
			VALUES ($1, 'directory', $2, $3, $4, $5)
			ON CONFLICT DO NOTHING`, id, username, name, depthDirectory, now)
		if err != nil {
			return fmt.Errorf("credprotect: create directory identity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: a directory identity with that name exists", ErrInvalid)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO credprotect_identity_edges (child_id, parent_id) VALUES ($1, $2)`, id, root); err != nil {
			return fmt.Errorf("credprotect: link directory identity: %w", err)
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// Target is where a classification moves a credential.
type Target struct {
	Scope     Scope
	Directory uuid.UUID // for ScopeDirectory
}

// Classify moves a credential to a narrower identity (spec C-02, C-12):
// unconfirmed to local or directory, or directory to local. It is refused
// while any identity at or below the credential's current identity has a
// submission holding a slot or an outstanding override. Nothing is copied;
// restrictions reach the new identities through lineage.
func (s *Store) Classify(ctx context.Context, credentialID uuid.UUID, to Target) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		root, err := ensureRoot(ctx, tx, username, now)
		if err != nil {
			return err
		}
		from, err := readClass(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		var current uuid.UUID
		switch {
		case from.scope == ScopeUnconfirmed && (to.Scope == ScopeLocal || to.Scope == ScopeDirectory):
			current = root
		case from.scope == ScopeDirectory && to.Scope == ScopeLocal:
			current = from.directory
		default:
			return fmt.Errorf("%w: %s to %s would exceed the lineage bound or merge lineage",
				ErrClassification, from.scope, to.Scope)
		}
		if to.Scope == ScopeDirectory {
			var dirUser string
			var dirScope Scope
			err := tx.QueryRow(ctx, `SELECT username, scope FROM credprotect_identities WHERE id = $1`,
				to.Directory).Scan(&dirUser, &dirScope)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && dirScope != ScopeDirectory) {
				return fmt.Errorf("%w: no such directory identity", ErrClassification)
			}
			if err != nil {
				return fmt.Errorf("credprotect: read directory identity: %w", err)
			}
			if dirUser != username {
				return fmt.Errorf("%w: the directory identity is for another username", ErrClassification)
			}
		}
		var outstanding bool
		if err := tx.QueryRow(ctx, `
			WITH RECURSIVE below(id) AS (
				SELECT $1::uuid
				UNION
				SELECT e.child_id FROM credprotect_identity_edges e JOIN below b ON e.parent_id = b.id
			)
			SELECT EXISTS (
				SELECT 1 FROM credprotect_submissions s
				 WHERE s.identity_id IN (SELECT id FROM below)
				   AND (s.slot_held OR (s.overridden_at IS NOT NULL AND s.ended_at IS NULL)))`,
			current).Scan(&outstanding); err != nil {
			return fmt.Errorf("credprotect: check outstanding: %w", err)
		}
		if outstanding {
			return fmt.Errorf("%w: classification waits until it ends", ErrOutstanding)
		}
		var dir *uuid.UUID
		if to.Scope == ScopeDirectory {
			dir = &to.Directory
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO credprotect_credential_classes
			       (credential_id, scope, directory_identity_id, parent_identity_id, classified_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (credential_id) DO UPDATE
			   SET scope = EXCLUDED.scope, directory_identity_id = EXCLUDED.directory_identity_id,
			       parent_identity_id = EXCLUDED.parent_identity_id, classified_at = EXCLUDED.classified_at`,
			credentialID, string(to.Scope), dir, current, now); err != nil {
			return fmt.Errorf("credprotect: record classification: %w", err)
		}
		return nil
	})
}

// ancestors returns an identity and every identity above it.
func ancestors(ctx context.Context, tx pgx.Tx, id uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE above(id) AS (
			SELECT $1::uuid
			UNION
			SELECT e.parent_id FROM credprotect_identity_edges e JOIN above a ON e.child_id = a.id
		)
		SELECT id FROM above`, id)
	if err != nil {
		return nil, fmt.Errorf("credprotect: read lineage: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("credprotect: read lineage: %w", err)
	}
	return ids, nil
}
