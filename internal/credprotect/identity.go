package credprotect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Class is what an attempt's credential and host establish about the
// account it reaches (spec C-01).
type Class string

const (
	// ClassDirectory: the credential is classified to a usable directory
	// identity. Its scope is that directory, fleet-wide.
	ClassDirectory Class = "directory"
	// ClassConfirmedLocal: the credential is classified local and its host
	// record was confirmed local by an operator. Its scope is the host
	// record.
	ClassConfirmedLocal Class = "confirmed_local"
	// ClassUnconfirmed: everything else. Its scope is the username's root,
	// fleet-wide.
	ClassUnconfirmed Class = "unconfirmed"
)

// Admission is a directory identity's state (spec C-13).
type Admission string

const (
	AdmissionUsable    Admission = "usable"
	AdmissionCandidate Admission = "candidate"
	AdmissionRetired   Admission = "retired"
)

// target is what an attempt is for: its class, its scope, its username's
// root, its host and that host's record, if one exists.
type target struct {
	class      Class
	scope      uuid.UUID
	root       uuid.UUID
	username   string
	host       uuid.UUID
	hostRecord uuid.UUID // uuid.Nil when (host, username) has no record
}

// credentialUsername reads a credential's normalized username. It runs
// before the lock is taken, to learn which lock to take; callers re-check it
// under the lock with lockCredential.
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

// identityRow is an identity as stored.
type identityRow struct {
	id        uuid.UUID
	scope     Scope
	username  string
	admission *string
	retiredTo *uuid.UUID
	confirmed bool
}

func readIdentity(ctx context.Context, tx pgx.Tx, id uuid.UUID) (identityRow, error) {
	var r identityRow
	err := tx.QueryRow(ctx, `
		SELECT id, scope, username, admission, retired_into, confirmed_local
		  FROM credprotect_identities WHERE id = $1`, id).Scan(
		&r.id, &r.scope, &r.username, &r.admission, &r.retiredTo, &r.confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityRow{}, fmt.Errorf("%w: identity", ErrNotFound)
	}
	if err != nil {
		return identityRow{}, fmt.Errorf("credprotect: read identity: %w", err)
	}
	return r, nil
}

// lockIdentity takes the lock for an identity's username and returns the
// identity.
func lockIdentity(ctx context.Context, tx pgx.Tx, id uuid.UUID) (identityRow, error) {
	r, err := readIdentity(ctx, tx, id)
	if err != nil {
		return identityRow{}, err
	}
	if err := lockUsername(ctx, tx, r.username); err != nil {
		return identityRow{}, err
	}
	return r, nil
}

// refuseUnusable refuses an operation that would put protection history on
// a candidate or retired directory identity: those admit nothing (spec
// C-13).
func refuseUnusable(r identityRow) error {
	if r.scope == ScopeDirectory && r.admission != nil && Admission(*r.admission) != AdmissionUsable {
		return fmt.Errorf("%w: directory identity is %s", ErrCandidate, *r.admission)
	}
	return nil
}

// ensureRoot returns the root identity for a username, creating it.
func ensureRoot(ctx context.Context, tx pgx.Tx, username string, now time.Time) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_identities (id, scope, username, created_at)
		VALUES ($1, 'unconfirmed', $2, $3)
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

// hostRecord returns the host record for (host, username), if one exists,
// and whether it is confirmed local.
func hostRecord(ctx context.Context, tx pgx.Tx, host uuid.UUID, username string) (uuid.UUID, bool, error) {
	var id uuid.UUID
	var confirmed bool
	err := tx.QueryRow(ctx, `
		SELECT id, confirmed_local FROM credprotect_identities
		 WHERE scope = 'local' AND host_id = $1 AND username = $2`, host, username).Scan(&id, &confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("credprotect: read host record: %w", err)
	}
	return id, confirmed, nil
}

// ensureHostRecord returns the host record for (host, username), creating it.
func ensureHostRecord(ctx context.Context, tx pgx.Tx, host uuid.UUID, username string, now time.Time) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_identities (id, scope, username, host_id, created_at)
		VALUES ($1, 'local', $2, $3, $4)
		ON CONFLICT DO NOTHING`, newID(), username, host, now); err != nil {
		return uuid.Nil, fmt.Errorf("credprotect: create host record: %w", err)
	}
	id, _, err := hostRecord(ctx, tx, host, username)
	return id, err
}

// class is a credential's classification; a zero value is unconfirmed.
type class struct {
	scope     Scope
	directory uuid.UUID
}

func readClass(ctx context.Context, tx pgx.Tx, credentialID uuid.UUID) (class, error) {
	var c class
	var dir *uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT scope, directory_identity_id FROM credprotect_credential_classes WHERE credential_id = $1`,
		credentialID).Scan(&c.scope, &dir)
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

// resolveTarget is what an attempt by credentialID on host would be for,
// now (spec C-01). The caller holds the username's lock.
//
//   - Classified to a usable directory for its current username: directory
//     class, scoped to that directory. A candidate or retired directory
//     admits nothing; resolving a candidate as the same reclassifies its
//     credentials, so none stays classified to a retired one.
//   - Classified local, on a host whose record is confirmed local:
//     confirmed-local class, scoped to the host record.
//   - Anything else, including a classification left stale by a username
//     edit and a local classification on an unconfirmed host: unconfirmed,
//     scoped to the root.
func (s *Store) resolveTarget(ctx context.Context, tx pgx.Tx, credentialID, host uuid.UUID,
	username string) (target, error) {
	now := s.clock.Now()
	root, err := ensureRoot(ctx, tx, username, now)
	if err != nil {
		return target{}, err
	}
	t := target{class: ClassUnconfirmed, scope: root, root: root, username: username, host: host}
	confirmed := false
	if host != uuid.Nil {
		if t.hostRecord, confirmed, err = hostRecord(ctx, tx, host, username); err != nil {
			return target{}, err
		}
	}
	c, err := readClass(ctx, tx, credentialID)
	if err != nil {
		return target{}, err
	}
	switch c.scope {
	case ScopeDirectory:
		d, err := readIdentity(ctx, tx, c.directory)
		if err != nil {
			return target{}, err
		}
		if d.username != username {
			return t, nil // stale: the credential's username was edited
		}
		if err := refuseUnusable(d); err != nil {
			return target{}, err
		}
		t.class, t.scope = ClassDirectory, d.id
	case ScopeLocal:
		if host == uuid.Nil {
			return target{}, fmt.Errorf("%w: a local credential resolves only for a host", ErrInvalid)
		}
		if confirmed {
			t.class, t.scope = ClassConfirmedLocal, t.hostRecord
		}
	}
	return t, nil
}

// Resolve returns the scope an attempt by credentialID on host would have
// now: the identity whose slot it would hold.
func (s *Store) Resolve(ctx context.Context, credentialID, hostID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		t, err := s.resolveTarget(ctx, tx, credentialID, hostID, username)
		id = t.scope
		return err
	})
	return id, err
}

// outstanding refuses while any attempt for a username holds a slot or
// counts in o. Binding changes wait for none (spec C-12).
func outstanding(ctx context.Context, tx pgx.Tx, username string) error {
	var busy bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM credprotect_submissions
		                WHERE username = $1
		                  AND (slot_held OR (overridden_at IS NOT NULL AND ended_at IS NULL)))`,
		username).Scan(&busy); err != nil {
		return fmt.Errorf("credprotect: check outstanding: %w", err)
	}
	if busy {
		return fmt.Errorf("%w: binding changes wait until it ends", ErrOutstanding)
	}
	return nil
}

// usableDirectories lists the usable directory identities for a username.
func usableDirectories(ctx context.Context, tx pgx.Tx, username string) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		SELECT id FROM credprotect_identities
		 WHERE scope = 'directory' AND username = $1 AND admission = 'usable'`, username)
	if err != nil {
		return nil, fmt.Errorf("credprotect: list directories: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("credprotect: list directories: %w", err)
	}
	return sortedIDs(ids), nil
}

// CreateDirectory creates an operator-named directory identity for a
// username, under the username's lock (spec C-13). The first one for a
// username is usable; any later one is a candidate, which admits no
// attempts until it is resolved with AssertDistinct or ResolveSame.
// Concurrent creations serialize on the lock, so exactly one is usable.
func (s *Store) CreateDirectory(ctx context.Context, name, username string) (uuid.UUID, Admission, error) {
	username = normalizeUsername(username)
	if name == "" || username == "" {
		return uuid.Nil, "", fmt.Errorf("%w: a directory identity needs a name and a username", ErrInvalid)
	}
	id := newID()
	var adm Admission
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockUsername(ctx, tx, username); err != nil {
			return err
		}
		now := s.clock.Now()
		if _, err := ensureRoot(ctx, tx, username, now); err != nil {
			return err
		}
		usable, err := usableDirectories(ctx, tx, username)
		if err != nil {
			return err
		}
		adm = AdmissionUsable
		if len(usable) > 0 {
			adm = AdmissionCandidate
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO credprotect_identities (id, scope, username, directory_name, admission, created_at)
			VALUES ($1, 'directory', $2, $3, $4, $5)
			ON CONFLICT DO NOTHING`, id, username, name, string(adm), now)
		if err != nil {
			return fmt.Errorf("credprotect: create directory identity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: a directory identity with that name exists", ErrInvalid)
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, "", err
	}
	return id, adm, nil
}

// lockCandidate locks a candidate directory's username and checks the
// conditions every resolution shares.
func lockCandidate(ctx context.Context, tx pgx.Tx, candidate, actor uuid.UUID, basis string) (identityRow, error) {
	if actor == uuid.Nil || basis == "" {
		return identityRow{}, fmt.Errorf("%w: a resolution needs the operator and its basis", ErrInvalid)
	}
	c, err := lockIdentity(ctx, tx, candidate)
	if err != nil {
		return identityRow{}, err
	}
	if c.scope != ScopeDirectory || c.admission == nil || Admission(*c.admission) != AdmissionCandidate {
		return identityRow{}, fmt.Errorf("%w: not a candidate directory identity", ErrInvalid)
	}
	if err := outstanding(ctx, tx, c.username); err != nil {
		return identityRow{}, err
	}
	return c, nil
}

// AssertDistinct makes a candidate directory usable, on the operator's
// audited assertion that it is a separate account from each usable
// directory identity it names (spec C-13). covers must be exactly the
// usable directory identities for the username now; if that set changed
// since the operator saw it, the assertion is refused.
func (s *Store) AssertDistinct(ctx context.Context, candidate uuid.UUID, covers []uuid.UUID, actor uuid.UUID,
	basis string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		c, err := lockCandidate(ctx, tx, candidate, actor, basis)
		if err != nil {
			return err
		}
		usable, err := usableDirectories(ctx, tx, c.username)
		if err != nil {
			return err
		}
		if !sameIDs(sortedIDs(covers), usable) {
			return fmt.Errorf("%w: the usable directory identities changed; review them and assert again",
				ErrStaleAssertion)
		}
		now := s.clock.Now()
		if _, err := tx.Exec(ctx, `UPDATE credprotect_identities SET admission = 'usable' WHERE id = $1`,
			candidate); err != nil {
			return fmt.Errorf("credprotect: admit directory identity: %w", err)
		}
		return recordResolution(ctx, tx, candidate, "distinct", usable, actor, basis, now)
	})
}

// ResolveSame retires a candidate directory as the same account as a usable
// one, and reclassifies every credential classified to the candidate to
// it, in one transaction (spec C-13). A candidate admits no attempts, so
// it has no protection history to carry over; that is checked, not assumed.
func (s *Store) ResolveSame(ctx context.Context, candidate, into, actor uuid.UUID, basis string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		c, err := lockCandidate(ctx, tx, candidate, actor, basis)
		if err != nil {
			return err
		}
		d, err := readIdentity(ctx, tx, into)
		if err != nil {
			return err
		}
		if d.scope != ScopeDirectory || d.username != c.username || d.admission == nil ||
			Admission(*d.admission) != AdmissionUsable {
			return fmt.Errorf("%w: the target is not a usable directory identity for the same username", ErrInvalid)
		}
		var history bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM credprotect_restrictions WHERE identity_id = $1)
			    OR EXISTS (SELECT 1 FROM credprotect_submissions WHERE identity_id = $1)
			    OR EXISTS (SELECT 1 FROM credprotect_recoveries WHERE identity_id = $1)
			    OR EXISTS (SELECT 1 FROM credprotect_verification_requests WHERE identity_id = $1)`,
			candidate).Scan(&history); err != nil {
			return fmt.Errorf("credprotect: check candidate history: %w", err)
		}
		if history {
			return fmt.Errorf("%w: the candidate has protection history", ErrCandidate)
		}
		now := s.clock.Now()
		if _, err := tx.Exec(ctx, `
			UPDATE credprotect_identities SET admission = 'retired', retired_into = $2 WHERE id = $1`,
			candidate, into); err != nil {
			return fmt.Errorf("credprotect: retire directory identity: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE credprotect_credential_classes SET directory_identity_id = $2, classified_at = $3
			 WHERE directory_identity_id = $1`, candidate, into, now); err != nil {
			return fmt.Errorf("credprotect: reclassify to the usable identity: %w", err)
		}
		return recordResolution(ctx, tx, candidate, "same", []uuid.UUID{into}, actor, basis, now)
	})
}

func recordResolution(ctx context.Context, tx pgx.Tx, directory uuid.UUID, kind string, covers []uuid.UUID,
	actor uuid.UUID, basis string, now time.Time) error {
	if covers == nil {
		covers = []uuid.UUID{}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO credprotect_directory_resolutions (id, directory_id, resolution, covers, actor, basis, resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, newID(), directory, kind, covers, actor, basis, now); err != nil {
		return fmt.Errorf("credprotect: record resolution: %w", err)
	}
	return nil
}

// sortedIDs returns a sorted copy, never nil: an empty set is stored as an
// empty array, not NULL.
func sortedIDs(ids []uuid.UUID) []uuid.UUID {
	out := append([]uuid.UUID{}, ids...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// ConfirmLocal records an operator's audited assertion, with its basis,
// that (host, username) is a local account and no directory account (spec
// C-14). It is refused once a directory-bound attempt has recorded binding
// intent for that host account: a conservative policy, since intent is not
// proof that the attempt reached the host.
func (s *Store) ConfirmLocal(ctx context.Context, host uuid.UUID, username string, actor uuid.UUID,
	basis string) error {
	username = normalizeUsername(username)
	if host == uuid.Nil || username == "" || actor == uuid.Nil || basis == "" {
		return fmt.Errorf("%w: a confirmation needs the host, username, operator and basis", ErrInvalid)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockUsername(ctx, tx, username); err != nil {
			return err
		}
		if err := outstanding(ctx, tx, username); err != nil {
			return err
		}
		var intent bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM credprotect_directory_bindings WHERE host_id = $1 AND username = $2)`,
			host, username).Scan(&intent); err != nil {
			return fmt.Errorf("credprotect: read binding intent: %w", err)
		}
		if intent {
			return fmt.Errorf("%w: a directory-bound attempt recorded intent for this host account", ErrBinding)
		}
		now := s.clock.Now()
		if _, err := ensureRoot(ctx, tx, username, now); err != nil {
			return err
		}
		hr, err := ensureHostRecord(ctx, tx, host, username, now)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE credprotect_identities
			   SET confirmed_local = true, confirmed_by = $2, confirmed_at = $3, confirmed_basis = $4
			 WHERE id = $1`, hr, actor, now, basis); err != nil {
			return fmt.Errorf("credprotect: confirm local: %w", err)
		}
		return nil
	})
}

// WithdrawLocal withdraws a local confirmation. Attempts on that host go
// back to unconfirmed coordination; the host record and its history stay.
func (s *Store) WithdrawLocal(ctx context.Context, host uuid.UUID, username string) error {
	username = normalizeUsername(username)
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockUsername(ctx, tx, username); err != nil {
			return err
		}
		if err := outstanding(ctx, tx, username); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE credprotect_identities
			   SET confirmed_local = false, confirmed_by = NULL, confirmed_at = NULL, confirmed_basis = NULL
			 WHERE scope = 'local' AND host_id = $1 AND username = $2`, host, username); err != nil {
			return fmt.Errorf("credprotect: withdraw local: %w", err)
		}
		return nil
	})
}

// Target is where a classification moves a credential.
type Target struct {
	Scope     Scope
	Directory uuid.UUID // for ScopeDirectory
}

// Classify sets what a credential claims about its account (spec C-12):
// unconfirmed, local, or a directory identity for its username, a
// candidate included. It is refused while any attempt for the username
// holds a slot or counts in o. Nothing is copied or moved: restrictions
// stay where they were recorded, and the classes of spec C-01 decide which
// of them later attempts consult.
func (s *Store) Classify(ctx context.Context, credentialID uuid.UUID, to Target) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		username, err := lockCredential(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		if err := outstanding(ctx, tx, username); err != nil {
			return err
		}
		now := s.clock.Now()
		switch to.Scope {
		case ScopeUnconfirmed:
			if _, err := tx.Exec(ctx, `DELETE FROM credprotect_credential_classes WHERE credential_id = $1`,
				credentialID); err != nil {
				return fmt.Errorf("credprotect: record classification: %w", err)
			}
			return nil
		case ScopeLocal:
		case ScopeDirectory:
			d, err := readIdentity(ctx, tx, to.Directory)
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("%w: no such directory identity", ErrClassification)
			}
			if err != nil {
				return err
			}
			if d.scope != ScopeDirectory {
				return fmt.Errorf("%w: not a directory identity", ErrClassification)
			}
			if d.username != username {
				return fmt.Errorf("%w: the directory identity is for another username", ErrClassification)
			}
			if Admission(*d.admission) == AdmissionRetired {
				return fmt.Errorf("%w: the directory identity is retired", ErrClassification)
			}
		default:
			return fmt.Errorf("%w: unknown scope %q", ErrClassification, to.Scope)
		}
		var dir *uuid.UUID
		if to.Scope == ScopeDirectory {
			dir = &to.Directory
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO credprotect_credential_classes (credential_id, scope, directory_identity_id, classified_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (credential_id) DO UPDATE
			   SET scope = EXCLUDED.scope, directory_identity_id = EXCLUDED.directory_identity_id,
			       classified_at = EXCLUDED.classified_at`,
			credentialID, string(to.Scope), dir, now); err != nil {
			return fmt.Errorf("credprotect: record classification: %w", err)
		}
		return nil
	})
}
