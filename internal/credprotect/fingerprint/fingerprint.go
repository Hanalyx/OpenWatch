// Package fingerprint identifies passwords for credential protection without
// storing them (features/OW-122 slice 2; spec system-credential-protection
// C-15 to C-17).
//
// A password's identifier under one fingerprint key is
// HMAC-SHA256(key, normalized username || 0x00 || password). Each key is 32
// random bytes, stored wrapped by the credential encryption key in
// credprotect_fingerprint_keys. A password is identified under every key the
// keyring holds, and a key is never removed: protection history recorded
// under it must keep matching.
//
// An identifier is a sensitive equality value. Anyone holding a fingerprint
// key and the protection tables can test password guesses offline, under
// every key, past and future, so the keys stay wrapped at rest and no
// identifier is logged, audited or returned by the API.
package fingerprint

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// KeySize is the length of a fingerprint key and of an identifier.
const KeySize = 32

// Wrapper wraps and unwraps fingerprint keys: the credential encryption key.
// *secretkey.Key satisfies it.
type Wrapper interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// TxBeginner starts a transaction. *pgxpool.Pool satisfies it.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Alias is a password's identifier under one fingerprint key. KeyID is the
// key's id as a string.
type Alias struct {
	KeyID string
	ID    [KeySize]byte
}

// String never reveals the identifier.
func (a Alias) String() string { return "alias under key " + a.KeyID }

// GoString keeps %#v from printing the identifier.
func (a Alias) GoString() string { return a.String() }

type key struct {
	id       uuid.UUID
	material []byte
	current  bool
}

// Keyring is a validated snapshot of the fingerprint keys, taken at
// Generation. Callers pass its Snapshot with the aliases they compute, so
// credential protection can refuse aliases from a stale or damaged keyring.
type Keyring struct {
	Generation int64
	keys       []key
	digest     [sha256.Size]byte
}

// Snapshot identifies the exact keyring a set of aliases was computed
// from: its generation and a digest of every key row as stored (id,
// current flag, wrapped bytes). Credential protection recomputes it from
// the rows inside its own transaction, without the encryption key, so any
// change to the keyring after it was validated (a key deleted, the current
// flag moved, a wrapped key altered, a key added) refuses the aliases
// (spec C-16).
type Snapshot struct {
	Generation int64
	Digest     [sha256.Size]byte
}

// Snapshot returns the snapshot this keyring was validated at.
func (k Keyring) Snapshot() Snapshot { return Snapshot{Generation: k.Generation, Digest: k.digest} }

// digestOf hashes the stored key rows. Rows are taken in id order, and the
// wrapped bytes are length-prefixed, so no two keyrings share a digest by
// concatenation. The generation is not part of it: a Snapshot compares the
// generation itself.
func digestOf(keys []storedKey) [sha256.Size]byte {
	rows := slices.Clone(keys)
	slices.SortFunc(rows, func(a, b storedKey) int { return strings.Compare(a.id.String(), b.id.String()) })
	h := sha256.New()
	var n [8]byte
	h.Write([]byte("openwatch/fingerprint-keyring/v1"))
	for _, k := range rows {
		h.Write(k.id[:])
		if k.current {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
		binary.BigEndian.PutUint64(n[:], uint64(len(k.wrapped)))
		h.Write(n[:])
		h.Write(k.wrapped)
	}
	var d [sha256.Size]byte
	copy(d[:], h.Sum(nil))
	return d
}

// State is the keyring as credential protection sees it inside its own
// transaction. Reading it needs no encryption key: it checks structure and
// the snapshot, not that the keys unwrap; a snapshot proves that, because
// only a keyring that unwrapped (Load) produces one.
type State struct {
	Initialized bool
	Keys        int
	Current     int
	KeyIDs      map[string]bool
	Snapshot    Snapshot
}

// ReadState reads the keyring row and its key rows FOR SHARE in tx, so a
// keyring change (which locks the row FOR UPDATE) cannot overlap the
// caller's operation. A missing keyring row is an *UnavailableError.
func ReadState(ctx context.Context, tx pgx.Tx) (State, error) {
	s, err := readSingleton(ctx, tx, "FOR SHARE")
	if err != nil {
		return State{}, err
	}
	keys, err := readKeys(ctx, tx)
	if err != nil {
		return State{}, err
	}
	st := State{Initialized: s.initialized, Keys: len(keys), KeyIDs: map[string]bool{},
		Snapshot: Snapshot{Generation: s.generation, Digest: digestOf(keys)}}
	for _, k := range keys {
		st.KeyIDs[k.id.String()] = true
		if k.current {
			st.Current++
		}
	}
	return st, nil
}

// KeyIDs lists the keys' ids, the current key first.
func (k Keyring) KeyIDs() []string {
	out := make([]string, 0, len(k.keys))
	for _, ky := range k.keys {
		out = append(out, ky.id.String())
	}
	return out
}

// Password returns the password's identifier under every key, the current
// key first.
func (k Keyring) Password(username, password string) []Alias {
	out := make([]Alias, 0, len(k.keys))
	for _, ky := range k.keys {
		out = append(out, Alias{KeyID: ky.id.String(), ID: identify(ky.material, username, password)})
	}
	return out
}

// identify is HMAC-SHA256(material, normalized username || 0x00 ||
// password).
func identify(material []byte, username, password string) [KeySize]byte {
	m := hmac.New(sha256.New, material)
	m.Write([]byte(normalizeUsername(username)))
	m.Write([]byte{0})
	m.Write([]byte(password))
	var id [KeySize]byte
	copy(id[:], m.Sum(nil))
	return id
}

// normalizeUsername is credprotect's identity key: trimmed, lower-case. It
// is repeated here because this package must not import credprotect.
func normalizeUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

// Cause says why a keyring cannot be used.
type Cause string

const (
	// CauseNotInitialized: no keyring has been created. Load creates one
	// when nothing depends on an earlier one; Rewrap and Verify report it.
	CauseNotInitialized Cause = "not_initialized"
	// CauseRowMissing: the keyring's single row is gone.
	CauseRowMissing Cause = "keyring_row_missing"
	// CauseInconsistent: the keyring row and the key rows disagree: keys
	// or password identifiers exist without an initialized keyring, or the
	// keyring has no current key or more than one.
	CauseInconsistent Cause = "inconsistent"
	// CauseKeysDeleted: the keyring is initialized but holds no key.
	CauseKeysDeleted Cause = "keys_deleted"
	// CauseKeyMissing: protection state holds a password identifier under a
	// key the keyring does not have.
	CauseKeyMissing Cause = "key_missing"
	// CauseUnwrap: a key cannot be unwrapped with the credential encryption
	// key at hand.
	CauseUnwrap Cause = "unwrap_failed"
	// CauseBadLength: a key unwrapped to the wrong length.
	CauseBadLength Cause = "bad_key_length"
)

// ErrUnavailable is the error every UnavailableError wraps.
var ErrUnavailable = errors.New("credential protection keyring cannot be used")

// UnavailableError is a keyring that must not be used. Credential protection
// refuses every operation on it rather than continue as if it had no
// history.
type UnavailableError struct {
	Cause  Cause
	Detail string
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("%v: %s (%s). %s", ErrUnavailable, e.Detail, e.Cause, e.Remedy())
}

func (e *UnavailableError) Unwrap() error { return ErrUnavailable }

// Remedy says what an operator can do. A key that cannot be unwrapped may
// only need its encryption key; a key that is gone cannot be recreated.
func (e *UnavailableError) Remedy() string {
	switch e.Cause {
	case CauseUnwrap:
		return "If the credential encryption key was replaced, run `openwatch credential-key rewrap " +
			"--previous-key-file PATH` with the previous key, or restore the previous key."
	case CauseNotInitialized:
		return "No keyring exists yet; it is created the first time credential protection is used."
	default:
		return "A re-wrap cannot recreate key material. Restore the credential protection tables from " +
			"a database backup that matches the current credential encryption key."
	}
}

func unavailable(c Cause, format string, args ...any) error {
	return &UnavailableError{Cause: c, Detail: fmt.Sprintf(format, args...)}
}

// singleton is the keyring row.
type singleton struct {
	initialized bool
	generation  int64
	wrapEpoch   int64
}

// readSingleton reads the keyring row, locking it in mode ("FOR UPDATE" or
// "FOR SHARE").
func readSingleton(ctx context.Context, tx pgx.Tx, mode string) (singleton, error) {
	var s singleton
	err := tx.QueryRow(ctx, `SELECT initialized_at IS NOT NULL, generation, wrap_epoch
		FROM credprotect_keyring WHERE singleton `+mode).Scan(&s.initialized, &s.generation, &s.wrapEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, unavailable(CauseRowMissing, "the keyring row does not exist")
	}
	if err != nil {
		return s, fmt.Errorf("fingerprint: read keyring: %w", err)
	}
	return s, nil
}

// storedKey is a key row as stored.
type storedKey struct {
	id      uuid.UUID
	wrapped []byte
	current bool
}

func readKeys(ctx context.Context, tx pgx.Tx) ([]storedKey, error) {
	rows, err := tx.Query(ctx, `SELECT id, wrapped, is_current FROM credprotect_fingerprint_keys
		ORDER BY is_current DESC, created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: read keys: %w", err)
	}
	defer rows.Close()
	var out []storedKey
	for rows.Next() {
		var k storedKey
		if err := rows.Scan(&k.id, &k.wrapped, &k.current); err != nil {
			return nil, fmt.Errorf("fingerprint: read keys: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// aliasKeyIDs lists every key id that recorded protection state uses for a
// password identifier. It only reads.
func aliasKeyIDs(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT k FROM (
			SELECT unnest(alias_key_ids) AS k FROM credprotect_restrictions WHERE secret_kind = 'password'
			UNION ALL SELECT unnest(alias_key_ids) FROM credprotect_submissions WHERE secret_kind = 'password'
			UNION ALL SELECT unnest(alias_key_ids) FROM credprotect_verification_requests WHERE secret_kind = 'password'
			UNION ALL SELECT unnest(alias_key_ids) FROM credprotect_verified_secrets WHERE secret_kind = 'password'
		) AS used ORDER BY k`)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: read identifier keys: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("fingerprint: read identifier keys: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// checkStructure checks an initialized keyring's rows: at least one key,
// exactly one current, and every password identifier's key present.
func checkStructure(ctx context.Context, tx pgx.Tx, keys []storedKey) error {
	if len(keys) == 0 {
		return unavailable(CauseKeysDeleted, "the keyring is initialized but holds no key")
	}
	current := 0
	ids := map[string]bool{}
	for _, k := range keys {
		ids[k.id.String()] = true
		if k.current {
			current++
		}
	}
	if current != 1 {
		return unavailable(CauseInconsistent, "the keyring has %d current keys, not one", current)
	}
	used, err := aliasKeyIDs(ctx, tx)
	if err != nil {
		return err
	}
	var missing []string
	for _, id := range used {
		if !ids[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return unavailable(CauseKeyMissing, "protection state uses %d key(s) the keyring does not hold: %s",
			len(missing), strings.Join(missing, ", "))
	}
	return nil
}

// unwrapAll unwraps every key with w. It returns the keys it could read and
// how many it could not.
func unwrapAll(keys []storedKey, w Wrapper) ([]key, int) {
	out := make([]key, 0, len(keys))
	unreadable := 0
	for _, k := range keys {
		m, err := w.Decrypt(k.wrapped)
		if err != nil {
			unreadable++
			continue
		}
		out = append(out, key{id: k.id, material: m, current: k.current})
	}
	return out, unreadable
}

func checkLengths(keys []key) error {
	for _, k := range keys {
		if len(k.material) != KeySize {
			return unavailable(CauseBadLength, "key %s unwraps to %d bytes, not %d", k.id, len(k.material), KeySize)
		}
	}
	return nil
}

// validate reads and checks an initialized keyring and unwraps it with w.
func validate(ctx context.Context, tx pgx.Tx, s singleton, w Wrapper) (Keyring, error) {
	keys, err := readKeys(ctx, tx)
	if err != nil {
		return Keyring{}, err
	}
	if err := checkStructure(ctx, tx, keys); err != nil {
		return Keyring{}, err
	}
	unwrapped, unreadable := unwrapAll(keys, w)
	if unreadable > 0 {
		return Keyring{}, unavailable(CauseUnwrap, "%d of %d key(s) cannot be unwrapped with the credential encryption key",
			unreadable, len(keys))
	}
	if err := checkLengths(unwrapped); err != nil {
		return Keyring{}, err
	}
	return Keyring{Generation: s.generation, keys: unwrapped, digest: digestOf(keys)}, nil
}

// checkNew reports whether an uninitialized keyring is genuinely new: no key
// rows and no password identifier anywhere. Anything else is a keyring that
// was lost, which must not be replaced.
func checkNew(ctx context.Context, tx pgx.Tx) error {
	keys, err := readKeys(ctx, tx)
	if err != nil {
		return err
	}
	used, err := aliasKeyIDs(ctx, tx)
	if err != nil {
		return err
	}
	if len(keys) > 0 || len(used) > 0 {
		return unavailable(CauseInconsistent, "the keyring is not initialized, but %d key row(s) and "+
			"password identifiers under %d key(s) exist", len(keys), len(used))
	}
	return nil
}

// Load returns the keyring, validated and unwrapped with w. A keyring that
// is genuinely new is initialized with one current key; any other state
// that cannot be used returns an *UnavailableError. Two processes racing to
// initialize serialize on the keyring row: one creates the key and the
// other loads it.
func Load(ctx context.Context, db TxBeginner, w Wrapper, now time.Time) (Keyring, error) {
	var kr Keyring
	initialized := false
	err := inTx(ctx, db, func(tx pgx.Tx) error {
		s, err := readSingleton(ctx, tx, "FOR SHARE")
		if err != nil {
			return err
		}
		if !s.initialized {
			return nil
		}
		initialized = true
		kr, err = validate(ctx, tx, s, w)
		return err
	})
	if err != nil || initialized {
		return kr, err
	}
	return initialize(ctx, db, w, now)
}

// initialize creates the first key of a keyring that is provably new, under
// the keyring row's FOR UPDATE lock. A caller that finds the keyring already
// initialized once it holds the lock lost a race to another process and
// loads that keyring instead.
func initialize(ctx context.Context, db TxBeginner, w Wrapper, now time.Time) (Keyring, error) {
	var kr Keyring
	err := inTx(ctx, db, func(tx pgx.Tx) error {
		s, err := readSingleton(ctx, tx, "FOR UPDATE")
		if err != nil {
			return err
		}
		if s.initialized {
			// Another process initialized it first.
			kr, err = validate(ctx, tx, s, w)
			return err
		}
		if err := checkNew(ctx, tx); err != nil {
			return err
		}
		material := make([]byte, KeySize)
		if _, err := rand.Read(material); err != nil {
			return fmt.Errorf("fingerprint: generate key: %w", err)
		}
		wrapped, err := w.Encrypt(material)
		if err != nil {
			return fmt.Errorf("fingerprint: wrap key: %w", err)
		}
		id := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO credprotect_fingerprint_keys (id, wrapped, is_current, created_at)
			VALUES ($1, $2, true, $3)`, id, wrapped, now); err != nil {
			return fmt.Errorf("fingerprint: store key: %w", err)
		}
		gen := s.generation + 1
		if _, err := tx.Exec(ctx, `UPDATE credprotect_keyring SET initialized_at = $1, generation = $2
			WHERE singleton`, now, gen); err != nil {
			return fmt.Errorf("fingerprint: initialize keyring: %w", err)
		}
		kr = Keyring{Generation: gen, keys: []key{{id: id, material: material, current: true}},
			digest: digestOf([]storedKey{{id: id, wrapped: wrapped, current: true}})}
		return nil
	})
	return kr, err
}

// Report describes a validated keyring for an operator. It never holds key
// material.
type Report struct {
	Keys       int
	Generation int64
	WrapEpoch  int64
	// AlreadyRewrapped: Rewrap found every key already wrapped with the
	// new key and changed nothing.
	AlreadyRewrapped bool
}

// Verify checks that the keyring is initialized, structurally sound and
// readable with w, the active credential encryption key. It changes
// nothing. An uninitialized keyring is reported as such, not as success.
func Verify(ctx context.Context, db TxBeginner, w Wrapper) (Report, error) {
	var rep Report
	err := inTx(ctx, db, func(tx pgx.Tx) error {
		s, err := readSingleton(ctx, tx, "FOR SHARE")
		if err != nil {
			return err
		}
		if !s.initialized {
			if err := checkNew(ctx, tx); err != nil {
				return err
			}
			return unavailable(CauseNotInitialized, "the keyring has not been initialized")
		}
		kr, err := validate(ctx, tx, s, w)
		if err != nil {
			return err
		}
		rep = Report{Keys: len(kr.keys), Generation: s.generation, WrapEpoch: s.wrapEpoch}
		return nil
	})
	return rep, err
}

// Rewrap re-wraps every fingerprint key from previous to current, the
// credential encryption keys before and after a rotation. It is safe to
// run again: when every key already unwraps with current it reports that
// and changes nothing. The keys themselves never change, so recorded
// protection state keeps matching. Only the key rows and the keyring's
// wrap_epoch are written; protection state is read only to check that
// every identifier's key is present.
//
// Every path validates the keyring first: it must be initialized, hold at
// least one key with exactly one current, every identifier's key must be
// present, and every key must unwrap to 32 bytes. A keyring whose keys
// unwrap under neither key, or under different ones, is refused unchanged.
func Rewrap(ctx context.Context, db TxBeginner, previous, current Wrapper) (Report, error) {
	var rep Report
	var before []key
	err := inTx(ctx, db, func(tx pgx.Tx) error {
		s, err := readSingleton(ctx, tx, "FOR UPDATE")
		if err != nil {
			return err
		}
		if !s.initialized {
			if err := checkNew(ctx, tx); err != nil {
				return err
			}
			return unavailable(CauseNotInitialized, "the keyring has not been initialized; there is nothing to re-wrap")
		}
		keys, err := readKeys(ctx, tx)
		if err != nil {
			return err
		}
		if err := checkStructure(ctx, tx, keys); err != nil {
			return err
		}
		if done, unreadable := unwrapAll(keys, current); unreadable == 0 {
			if err := checkLengths(done); err != nil {
				return err
			}
			rep = Report{Keys: len(keys), Generation: s.generation, WrapEpoch: s.wrapEpoch, AlreadyRewrapped: true}
			return nil
		}
		old, unreadable := unwrapAll(keys, previous)
		if unreadable > 0 {
			_, unreadableNew := unwrapAll(keys, current)
			return unavailable(CauseUnwrap, "of %d key(s), %d unwrap with the new key and %d with the previous key; "+
				"a keyring must unwrap entirely under one of them", len(keys), len(keys)-unreadableNew, len(keys)-unreadable)
		}
		if err := checkLengths(old); err != nil {
			return err
		}
		for _, k := range old {
			wrapped, err := current.Encrypt(k.material)
			if err != nil {
				return fmt.Errorf("fingerprint: wrap key %s: %w", k.id, err)
			}
			if _, err := tx.Exec(ctx, `UPDATE credprotect_fingerprint_keys SET wrapped = $1 WHERE id = $2`,
				wrapped, k.id); err != nil {
				return fmt.Errorf("fingerprint: store key %s: %w", k.id, err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE credprotect_keyring SET wrap_epoch = wrap_epoch + 1 WHERE singleton`); err != nil {
			return fmt.Errorf("fingerprint: record re-wrap: %w", err)
		}
		before = old
		rep = Report{Keys: len(keys), Generation: s.generation, WrapEpoch: s.wrapEpoch + 1}
		return nil
	})
	if err != nil || rep.AlreadyRewrapped {
		return rep, err
	}
	// Committed. Read every key back with the new key and compare.
	after, err := Verify(ctx, db, current)
	if err != nil {
		return rep, fmt.Errorf("fingerprint: the re-wrap committed, but the keyring does not verify: %w", err)
	}
	var check []key
	err = inTx(ctx, db, func(tx pgx.Tx) error {
		keys, err := readKeys(ctx, tx)
		if err != nil {
			return err
		}
		check, _ = unwrapAll(keys, current)
		return nil
	})
	if err != nil {
		return rep, err
	}
	if !sameKeys(before, check) || after.Keys != len(before) {
		return rep, errors.New("fingerprint: the re-wrap committed, but the keys read back differ from those re-wrapped")
	}
	return rep, nil
}

func sameKeys(a, b []key) bool {
	if len(a) != len(b) {
		return false
	}
	byID := map[uuid.UUID][]byte{}
	for _, k := range a {
		byID[k.id] = k.material
	}
	for _, k := range b {
		m, ok := byID[k.id]
		if !ok || !hmac.Equal(m, k.material) {
			return false
		}
	}
	return true
}

func inTx(ctx context.Context, db TxBeginner, fn func(pgx.Tx) error) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("fingerprint: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
