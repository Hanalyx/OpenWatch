// Package credprotect decides whether a secret may be sent to a host. It owns
// identities and their lineage, the restrictions that apply to a secret on
// an identity, one durable reservation per identity, the fence run just
// before a secret reaches a transport, and the conditional settlement of
// each submission's outcome. It sends nothing itself.
//
// Callers reserve before any network I/O, fence immediately before handing
// the secret to the transport, and settle afterwards:
//
//	sub, err := store.Reserve(ctx, req)      // refused: send nothing
//	err = store.Fence(ctx, sub.ID, current)  // refused: send nothing
//	... one submission ...
//	_, err = store.Settle(ctx, sub.ID, outcome)
//
// If the store cannot be reached, Reserve fails and the caller must not dial.
//
// Every write takes the username's lock first (lockUsername). All identities
// for one username share a root, so that one lock serializes every decision
// that could interact, and a single lock order rules out deadlock.
//
// Spec system-credential-protection; features/OW-122, contract r2, slice 3.
package credprotect

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Scope is how a credential's account is identified.
type Scope string

const (
	ScopeUnconfirmed Scope = "unconfirmed"
	ScopeLocal       Scope = "local"
	ScopeDirectory   Scope = "directory"
)

// SecretKind is a password or an SSH key.
type SecretKind string

const (
	SecretPassword SecretKind = "password" // pragma: allowlist secret
	SecretKey      SecretKind = "key"      // pragma: allowlist secret
)

// IDLen is the length of a secret identifier.
const IDLen = 32

// Alias is one identifier of a secret: the id of the key that derived it,
// and the identifier itself. For an SSH key the identifier is the SHA-256 of
// the public key and KeyID is empty. For a password it is a keyed
// fingerprint; deriving it is slice 2, which may give one password several
// aliases during a key rotation.
type Alias struct {
	KeyID string
	ID    [IDLen]byte
}

// Secret identifies a secret by kind and aliases. Two secrets are the same
// when their kinds match and any alias matches. The first alias is the one
// recorded on new rows.
type Secret struct {
	Kind    SecretKind
	Aliases []Alias
}

// String never reveals an identifier: an identifier is a sensitive equality
// value (spec C-03).
func (s Secret) String() string { return fmt.Sprintf("%s secret", s.Kind) }

// GoString keeps %#v from printing the aliases.
func (s Secret) GoString() string { return s.String() }

func (s Secret) valid() error {
	if s.Kind != SecretPassword && s.Kind != SecretKey {
		return fmt.Errorf("credprotect: unknown secret kind %q", s.Kind)
	}
	if len(s.Aliases) == 0 {
		return errors.New("credprotect: secret has no identifier")
	}
	return nil
}

func (s Secret) primary() Alias { return s.Aliases[0] }

// matches reports whether a stored (kind, key id, id) is this secret.
func (s Secret) matches(kind string, keyID string, id []byte) bool {
	if kind != string(s.Kind) {
		return false
	}
	for _, a := range s.Aliases {
		if a.KeyID == keyID && subtle.ConstantTimeCompare(a.ID[:], id) == 1 {
			return true
		}
	}
	return false
}

// Same reports whether two secrets are the same secret.
func (s Secret) Same(o Secret) bool {
	for _, a := range o.Aliases {
		if s.matches(string(o.Kind), a.KeyID, a.ID[:]) {
			return true
		}
	}
	return false
}

// Kind is what a submission is for.
type Kind string

const (
	KindOrdinary     Kind = "ordinary"
	KindVerification Kind = "verification"
)

// Mode is what may be reserved for a secret on an identity.
type Mode string

const (
	ModePaused    Mode = "PAUSED"
	ModeBlocked   Mode = "BLOCKED"
	ModeVerifying Mode = "VERIFYING"
	ModeActive    Mode = "ACTIVE"
)

// Outcome is how a submission ended. Contract r2 section 7.
type Outcome string

const (
	OutcomeVerified           Outcome = "verified"
	OutcomeRejected           Outcome = "rejected"
	OutcomeUnsuccessful       Outcome = "unsuccessful"
	OutcomeUnknown            Outcome = "unknown"
	OutcomeAmbiguous          Outcome = "ambiguous"
	OutcomeUnsupportedProfile Outcome = "unsupported_profile"
	OutcomeNotSubmitted       Outcome = "not_submitted"
	OutcomeLocalDecryptFailed Outcome = "local_decrypt_failed"
)

func (o Outcome) valid() bool {
	switch o {
	case OutcomeVerified, OutcomeRejected, OutcomeUnsuccessful, OutcomeUnknown, OutcomeAmbiguous,
		OutcomeUnsupportedProfile, OutcomeNotSubmitted, OutcomeLocalDecryptFailed:
		return true
	}
	return false
}

// restrictive reports whether an outcome blocks the secret: it may have
// consumed the account's failure budget.
func (o Outcome) restrictive() bool {
	switch o {
	case OutcomeRejected, OutcomeUnsuccessful, OutcomeUnknown, OutcomeAmbiguous, OutcomeUnsupportedProfile:
		return true
	}
	return false
}

// Owner identifies the process that holds a reservation, so a slot can be
// released when that process is verified gone.
type Owner struct {
	Machine string
	PID     int
	Start   string
}

// Clock is the time source. Tests control it.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Processes answers whether a process still exists on this machine.
type Processes interface {
	// Machine identifies this machine, as recorded in Owner.Machine.
	Machine() string
	// Alive reports whether a process with this PID and start time exists.
	Alive(pid int, start string) (bool, error)
}

// TxBeginner starts a transaction. *pgxpool.Pool satisfies it.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Store is the protection state, kept in PostgreSQL.
type Store struct {
	db    TxBeginner
	clock Clock
	procs Processes
}

// Option configures a Store.
type Option func(*Store)

// WithClock sets the time source.
func WithClock(c Clock) Option { return func(s *Store) { s.clock = c } }

// WithProcesses sets how process liveness is checked.
func WithProcesses(p Processes) Option { return func(s *Store) { s.procs = p } }

// New returns a Store over db.
func New(db TxBeginner, opts ...Option) *Store {
	s := &Store{db: db, clock: systemClock{}, procs: LocalProcesses{}}
	for _, o := range opts {
		o(s)
	}
	return s
}

// K is the number of submissions an identity may have holding a slot.
const K = 1

// Cooldown is the least time between a non-verified verification and the
// next request for that secret. It is spacing, not a claim that the account
// has unlocked.
const Cooldown = 15 * time.Minute

// Errors. A refused call changes nothing.
var (
	ErrPaused          = errors.New("credprotect: paused")
	ErrBlocked         = errors.New("credprotect: blocked")
	ErrVerifying       = errors.New("credprotect: verification pending; ordinary work refused")
	ErrNotVerifying    = errors.New("credprotect: nothing to verify")
	ErrSlotBusy        = errors.New("credprotect: another submission holds the identity's slot")
	ErrCooldown        = errors.New("credprotect: cooldown applies")
	ErrAllowanceUsed   = errors.New("credprotect: verification allowance used for this secret")
	ErrFenceRefused    = errors.New("credprotect: fence refused")
	ErrOutcomeConflict = errors.New("credprotect: a different outcome is already recorded")
	ErrNotFound        = errors.New("credprotect: not found")
	ErrClassification  = errors.New("credprotect: classification refused")
	ErrOutstanding     = errors.New("credprotect: a submission is outstanding")
	ErrNotTerminated   = errors.New("credprotect: owner not verified ended")
	ErrOverride        = errors.New("credprotect: an override needs a reason and a confirmation")
	ErrInvalid         = errors.New("credprotect: invalid request")
)

// normalizeUsername is the identity key's username: trimmed, lower-case.
// Lower-casing can only merge accounts, which coordinates more, never less.
func normalizeUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

// lockUsername takes the username's lock until tx ends. Every write in this
// package takes it first.
func lockUsername(ctx context.Context, tx pgx.Tx, username string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"credprotect:"+username); err != nil {
		return fmt.Errorf("credprotect: lock: %w", err)
	}
	return nil
}

// inTx runs fn in a transaction and commits it if fn succeeds.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("credprotect: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("credprotect: commit: %w", err)
	}
	return nil
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }
