package credprotect

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
)

// checkKeyring refuses a password unless the fingerprint keyring, read FOR
// SHARE inside the caller's transaction, is the one its aliases were
// computed from (spec C-16). The keyring must be initialized and hold
// exactly one current key (so at least one key); otherwise it is
// unavailable. Its snapshot (generation and a digest of every key row)
// must equal the password's, and every alias must name a key the keyring
// holds; otherwise the keyring changed since the aliases were computed. A
// keyring change locks the row FOR UPDATE, so it never overlaps the
// operation. A key secret is not identified through the keyring and
// passes.
func checkKeyring(ctx context.Context, tx pgx.Tx, s Secret) error {
	if s.Kind != SecretPassword {
		return nil
	}
	st, err := fingerprint.ReadState(ctx, tx)
	if errors.Is(err, fingerprint.ErrUnavailable) {
		return fmt.Errorf("%w: %v", ErrKeyringUnavailable, err)
	}
	if err != nil {
		return fmt.Errorf("credprotect: read keyring: %w", err)
	}
	switch {
	case !st.Initialized:
		return fmt.Errorf("%w: the keyring is not initialized", ErrKeyringUnavailable)
	case st.Current != 1:
		return fmt.Errorf("%w: the keyring has %d current keys, not one", ErrKeyringUnavailable, st.Current)
	case st.Snapshot != s.Keyring:
		return fmt.Errorf("%w: the keyring is not the one the password was identified with", ErrKeyringChanged)
	}
	for _, a := range s.Aliases {
		if !st.KeyIDs[a.KeyID] {
			return fmt.Errorf("%w: an alias names a key the keyring does not hold", ErrKeyringChanged)
		}
	}
	return nil
}

// lockKeyringShared takes the keyring row FOR SHARE without checking it.
// Recording an outcome serializes with keyring changes this way, but is
// never refused for an old or damaged keyring: a restriction, or a late
// outcome, must still be recorded (spec C-16).
func lockKeyringShared(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM credprotect_keyring WHERE singleton FOR SHARE`); err != nil {
		return fmt.Errorf("credprotect: lock keyring: %w", err)
	}
	return nil
}
