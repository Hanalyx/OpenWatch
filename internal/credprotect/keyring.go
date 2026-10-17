package credprotect

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// checkKeyring refuses a password whose aliases do not belong to the
// fingerprint keyring's current generation (spec C-16). It reads the
// keyring row FOR SHARE inside the caller's transaction, so a keyring
// change (initialization or re-wrap, which lock the row FOR UPDATE) never
// overlaps the operation. A key secret is not identified through the
// keyring and passes.
func checkKeyring(ctx context.Context, tx pgx.Tx, s Secret) error {
	if s.Kind != SecretPassword {
		return nil
	}
	var initialized bool
	var generation int64
	err := tx.QueryRow(ctx, `SELECT initialized_at IS NOT NULL, generation FROM credprotect_keyring
		WHERE singleton FOR SHARE`).Scan(&initialized, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: the keyring row does not exist", ErrKeyringUnavailable)
	}
	if err != nil {
		return fmt.Errorf("credprotect: read keyring: %w", err)
	}
	if !initialized {
		return fmt.Errorf("%w: the keyring is not initialized", ErrKeyringUnavailable)
	}
	if s.KeyringGeneration != generation {
		return fmt.Errorf("%w: aliases from generation %d, keyring at %d", ErrKeyringChanged, s.KeyringGeneration, generation)
	}
	return nil
}
