package license

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Watermark reads the persisted clock-rollback watermark.
//
// A missing row is not an error: it is a deployment that has never recorded
// one, which is the correct state on a first boot. The zero time it returns
// makes Verify skip the rollback check, per C-11.
func Watermark(ctx context.Context, pool *pgxpool.Pool) (time.Time, error) {
	var t time.Time
	err := pool.QueryRow(ctx,
		`SELECT observed_at FROM license_clock_watermark WHERE id = TRUE`).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// AdvanceWatermark records now as the highest wall-clock time this deployment
// has observed. It is a RATCHET and never moves the stored value backwards.
//
// The monotonicity lives in the SQL, not in a read-then-write in Go, so two
// processes advancing at once cannot interleave into a lost update. `serve`
// and a standalone `worker` both load licenses and both call this.
//
// GREATEST is what makes it safe. Verify tolerates an hour of backwards drift,
// so a clock wound back 59 minutes still verifies; writing that reading back
// would drop the watermark by 59 minutes, and repeating it would walk the
// watermark down without a single check ever failing. See C-13.
func AdvanceWatermark(ctx context.Context, pool *pgxpool.Pool, now time.Time) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO license_clock_watermark (id, observed_at, updated_at)
		VALUES (TRUE, $1, NOW())
		ON CONFLICT (id) DO UPDATE
		SET observed_at = GREATEST(license_clock_watermark.observed_at, EXCLUDED.observed_at),
		    updated_at  = NOW()`, now)
	return err
}
