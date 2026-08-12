package license

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
)

// Init wires the package: loads embedded public keys and installs a
// no-license (free-tier) initial state. Must be called once at boot
// before any Load attempt. Subsequent calls are no-ops.
//
// Returns an error only if the embedded keys are missing or unparseable
// (build error — should never happen in a compiled binary).
func Init() error {
	initOnce.Do(func() {
		ring, err := loadEmbeddedKeys()
		if err != nil {
			initErr = err
			return
		}
		setKeyring(ring)

		// Install the free-tier baseline state. Operators get a working
		// service even without a license file.
		setState(&State{
			License:  nil,
			LoadedAt: time.Now(),
		})
	})
	return initErr
}

var (
	initOnce sync.Once
	initErr  error
)

// LoadFile reads a license file from disk, validates it, and (on success)
// swaps it into the runtime state. Missing file is non-fatal: state stays
// at the free-tier baseline (per AC-1).
//
// Spec AC-10: install + SIGHUP makes /api/v1/license reflect the new state
// without restart.
func LoadFile(path string, opts VerifyOptions) (VerifyResult, error) {
	if err := Init(); err != nil {
		return VerifyMalformedJWT, fmt.Errorf("license: init: %w", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No file: stay at free tier. Caller decides whether to alert.
			return VerifyValid, nil
		}
		return VerifyMalformedJWT, fmt.Errorf("license: read %s: %w", path, err)
	}

	jwtBlob := strings.TrimSpace(string(raw))
	return LoadJWT(jwtBlob, opts)
}

// LoadJWT validates a raw JWT string and swaps it into runtime state on
// success. Useful for tests and for installing a license JWT minted by the
// Hanalyx issuer (the product only verifies licenses; it never mints them).
func LoadJWT(jwtBlob string, opts VerifyOptions) (VerifyResult, error) {
	if err := Init(); err != nil {
		return VerifyMalformedJWT, err
	}

	// Carry forward the watermark from current state if the caller did not
	// override it, so rollback detection survives a reload.
	prevLKG := time.Time{}
	if cur := current.Load(); cur != nil {
		prevLKG = cur.LastKnownGood
	}
	if opts.LastKnownGood.IsZero() {
		opts.LastKnownGood = prevLKG
	}

	lic, result, err := Verify(jwtBlob, activeKeyring(), opts)

	// Policy split: Verify reports what it found, the loader decides what to
	// do about it. A clock rollback WARNS and still loads (decision record 06).
	//
	// Withholding entitlement here would buy almost nothing. The watermark
	// lives in the customer's own PostgreSQL and the adversary has root on
	// that host, so anyone willing to move the clock can delete the row and
	// reset the check. What failing closed reliably produces instead is a
	// paying customer silently dropped to free tier after one clock-forward
	// accident, with a cause weeks in the past and a database row to delete
	// before it recovers.
	//
	// Re-verify with the watermark cleared rather than waving the license
	// through: every other check (signature, issuer, audience, iat skew, nbf,
	// expiry, fingerprint) must still pass on its own.
	if result == VerifyClockRollback {
		rollbackOpts := opts
		rollbackOpts.LastKnownGood = time.Time{}
		lic, result, err = Verify(jwtBlob, activeKeyring(), rollbackOpts)
		if result == VerifyValid && lic != nil {
			lic.ClockRollbackDetected = true
		}
	}

	if result != VerifyValid {
		// Don't replace the active state on failure: keep the previous
		// license active (or free tier). Audit emission is the caller's
		// responsibility (audit.go helpers).
		return result, err
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	setState(&State{
		License:  lic,
		LoadedAt: time.Now(),
		// The watermark is a RATCHET: it only ever moves forward.
		//
		// Stamping it to `now` unconditionally would let an attacker lower it.
		// Verify tolerates an hour of backwards drift, so a clock walked back
		// 59 minutes verifies, and writing that reading back would drop the
		// watermark by 59 minutes. Repeat and the watermark follows the clock
		// down without a single check ever failing, which defeats the whole
		// mechanism. Taking the max makes each step a no-op instead.
		//
		// Ratchet against BOTH baselines, not just the in-process one. On a
		// fresh boot prevLKG is zero while opts.LastKnownGood holds the value
		// read from the database, so measuring only prevLKG lets a rollback
		// load store a time behind the persisted watermark. The next SIGHUP
		// then reloads with empty options, sees the lowered in-memory value,
		// finds no rollback, and the warning disappears: reloading the license
		// would clear the alert without anything being fixed.
		LastKnownGood: laterOf(nowFn(), laterOf(prevLKG, opts.LastKnownGood)),
	})
	return VerifyValid, nil
}

// laterOf returns whichever time is not earlier. Used to advance the
// clock-rollback watermark without ever moving it backwards.
func laterOf(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

// VerifyOnly parses + validates without installing. Used by
// /admin/license:verify so operators can dry-run before commit.
func VerifyOnly(jwtBlob string, opts VerifyOptions) (*License, VerifyResult, error) {
	if err := Init(); err != nil {
		return nil, VerifyMalformedJWT, err
	}
	if opts.LastKnownGood.IsZero() {
		if cur := current.Load(); cur != nil {
			opts.LastKnownGood = cur.LastKnownGood
		}
	}
	return Verify(jwtBlob, activeKeyring(), opts)
}
