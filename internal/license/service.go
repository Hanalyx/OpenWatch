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
// success. Useful for tests and for owlicgen-driven local installs.
func LoadJWT(jwtBlob string, opts VerifyOptions) (VerifyResult, error) {
	if err := Init(); err != nil {
		return VerifyMalformedJWT, err
	}

	// Carry forward the LastKnownGood from current state if caller didn't
	// override (so clock-rollback detection works across reloads).
	if opts.LastKnownGood.IsZero() {
		if cur := current.Load(); cur != nil {
			opts.LastKnownGood = cur.LastKnownGood
		}
	}

	lic, result, err := Verify(jwtBlob, activeKeyring(), opts)
	if result != VerifyValid {
		// Don't replace the active state on failure — keep the previous
		// license active (or free tier). Audit emission is the caller's
		// responsibility (audit.go helpers).
		return result, err
	}

	newLKG := opts.Now
	if newLKG == nil {
		newLKG = time.Now
	}
	setState(&State{
		License:       lic,
		LoadedAt:      time.Now(),
		LastKnownGood: newLKG(),
	})
	return VerifyValid, nil
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
