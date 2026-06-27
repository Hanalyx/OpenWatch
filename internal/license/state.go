package license

import (
	"sync/atomic"
	"time"
)

// Package-level state pointer. Hot-path reads (IsEnabled) load from this
// atomic with zero allocation. Load and Reload swap it atomically; readers
// see either old or new state, never partial.
var (
	current atomic.Pointer[State]
	keyring atomic.Pointer[publicKeyRing]
)

// IsEnabled is the hot-path check used by the RequireFeature middleware
// and direct feature checks throughout the codebase. Returns whether the
// running deployment has the given feature available right now.
//
// Free-tier features are always enabled. Non-free features require a
// loaded license that grants them.
//
// p99 < 50ns; no allocation. Spec AC-8, AC-9.
func IsEnabled(f Feature) bool {
	// Local-dev bypass: only ever true in `-tags dev` builds with
	// OPENWATCH_DEV_MODE=true (see entitlements_{dev,release}.go). Always false
	// in release binaries — the bypass code is not compiled in.
	if devEntitlementsEnabled() {
		return true
	}
	s := current.Load()
	return s.IsEnabled(f)
}

// CurrentState returns the loaded state pointer. May be nil before any
// Load call (boot ordering bug if so). Callers MUST NOT mutate the
// returned struct; create a new State and swap via setState if updating.
func CurrentState() *State {
	return current.Load()
}

// setState replaces the active state atomically. Called by Load and
// Reload.
func setState(s *State) {
	// Build the enabled map from the license's feature list combined with
	// every free-tier feature from the registry. Lookup becomes O(1).
	enabled := make(map[Feature]bool, len(FeatureRegistry))
	for f, meta := range FeatureRegistry {
		if meta.Tier == TierFree {
			enabled[f] = true
		}
	}
	if s.License != nil {
		for _, f := range s.License.Features {
			enabled[f] = true
		}
	}
	s.enabled = enabled
	current.Store(s)
}

// Reset clears the active license state back to the free-tier baseline
// and wipes the LastKnownGood watermark. This is the in-process equivalent
// of "deleting the license file and re-running boot." Used by tests that
// install a license and need a clean slate for the next subtest, and by
// the admin endpoint that uninstalls a license.
//
// Safe to call concurrently with IsEnabled — the underlying swap is atomic.
func Reset() {
	setState(&State{LoadedAt: time.Now()})
}

// setKeyring is called once at package init from service.Init.
func setKeyring(ring *publicKeyRing) {
	keyring.Store(ring)
}

// activeKeyring returns the currently-active keyring; nil before Init.
func activeKeyring() *publicKeyRing {
	return keyring.Load()
}
