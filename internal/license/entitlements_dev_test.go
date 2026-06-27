//go:build dev

package license

import "testing"

// TestDevEntitlements_OnUnderDevTag verifies the local-dev bypass behaves as
// documented in `-tags dev` builds: gated on OPENWATCH_DEV_MODE, off by default,
// on when set. Compiled only under -tags dev (the launcher's build mode).
func TestDevEntitlements_OnUnderDevTag(t *testing.T) {
	t.Setenv("OPENWATCH_DEV_MODE", "")
	if devEntitlementsEnabled() {
		t.Fatal("bypass should be off when OPENWATCH_DEV_MODE is unset, even under -tags dev")
	}
	t.Setenv("OPENWATCH_DEV_MODE", "true")
	if !devEntitlementsEnabled() {
		t.Fatal("bypass should be on under -tags dev with OPENWATCH_DEV_MODE=true")
	}
}
