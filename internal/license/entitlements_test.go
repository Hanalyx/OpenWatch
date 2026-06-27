//go:build !dev

package license

import "testing"

// TestDevEntitlements_OffInReleaseBuilds is a release-safety guard. The default
// build carries no `dev` tag, so the dev entitlement bypass MUST be off even
// with OPENWATCH_DEV_MODE set — otherwise a release binary could unlock paid
// features from the environment alone. This runs in normal CI (no -tags dev) and
// fails if the release variant ever starts returning true.
func TestDevEntitlements_OffInReleaseBuilds(t *testing.T) {
	t.Setenv("OPENWATCH_DEV_MODE", "true")
	if devEntitlementsEnabled() {
		t.Fatal("dev entitlement bypass is active in a non-dev build; it must be physically absent from release binaries")
	}
}
