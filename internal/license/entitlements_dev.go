//go:build dev

package license

import "os"

// devEntitlementsEnabled reports whether the local-dev entitlement bypass is
// active. This variant is compiled ONLY into `-tags dev` builds (never
// released), and even then unlocks paid features only when OPENWATCH_DEV_MODE=true.
// Two independent gates — the build tag AND the env var — so paid features can be
// exercised locally (e.g. via scripts/openwatch.sh) without minting a license,
// while a release binary contains none of this code. Replaces the local use of
// the removed owlicgen tool.
func devEntitlementsEnabled() bool { return os.Getenv("OPENWATCH_DEV_MODE") == "true" }
