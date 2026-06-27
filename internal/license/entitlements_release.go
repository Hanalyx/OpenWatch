//go:build !dev

package license

// devEntitlementsEnabled reports whether the local-dev entitlement bypass is
// active. In release builds (the default — no `dev` build tag) it is always
// false: the bypass is physically absent from shipped binaries, so a production
// install can never unlock paid features without a real license, regardless of
// environment. The dev variant lives in entitlements_dev.go (built only under
// `-tags dev`).
func devEntitlementsEnabled() bool { return false }
