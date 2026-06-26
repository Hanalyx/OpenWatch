//go:build !ee

// CE (community) build: no EE modules are compiled in. The capability registry
// in internal/eereg keeps its free-tier defaults, so every EE capability
// reports Available()=false and the core uses its free-core paths.
//
// The counterpart wire_ee.go (built with -tags ee) blank-imports the ee module,
// whose init registers licensed implementations into internal/eereg. This file
// is intentionally declaration-free — selecting it is the whole effect.
package main
