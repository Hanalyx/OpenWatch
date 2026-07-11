// Package version exposes build-time metadata for the openwatch binary.
//
// All values are overridden via -ldflags at build time by the Makefile.
// The default values are used when building with bare `go build` (e.g.,
// during local development or in IDE-driven builds).
package version

import (
	"runtime"
	"runtime/debug"
)

// Build-time injected values. Default to placeholders that make it obvious
// when a binary was built without the Makefile.
var (
	// Version is the semver string (e.g., "0.1.0-dev").
	Version = "dev"

	// Commit is the abbreviated git commit hash.
	Commit = "unknown"

	// BuildTime is an ISO-8601 timestamp.
	BuildTime = "unknown"

	// FIPS is "true" when built with the microsoft/go FIPS toolchain (Day 12).
	FIPS = "false"
)

// kensaModulePath is the import path of the embedded compliance engine. Its
// version is not ldflags-injected; it is read from the module build info so it
// always reflects the Kensa actually linked in, never a hand-edited constant.
const kensaModulePath = "github.com/Hanalyx/kensa"

// Go returns the Go toolchain version the binary was built with, e.g.
// "go1.26.5". Sourced from the runtime, never hardcoded.
func Go() string {
	return runtime.Version()
}

// Kensa returns the version of the embedded Kensa engine module, read from the
// binary's build info (the version selected in go.mod at link time). Returns
// "unknown" when build info is unavailable (e.g. `go run` outside a module).
func Kensa() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == kensaModulePath {
			return dep.Version
		}
	}
	return "unknown"
}
