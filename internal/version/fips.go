// FIPS reporting, sourced from the runtime rather than from a build flag.
//
// WHY THIS EXISTS: --version used to print the FIPS ldflag verbatim. That is a
// claim about how someone intended to build the binary, not a fact about the
// binary. `go build -ldflags "-X ...version.FIPS=true"` without GOFIPS140 set
// produces a binary that reports fips=true and contains no FIPS module at all.
// For a compliance product that is the worst possible failure: an auditor reads
// the claim off the box and it is false.
//
// Everything here is read from the running binary. FIPS is the ldflag, kept as
// a cross-check: when the two disagree the binary says so instead of choosing
// the flattering answer.
package version

import (
	"crypto/fips140"
	"os"
	"runtime/debug"
	"strings"
)

// FIPSEnabled reports whether the FIPS 140-3 module is active in this binary,
// as the crypto runtime sees it. This is the authoritative answer.
func FIPSEnabled() bool {
	return fips140.Enabled()
}

// FIPSModule returns the FIPS module build tag linked into the binary, for
// example "fips140v1.0", or "" when no module is linked. Read from build info,
// so it reflects what GOFIPS140 actually selected at link time.
func FIPSModule() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key != "-tags" {
			continue
		}
		for _, tag := range strings.Split(s.Value, ",") {
			if strings.HasPrefix(tag, "fips140") {
				return tag
			}
		}
	}
	return ""
}

// FIPSMode returns the active enforcement mode: "off", "on", or "only".
//
// The distinction matters operationally, not just cosmetically. In "only" mode
// the Go crypto runtime refuses every algorithm outside the validated set, and
// golang.org/x/crypto/ssh cannot complete a handshake because its AES-GCM path
// uses arbitrary IVs. An OpenWatch reaching for maximum assurance by setting
// fips140=only loses the ability to scan any host, so the mode has to be
// visible rather than inferred.
//
// A GODEBUG environment setting overrides the value baked in at build time,
// which is why both are consulted in that order.
func FIPSMode() string {
	if m := fips140Setting(os.Getenv("GODEBUG")); m != "" {
		return m
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "DefaultGODEBUG" {
				if m := fips140Setting(s.Value); m != "" {
					return m
				}
			}
		}
	}
	if FIPSEnabled() {
		return "on"
	}
	return "off"
}

// fips140Setting extracts the fips140 value from a GODEBUG-style
// comma-separated list, returning "" when the key is absent. The last
// occurrence wins, matching the runtime's own precedence.
func fips140Setting(godebug string) string {
	out := ""
	for _, kv := range strings.Split(godebug, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(kv), "=")
		if found && k == "fips140" {
			out = v
		}
	}
	return out
}

// FIPSClaimMismatch reports whether the build-time FIPS ldflag disagrees with
// the runtime. True means the binary was labelled FIPS but has no active
// module, or the reverse. Callers surface this loudly: a mislabelled binary is
// worse than an unlabelled one, because it is trusted.
func FIPSClaimMismatch() bool {
	return (FIPS == "true") != FIPSEnabled()
}
