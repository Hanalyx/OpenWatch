// @spec release-fips-build
//
//	AC-09  TestFIPS_ReportedFromRuntimeNotBuildFlag
//	AC-10  TestFIPS_OnlyModeIsFlaggedUnsafe
package version

import (
	"crypto/fips140"
	"strings"
	"testing"
)

// @ac AC-09
// AC-09: the FIPS report is measured, not declared.
//
// This test runs under whichever toolchain mode the suite was invoked with, so
// it asserts the INVARIANT (report agrees with the crypto runtime) rather than
// a fixed value. `make test` and `GOFIPS140=v1.0.0 go test` therefore both
// exercise it, and a build that lies is caught either way.
func TestFIPS_ReportedFromRuntimeNotBuildFlag(t *testing.T) {
	t.Run("release-fips-build/AC-09", func(t *testing.T) {
		if FIPSEnabled() != fips140.Enabled() {
			t.Errorf("FIPSEnabled() = %t, crypto/fips140.Enabled() = %t; the report "+
				"must mirror the runtime", FIPSEnabled(), fips140.Enabled())
		}

		// The module tag is present exactly when a module is linked. A build
		// claiming FIPS with no tag is the mislabelled case this guards.
		mod := FIPSModule()
		if FIPSEnabled() && mod == "" {
			t.Error("FIPS is enabled but FIPSModule() is empty; the linked module " +
				"tag should be readable from build info")
		}
		if mod != "" && !strings.HasPrefix(mod, "fips140") {
			t.Errorf("FIPSModule() = %q, want a fips140* build tag", mod)
		}

		// Mode is constrained to the three the runtime defines, and must be
		// off exactly when FIPS is inactive.
		switch m := FIPSMode(); m {
		case "off":
			if FIPSEnabled() {
				t.Error(`FIPSMode() = "off" while FIPS is enabled`)
			}
		case "on", "only":
			if !FIPSEnabled() {
				t.Errorf("FIPSMode() = %q while FIPS is disabled", m)
			}
		default:
			t.Errorf("FIPSMode() = %q, want off, on, or only", m)
		}
	})
}

// @ac AC-09
// AC-09 (parser): GODEBUG parsing, asserted directly so the precedence rules
// are pinned without needing to relaunch the process under each setting.
func TestFIPS_GodebugParsing(t *testing.T) {
	t.Run("release-fips-build/AC-09", func(t *testing.T) {
		cases := []struct {
			godebug string
			want    string
		}{
			{"", ""},
			{"fips140=on", "on"},
			{"fips140=only", "only"},
			{"http2debug=1,fips140=only", "only"},
			{"fips140=only,http2debug=1", "only"},
			{" fips140=on , other=2 ", "on"},
			{"notfips140=only", ""},
			// Last occurrence wins, matching the runtime.
			{"fips140=on,fips140=only", "only"},
		}
		for _, c := range cases {
			if got := fips140Setting(c.godebug); got != c.want {
				t.Errorf("fips140Setting(%q) = %q, want %q", c.godebug, got, c.want)
			}
		}
	})
}

// @ac AC-10
// AC-10: "only" is a recognised mode and is treated as unsafe rather than as
// the strictest good option.
//
// The empirical basis: a FIPS-built SSH client connecting to a real host
// succeeds at fips140=on and fails at fips140=only with "crypto/cipher: use of
// GCM with arbitrary IVs is not allowed in FIPS 140-only mode". The failure is
// in golang.org/x/crypto/ssh, not in OpenWatch, so it cannot be fixed here and
// has to be surfaced. An operator choosing "only" for maximum assurance would
// otherwise silently lose scanning against every host.
func TestFIPS_OnlyModeIsFlaggedUnsafe(t *testing.T) {
	t.Run("release-fips-build/AC-10", func(t *testing.T) {
		if got := fips140Setting("fips140=only"); got != "only" {
			t.Fatalf("fips140Setting could not detect only mode, got %q", got)
		}
		// C-05 claims the two binaries are functionally identical. That holds
		// for the diagnostic echo path it names, and does NOT hold across FIPS
		// modes. This assertion exists so the mode stays distinguishable: the
		// warning in printVersion depends on telling "only" from "on".
		if fips140Setting("fips140=on") == fips140Setting("fips140=only") {
			t.Error("on and only must be distinguishable; the --version warning " +
				"and the supported-configuration claim both depend on it")
		}
	})
}
