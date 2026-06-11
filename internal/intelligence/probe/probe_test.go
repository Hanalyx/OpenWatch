// @spec system-host-discovery
//
// AC traceability (this file):
//
//	AC-01  TestParseOSRelease_RHEL9
//	AC-02  TestParseOSRelease_Ubuntu24
//	AC-03  TestParseUname
//	AC-04  TestParseMemInfo

package probe

import (
	"strings"
	"testing"
)

// @ac AC-01
// AC-01: RHEL 9.4 os-release → typed OSFacts.
func TestParseOSRelease_RHEL9(t *testing.T) {
	t.Run("system-host-discovery/AC-01", func(t *testing.T) {
		const sample = `NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"`
		got, err := ParseOSRelease([]byte(sample))
		if err != nil {
			t.Fatalf("ParseOSRelease: %v", err)
		}
		if got.OSName != "Red Hat Enterprise Linux" {
			t.Errorf("OSName=%q, want \"Red Hat Enterprise Linux\"", got.OSName)
		}
		if got.OSVersion != "9.4" {
			t.Errorf("OSVersion=%q, want \"9.4\"", got.OSVersion)
		}
		if got.OSID != "rhel" {
			t.Errorf("OSID=%q, want \"rhel\"", got.OSID)
		}
		if got.OSIDLike != "fedora" {
			t.Errorf("OSIDLike=%q, want \"fedora\"", got.OSIDLike)
		}
		if got.OSPrettyName != "Red Hat Enterprise Linux 9.4 (Plow)" {
			t.Errorf("OSPrettyName=%q, unexpected", got.OSPrettyName)
		}
		if got.PlatformIdentifier != "platform:el9" {
			t.Errorf("PlatformIdentifier=%q, want \"platform:el9\"", got.PlatformIdentifier)
		}
	})
}

// @ac AC-02
// AC-02: Ubuntu 24.04 os-release → typed OSFacts; parser handles both
// distro family conventions interchangeably.
func TestParseOSRelease_Ubuntu24(t *testing.T) {
	t.Run("system-host-discovery/AC-02", func(t *testing.T) {
		const sample = `PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo`
		got, err := ParseOSRelease([]byte(sample))
		if err != nil {
			t.Fatalf("ParseOSRelease: %v", err)
		}
		if got.OSName != "Ubuntu" {
			t.Errorf("OSName=%q, want \"Ubuntu\"", got.OSName)
		}
		if got.OSVersion != "24.04" {
			t.Errorf("OSVersion=%q, want \"24.04\"", got.OSVersion)
		}
		if got.OSVersionFull != "24.04.3 LTS (Noble Numbat)" {
			t.Errorf("OSVersionFull=%q, unexpected", got.OSVersionFull)
		}
		if got.OSID != "ubuntu" {
			t.Errorf("OSID=%q, want \"ubuntu\"", got.OSID)
		}
		if got.OSIDLike != "debian" {
			t.Errorf("OSIDLike=%q, want \"debian\"", got.OSIDLike)
		}
		// Unquoted values must work (Ubuntu omits quotes on ID).
		if strings.Contains(got.OSID, `"`) {
			t.Errorf("OSID has leftover quote chars: %q", got.OSID)
		}
	})
}

// @ac AC-03
// AC-03: uname -srvm output → KernelName / KernelRelease / KernelVersion / Architecture.
func TestParseUname(t *testing.T) {
	t.Run("system-host-discovery/AC-03", func(t *testing.T) {
		const sample = `Linux 5.14.0-362.el9.x86_64 #1 SMP PREEMPT_DYNAMIC Wed Aug 23 19:16:43 UTC 2025 x86_64`
		got, err := ParseUname([]byte(sample))
		if err != nil {
			t.Fatalf("ParseUname: %v", err)
		}
		if got.KernelName != "Linux" {
			t.Errorf("KernelName=%q, want \"Linux\"", got.KernelName)
		}
		if got.KernelRelease != "5.14.0-362.el9.x86_64" {
			t.Errorf("KernelRelease=%q, want \"5.14.0-362.el9.x86_64\"", got.KernelRelease)
		}
		if got.Architecture != "x86_64" {
			t.Errorf("Architecture=%q, want \"x86_64\"", got.Architecture)
		}
		// Sanity: KernelVersion captures the long middle, includes "SMP".
		if !strings.Contains(got.KernelVersion, "SMP") {
			t.Errorf("KernelVersion=%q, expected to include kernel build details", got.KernelVersion)
		}
	})
}

// @ac AC-04
// AC-04: /proc/meminfo → MemTotal / MemAvailable / SwapTotal as MB-rounded
// integers. Missing SwapTotal must yield zero, not error.
func TestParseMemInfo(t *testing.T) {
	t.Run("system-host-discovery/AC-04", func(t *testing.T) {
		// Realistic /proc/meminfo head (kB-suffixed values).
		const sample = `MemTotal:        8011028 kB
MemFree:          234188 kB
MemAvailable:    3567812 kB
Buffers:          124456 kB
Cached:          2145332 kB
SwapTotal:       4194300 kB
SwapFree:        4194300 kB`
		got, err := ParseMemInfo([]byte(sample))
		if err != nil {
			t.Fatalf("ParseMemInfo: %v", err)
		}
		// 8011028 kB → 7823 MB (integer division by 1024).
		if got.MemTotalMB != 8011028/1024 {
			t.Errorf("MemTotalMB=%d, want %d", got.MemTotalMB, 8011028/1024)
		}
		if got.MemAvailableMB != 3567812/1024 {
			t.Errorf("MemAvailableMB=%d, want %d", got.MemAvailableMB, 3567812/1024)
		}
		if got.SwapTotalMB != 4194300/1024 {
			t.Errorf("SwapTotalMB=%d, want %d", got.SwapTotalMB, 4194300/1024)
		}

		// Swap-disabled host has no SwapTotal line at all.
		const noSwap = `MemTotal:        1019728 kB
MemFree:          112340 kB
MemAvailable:     901248 kB`
		got2, err := ParseMemInfo([]byte(noSwap))
		if err != nil {
			t.Fatalf("ParseMemInfo (no swap): %v", err)
		}
		if got2.SwapTotalMB != 0 {
			t.Errorf("SwapTotalMB=%d on swap-disabled host, want 0", got2.SwapTotalMB)
		}
	})
}
