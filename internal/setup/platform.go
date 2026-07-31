// Platform detection for `openwatch setup`.
//
// WHY THIS EXISTS: setup writes to pg_hba.conf, installs packages, and enables
// services. Every one of those is distro-specific, and guessing wrong means
// writing to a path that belongs to something else. So the platform is
// detected once, carries a support tier, and gates the run: a distro CI does
// not cover is refused by default rather than approximated.
//
// The tier is deliberately three-valued. Claiming a support matrix that CI
// does not exercise is how documentation starts lying; refusing everything
// unrecognised would block the Rocky and Alma users who are, in practice,
// running the same paths as RHEL. "untested" says both things honestly: it
// runs with --allow-untested and reports itself in the receipt.
package setup

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Support states how much confidence the project has in a platform.
type Support string

const (
	// SupportTested means CI exercises this platform. v0.7.0: RHEL 9 only.
	SupportTested Support = "tested"
	// SupportUntested means the family is recognised and the paths are
	// believed correct, but nothing proves it. Requires --allow-untested.
	SupportUntested Support = "untested"
	// SupportUnsupported means setup will not run: unknown family, or a
	// version whose layout differs in ways this code does not model.
	SupportUnsupported Support = "unsupported"
)

// Family groups distributions that share package manager and file layout.
type Family string

const (
	FamilyRHEL    Family = "rhel"
	FamilyDebian  Family = "debian"
	FamilyUnknown Family = "unknown"
)

// Platform is the detected host. Every field is measured, never authored: a
// saved plan replayed on another machine re-detects and compares, so a plan
// captured on RHEL cannot be silently applied to Ubuntu.
type Platform struct {
	// ID is the os-release ID, e.g. "rhel", "rocky", "almalinux", "ubuntu".
	ID string `yaml:"id"`
	// VersionID is the os-release VERSION_ID, e.g. "9.8".
	VersionID string `yaml:"version_id"`
	// Major is VersionID's leading integer, e.g. 9. Zero when unparseable.
	Major int `yaml:"major"`
	// Family determines package manager and PostgreSQL layout.
	Family Family `yaml:"family"`
	// Arch is the Go architecture, e.g. "amd64".
	Arch string `yaml:"arch"`
	// Support gates the run.
	Support Support `yaml:"support"`
	// SELinux is "enforcing", "permissive", "disabled", or "" when absent.
	SELinux string `yaml:"selinux,omitempty"`
	// FIPS reports the kernel-level FIPS switch (/proc/sys/crypto/fips_enabled).
	FIPS bool `yaml:"fips"`
	// Fapolicyd reports whether the file-access policy daemon is active. It
	// blocks execution of anything absent from its trust database, which is
	// derived from the package database, so a non-packaged install is denied.
	Fapolicyd bool `yaml:"fapolicyd"`
}

// String renders the platform for a plan header.
func (p Platform) String() string {
	return fmt.Sprintf("%s %s (%s)", p.ID, p.VersionID, p.Arch)
}

// DetectPlatform reads the host's identity. It never fails: an unrecognised
// host is returned with Support unsupported so the caller reports it rather
// than a detection error the operator cannot act on.
func DetectPlatform() Platform {
	p := Platform{
		Arch:      runtime.GOARCH,
		Family:    FamilyUnknown,
		Support:   SupportUnsupported,
		SELinux:   detectSELinux(),
		FIPS:      detectKernelFIPS(),
		Fapolicyd: serviceActive("fapolicyd"),
	}
	osRelease := readOSRelease("/etc/os-release")
	p.ID = osRelease["ID"]
	p.VersionID = osRelease["VERSION_ID"]
	p.Major = majorOf(p.VersionID)
	p.Family = familyOf(p.ID, osRelease["ID_LIKE"])
	p.Support = supportOf(p.ID, p.VersionID, p.Major, p.Family)
	return p
}

// familyOf maps a distribution to its layout family, consulting ID_LIKE so a
// derivative that names its parent is placed correctly without this list
// needing to know every rebuild.
func familyOf(id, idLike string) Family {
	known := map[string]Family{
		"rhel": FamilyRHEL, "centos": FamilyRHEL, "rocky": FamilyRHEL,
		"almalinux": FamilyRHEL, "ol": FamilyRHEL, "oracle": FamilyRHEL,
		"fedora": FamilyRHEL,
		"debian": FamilyDebian, "ubuntu": FamilyDebian,
	}
	if f, ok := known[id]; ok {
		return f
	}
	for _, like := range strings.Fields(idLike) {
		if f, ok := known[like]; ok {
			return f
		}
	}
	return FamilyUnknown
}

// supportOf assigns the confidence tier.
//
// v0.7.0 ships with RHEL 9 tested and nothing else. The RHEL-family rebuilds
// at the same major are untested rather than unsupported because they share
// the paths this code uses; Debian-family is untested because the PostgreSQL
// layout genuinely differs (versioned clusters) and has not been exercised.
// versionID is carried alongside major because the Debian family needs it.
// "24" identifies no Ubuntu release: 24.04 is an LTS that CI installs on every
// push, and 24.10 is a different, interim release nobody has run. Matching on
// the major alone would extend a tested claim to a distribution the matrix
// never touches, which is the support statement starting to lie that C-10
// warns about. RHEL 9.x point releases are one product line and keep the
// coarser match.
func supportOf(id, versionID string, major int, family Family) Support {
	if family == FamilyUnknown || major == 0 {
		return SupportUnsupported
	}
	// Tested means a CI job installs here on every push and asserts the API
	// answers, not that someone tried it once. Each entry below corresponds
	// to a blocking platform in release/gates.toml.
	if id == "rhel" && major == 9 {
		return SupportTested
	}
	if id == "ubuntu" && versionID == "24.04" {
		return SupportTested
	}
	if id == "debian" && major == 12 {
		return SupportTested
	}
	// AlmaLinux 10, not the whole family's major 10. RHEL 10 has no image in
	// the matrix and no job, so it stays untested until one exists.
	if id == "almalinux" && major == 10 {
		return SupportTested
	}
	switch family {
	case FamilyRHEL:
		if major >= 8 && major <= 10 {
			return SupportUntested
		}
	case FamilyDebian:
		return SupportUntested
	}
	return SupportUnsupported
}

// readOSRelease parses the shell-fragment format of os-release. Values may be
// quoted; unquoting is done here so callers compare bare strings.
func readOSRelease(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out
}

// majorOf extracts the leading integer of a version string ("9.8" -> 9).
func majorOf(version string) int {
	major, _, _ := strings.Cut(version, ".")
	n := 0
	for _, r := range major {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	if major == "" {
		return 0
	}
	return n
}

// detectSELinux reports the current mode, or "" where SELinux is absent.
func detectSELinux() string {
	out, err := exec.Command("getenforce").Output()
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(out)))
}

// detectKernelFIPS reads the kernel FIPS switch. This is the system-wide
// setting, entirely separate from whether this binary was built with the Go
// FIPS module; a FIPS host running a non-FIPS binary is a real and dangerous
// combination, so setup reports both.
func detectKernelFIPS() bool {
	b, err := os.ReadFile("/proc/sys/crypto/fips_enabled")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// serviceActive reports whether a systemd unit is active, treating any error
// as inactive: absence of systemctl means absence of the service.
func serviceActive(unit string) bool {
	out, err := exec.Command("systemctl", "is-active", unit).Output()
	if err != nil && len(out) == 0 {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}
