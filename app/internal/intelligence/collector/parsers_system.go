package collector

import (
	"bytes"
	"strings"
)

// ParseInstalledPackages parses RPM (`rpm -qa --queryformat='%{NAME} %{VERSION}-%{RELEASE}\n'`)
// OR DPKG (`dpkg -l`) output into a map[name]version.
//
// Family detection is implicit: RPM lines are exactly two
// whitespace-separated fields. DPKG lines start with a two-character
// status field ("ii", "rc", "iU", etc) followed by name + version +
// architecture.
//
// Empty input yields an empty map, not an error.
func ParseInstalledPackages(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range bytes.Split(b, []byte("\n")) {
		line := strings.TrimRight(string(raw), " \t\r")
		if line == "" {
			continue
		}
		// Skip dpkg header decoration ("Desired=Unknown...", "+++=...", etc).
		if strings.HasPrefix(line, "Desired=") ||
			strings.HasPrefix(line, "| ") ||
			strings.HasPrefix(line, "|/ ") ||
			strings.HasPrefix(line, "||/ ") ||
			strings.HasPrefix(line, "+++") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// DPKG: first field is the status ("ii" = installed). RPM never
		// produces a two-character first field — it's the package name,
		// which is always longer than 2 chars for real packages.
		if len(fields) >= 4 && isDpkgStatus(fields[0]) {
			// "ii  name  version  arch  description..."
			out[fields[1]] = fields[2]
			continue
		}
		// RPM: "name version-release". Could be 2 fields exactly.
		if len(fields) >= 2 {
			out[fields[0]] = fields[1]
		}
	}
	return out, nil
}

// isDpkgStatus matches the two-character status column on `dpkg -l`
// output lines. Common values: "ii" (installed), "rc" (config-only),
// "iU" (mid-install), "iF" (failed config), "hi" (held installed).
func isDpkgStatus(s string) bool {
	if len(s) != 2 {
		return false
	}
	// Char 1: i (install), r (remove), p (purge), h (hold), u (unknown).
	switch s[0] {
	case 'i', 'r', 'p', 'h', 'u':
	default:
		return false
	}
	// Char 2: i (installed), c (config), U (unpacked), F (failed-cfg),
	// H (half-installed), W (trigger-await), T (trigger-pend), n (not-installed).
	switch s[1] {
	case 'i', 'c', 'U', 'F', 'H', 'W', 'T', 'n', 'R':
		return true
	}
	return false
}
