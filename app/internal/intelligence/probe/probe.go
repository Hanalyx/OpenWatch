// Package probe holds pure parsers for the OS-fingerprint commands the
// Discovery service runs over SSH. Each parser takes the raw stdout bytes
// of a single command and returns a typed fact struct.
//
// Spec: app/specs/system/host-discovery.spec.yaml (C-01).
//
// Pure: no SSH dial, no database, no HTTP, no time.Now. Parsers are
// trivially testable with bytes fixtures (see probe_test.go).
package probe

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// OSFacts is the structured form of /etc/os-release. Field semantics
// follow the FHS/os-release standard; both RHEL-family (quoted values)
// and Debian-family (mixed quoting) input is accepted.
type OSFacts struct {
	OSName             string
	OSVersion          string // VERSION_ID, e.g. "9.4" or "24.04"
	OSVersionFull      string // VERSION, e.g. "9.4 (Plow)" or "24.04.3 LTS (Noble Numbat)"
	OSID               string
	OSIDLike           string
	OSPrettyName       string
	PlatformIdentifier string // PLATFORM_ID, e.g. "platform:el9"
}

// UnameFacts is the structured form of `uname -srvm` output.
// Layout per coreutils: KernelName KernelRelease KernelVersion Architecture
// where KernelVersion is the long middle that contains build metadata.
type UnameFacts struct {
	KernelName    string
	KernelRelease string
	KernelVersion string
	Architecture  string
}

// MemInfoFacts is the subset of /proc/meminfo OpenWatch surfaces. All
// fields are MB-rounded integers (kB / 1024 → MB). A field absent from
// the input yields zero, not an error — swap-disabled hosts have no
// SwapTotal line and must still parse cleanly (C-01, AC-04).
type MemInfoFacts struct {
	MemTotalMB     int
	MemAvailableMB int
	SwapTotalMB    int
}

// ParseOSRelease parses /etc/os-release contents into OSFacts.
//
// Each line is KEY=VALUE; VALUE may or may not be quoted. Unknown keys
// are ignored. Empty input returns zero-value OSFacts and a nil error
// (a host with no os-release file is rare but not a probe failure).
func ParseOSRelease(b []byte) (OSFacts, error) {
	out := OSFacts{}
	for _, raw := range bytes.Split(b, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = strings.Trim(val, `"'`)
		switch key {
		case "NAME":
			out.OSName = val
		case "VERSION_ID":
			out.OSVersion = val
		case "VERSION":
			out.OSVersionFull = val
		case "ID":
			out.OSID = val
		case "ID_LIKE":
			out.OSIDLike = val
		case "PRETTY_NAME":
			out.OSPrettyName = val
		case "PLATFORM_ID":
			out.PlatformIdentifier = val
		}
	}
	return out, nil
}

// ParseUname parses `uname -srvm` output (one line, space-separated).
//
// Layout: <kernel_name> <kernel_release> <... kernel_version ...> <arch>
// — KernelVersion is everything between KernelRelease and Architecture
// because it can contain spaces (e.g. "#1 SMP PREEMPT_DYNAMIC Wed Aug 23 ...").
func ParseUname(b []byte) (UnameFacts, error) {
	line := strings.TrimSpace(string(b))
	if line == "" {
		return UnameFacts{}, errors.New("probe: uname output empty")
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return UnameFacts{}, errors.New("probe: uname output too short")
	}
	out := UnameFacts{
		KernelName:    fields[0],
		KernelRelease: fields[1],
		Architecture:  fields[len(fields)-1],
	}
	if len(fields) > 3 {
		out.KernelVersion = strings.Join(fields[2:len(fields)-1], " ")
	}
	return out, nil
}

// ParseMemInfo parses /proc/meminfo and returns MB-rounded MemTotal,
// MemAvailable, SwapTotal. Each line is `Key: <value> kB`; integer
// division by 1024 produces MB. Missing keys yield zero (AC-04).
func ParseMemInfo(b []byte) (MemInfoFacts, error) {
	out := MemInfoFacts{}
	for _, raw := range bytes.Split(b, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		rest := strings.TrimSpace(line[colon+1:])
		// Strip trailing "kB" suffix and the value's leading whitespace.
		rest = strings.TrimSuffix(rest, "kB")
		rest = strings.TrimSpace(rest)
		// First whitespace-delimited token is the integer kB count.
		valStr := rest
		if sp := strings.IndexFunc(rest, isSpace); sp >= 0 {
			valStr = rest[:sp]
		}
		kB, err := strconv.Atoi(valStr)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			out.MemTotalMB = kB / 1024
		case "MemAvailable":
			out.MemAvailableMB = kB / 1024
		case "SwapTotal":
			out.SwapTotalMB = kB / 1024
		}
	}
	return out, nil
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' }
