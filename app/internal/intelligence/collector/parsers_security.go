package collector

import (
	"bytes"
	"strconv"
	"strings"
)

// ParseListeningPorts parses `ss -tln` output into ListeningPort records.
//
// Expected header (skipped): "State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port"
// Each data line: "LISTEN   0   128   <addr>:<port>   <peer>:<peer_port>"
//
// The local address column may be IPv4 ("0.0.0.0:22"), IPv4 loopback
// ("127.0.0.1:25"), or IPv6 ("[::]:22"). All three forms parse cleanly:
// the parser takes everything before the last colon as the address and
// everything after as the port.
func ParseListeningPorts(b []byte) ([]ListeningPort, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var out []ListeningPort
	for _, raw := range bytes.Split(b, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		// Skip the header line.
		if strings.HasPrefix(strings.ToLower(line), "state") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !strings.EqualFold(fields[0], "LISTEN") {
			continue
		}
		local := fields[3]
		host, port, ok := splitHostPort(local)
		if !ok {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		out = append(out, ListeningPort{
			Protocol: "tcp",
			Address:  host,
			Port:     p,
		})
	}
	return out, nil
}

// splitHostPort handles IPv4, IPv4-mapped, and IPv6-bracketed forms.
// Returns (host, port, ok). Mirrors net.SplitHostPort but accepts the
// non-canonical "0.0.0.0:*" wildcard variants we don't care about.
func splitHostPort(s string) (string, string, bool) {
	// IPv6 with brackets: "[::]:22"
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || end+1 >= len(s) || s[end+1] != ':' {
			return "", "", false
		}
		return s[1:end], s[end+2:], true
	}
	idx := strings.LastIndexByte(s, ':')
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
