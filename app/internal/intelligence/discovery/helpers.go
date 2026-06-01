package discovery

import (
	"context"
	"strconv"
	"strings"
)

// deriveOSFamily collapses ID + ID_LIKE down to a single rollup label
// the list-page filter UI exposes (rhel, debian, suse, alpine, arch,
// gentoo, other). RHEL-family IDs map to "rhel"; Debian-family to
// "debian"; etc. Unknown distros fall through to "other".
func deriveOSFamily(osID, osIDLike string) string {
	id := strings.ToLower(osID)
	like := strings.ToLower(osIDLike)
	parts := strings.Fields(strings.ReplaceAll(like, ",", " "))
	parts = append(parts, id)
	for _, p := range parts {
		switch p {
		case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn", "amazon":
			return "rhel"
		case "ubuntu", "debian", "raspbian":
			return "debian"
		case "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "suse":
			return "suse"
		case "alpine":
			return "alpine"
		case "arch", "manjaro":
			return "arch"
		case "gentoo":
			return "gentoo"
		}
	}
	if id != "" {
		return id
	}
	return "other"
}

// parseDfRoot extracts (total, used, free) in GB from `df -BG /` output.
// Expected layout (BSD coreutils df):
//
//	Filesystem  1G-blocks  Used  Available  Use%  Mounted on
//	/dev/sda1   50G        12G   38G        25%   /
//
// Returns (0,0,0) if parse fails — partial-success semantics (C-03).
func parseDfRoot(out []byte) (total, used, free int) {
	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return 0, 0, 0
	}
	// Find the line whose last field is "/" (mount point).
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		if fields[len(fields)-1] != "/" {
			continue
		}
		total = parseGB(fields[1])
		used = parseGB(fields[2])
		free = parseGB(fields[3])
		return
	}
	return 0, 0, 0
}

func parseGB(s string) int {
	s = strings.TrimSuffix(s, "G")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// probeFirewall tries each known firewall service in order. The first
// one to answer (exit 0) wins. Returns ("", "", false) when none answer
// — typically because the credential lacks sudo. Per spec C-03 + AC-05
// this is partial success, not a probe failure.
func probeFirewall(ctx context.Context, sess SSHSession) (service, status string, ok bool) {
	// firewalld via systemctl is sudoless on many distros.
	if out, code, err := sess.Run(ctx, "systemctl is-active firewalld"); err == nil && code == 0 {
		return "firewalld", strings.TrimSpace(string(out)), true
	}
	// ufw — Debian / Ubuntu. Needs sudo on most distros for `status`.
	if out, code, err := sess.Run(ctx, "sudo -n ufw status"); err == nil && code == 0 {
		return "ufw", firstWord(string(out)), true
	}
	// nftables.
	if _, code, err := sess.Run(ctx, "sudo -n nft list ruleset"); err == nil && code == 0 {
		return "nftables", "active", true
	}
	// iptables fallback.
	if _, code, err := sess.Run(ctx, "sudo -n iptables -L"); err == nil && code == 0 {
		return "iptables", "active", true
	}
	// firewall-cmd as last resort (RHEL).
	if out, code, err := sess.Run(ctx, "sudo -n firewall-cmd --state"); err == nil && code == 0 {
		return "firewalld", strings.TrimSpace(string(out)), true
	}
	return "", "", false
}

func firstWord(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			// "Status: active" pattern from ufw.
			if strings.EqualFold(fields[0], "Status:") && len(fields) > 1 {
				return strings.ToLower(fields[1])
			}
			return strings.ToLower(fields[0])
		}
	}
	return ""
}

// nilIfEmpty + nilIfZero turn zero-values into SQL NULLs at bind time so
// missing fields persist as NULL, not "" or 0.
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nilIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
