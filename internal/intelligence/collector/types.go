package collector

import "time"

// Snapshot is the full structured state one RunCycle collects from a
// host. Persisted as JSONB in host_intelligence_state.snapshot; the
// diff engine compares two Snapshots to compute the change events.
//
// Field semantics are intentionally coarse — booleans + maps — so the
// diff is straightforward set-comparison and value-comparison. We pay
// in JSON size; we save in code clarity.
type Snapshot struct {
	// Packages: map[name]version. Family-agnostic — both RPM and DPKG
	// land here via the same parser.
	Packages map[string]string `json:"packages,omitempty"`

	// ListeningPorts: every (protocol, address, port) observed via `ss -tln`.
	ListeningPorts []ListeningPort `json:"listening_ports,omitempty"`

	// Groups: map[group_name][]usernames. Diff detects newly-added
	// members of privileged groups (wheel, sudo, admin).
	Groups map[string][]string `json:"groups,omitempty"`

	// Users: present-or-absent + lock-state from passwd+shadow.
	Users map[string]UserSnapshot `json:"users,omitempty"`

	// Services: map[unit]state — "active" | "inactive" | "failed".
	Services map[string]string `json:"services,omitempty"`

	// Mountpoints: every mountpoint observed in /proc/mounts. Diff
	// detects mount/unmount events.
	Mountpoints map[string]string `json:"mountpoints,omitempty"` // path → source

	// ConfigHashes: map[path]sha256 for critical config files
	// (/etc/passwd, /etc/sudoers, /etc/ssh/sshd_config, etc).
	ConfigHashes map[string]string `json:"config_hashes,omitempty"`

	// KernelRelease: uname -r. Diff detects kernel upgrades.
	KernelRelease string `json:"kernel_release,omitempty"`

	// RebootRequired: presence of vendor marker file
	// (/run/reboot-required, /var/run/reboot-required.pkgs, etc).
	RebootRequired bool `json:"reboot_required,omitempty"`

	// UptimeSeconds: /proc/uptime. Diff detects reboot completion
	// (uptime fell below prior cycle's value).
	UptimeSeconds int64 `json:"uptime_seconds,omitempty"`

	// NetworkInterfaces: one entry per device from `ip -j addr show` +
	// /sys/class/net. Powers the host-detail Network tab. Optional fields
	// (Speed, Duplex, Driver) may be empty for virtual / loopback / not-
	// permitted interfaces — that's expected, not an error.
	NetworkInterfaces []NetworkInterface `json:"network_interfaces,omitempty"`

	// Routes: parsed `ip -j route show` for the main routing table.
	// Used to populate the Network tab's "Default route" stat card and
	// the routing-table panel.
	Routes []Route `json:"routes,omitempty"`

	// FirewallRuleCount: count of currently-loaded user-visible rules
	// in whichever firewall the host runs. Definition is per-engine
	// (rich rules for firewalld, numbered rules for ufw, rule lines for
	// nftables, -A lines for iptables) — operators care about "did I
	// configure anything" more than parser semantics.
	//   nil    = field not collected (pre-feature snapshot OR probe crashed)
	//   *n=-1  = no firewall engine detected on this host
	//   *n=0   = engine present, no rules loaded
	//   *n=N>0 = engine present, N rules loaded
	// Pointer is required because we need to distinguish 0 ("engine
	// present, no rules") from "absent" — int with omitempty drops both.
	FirewallRuleCount *int `json:"firewall_rule_count,omitempty"`

	// CollectedAt is when the snapshot was captured. Set by the
	// service, not the parsers.
	CollectedAt time.Time `json:"collected_at,omitempty"`
}

// ListeningPort is one entry from `ss -tln`.
type ListeningPort struct {
	Protocol string `json:"protocol"` // tcp | udp
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

// NetworkInterface is one network device. Sourced from `ip -j addr`
// + /sys/class/net. The frontend renders one card per interface; the
// stat row counts physical vs loopback by Type.
type NetworkInterface struct {
	Name      string   `json:"name"`                 // eno1, lo, eth0, ...
	State     string   `json:"state,omitempty"`      // UP | DOWN | UNKNOWN
	Type      string   `json:"type,omitempty"`       // physical | loopback | virtual | bridge | tunnel
	IPv4Addrs []string `json:"ipv4_addrs,omitempty"` // CIDR strings, e.g., "192.168.1.214/24"
	IPv6Addrs []string `json:"ipv6_addrs,omitempty"` // CIDR strings
	MAC       string   `json:"mac,omitempty"`        // colon-separated; "" for loopback
	MTU       int      `json:"mtu,omitempty"`
	Driver    string   `json:"driver,omitempty"`     // virtio_net, e1000e, ...
	SpeedMbps int      `json:"speed_mbps,omitempty"` // 0 when unknown / loopback
	Duplex    string   `json:"duplex,omitempty"`     // full | half | ""
	RxBytes   uint64   `json:"rx_bytes,omitempty"`
	TxBytes   uint64   `json:"tx_bytes,omitempty"`
}

// Route is one entry from `ip -j route show`.
type Route struct {
	Destination string `json:"destination"`       // "default" | CIDR
	Gateway     string `json:"gateway,omitempty"` // "link-local" → empty
	Interface   string `json:"interface"`         // dev
	Metric      int    `json:"metric,omitempty"`
	Protocol    string `json:"protocol,omitempty"` // dhcp, static, kernel, ...
	Scope       string `json:"scope,omitempty"`    // host, link, global
}

// UserSnapshot is the per-user fact set from passwd+shadow.
type UserSnapshot struct {
	UID    int  `json:"uid"`
	Locked bool `json:"locked"`
}

// AccountFacts is the typed return of ParsePasswdShadow.
type AccountFacts struct {
	Users map[string]UserSnapshot
}

// Event is one detected change. The diff engine returns []Event;
// RunCycle persists each into host_intelligence_events and publishes
// the corresponding bus + audit event.
type Event struct {
	Code     Code           `json:"code"`
	Severity string         `json:"severity"` // info|low|medium|high|critical
	Detail   map[string]any `json:"detail"`
}
