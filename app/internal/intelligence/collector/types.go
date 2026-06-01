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
