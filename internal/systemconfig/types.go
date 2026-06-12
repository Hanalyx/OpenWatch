package systemconfig

import (
	"errors"
	"fmt"
)

// Key namespaces. One constant per config domain — keep them grouped
// here so the audit trail's config_key field has a stable enum.
const (
	KeyConnectivity = "connectivity"
	KeyIntelligence = "intelligence"
	KeySecurity     = "security"
	KeyDiscovery    = "discovery"
	KeyScan         = "scan"
)

// ConnectivityConfig is the typed shape stored under KeyConnectivity.
//
// Spec: services-connectivity-config v1.1.0 C-01 + C-02. Per-state
// intervals replace the v1.0.0 single IntervalSec — the liveness loop
// computes each host's next_probe_at from the band the host is in
// (Online / Degraded / Critical / Down).
//
// Maintenance band stays here as a persisted config so the UI can
// edit it, but the loop doesn't read it yet — per-host maintenance is
// in the backlog. MaintenanceGlobal still pauses the whole loop.
type ConnectivityConfig struct {
	// Per-state probe intervals in seconds. v1.1.0 NEW.
	OnlineSec      int `json:"online_sec"`
	DegradedSec    int `json:"degraded_sec"`
	CriticalSec    int `json:"critical_sec"`
	DownSec        int `json:"down_sec"`
	MaintenanceSec int `json:"maintenance_sec"`

	TimeoutSec           int  `json:"timeout_sec"`
	UnreachableThreshold int  `json:"unreachable_threshold"`
	RateLimit            int  `json:"rate_limit"`
	MaintenanceGlobal    bool `json:"maintenance_global"`
}

// DefaultConnectivity returns the baked-in defaults — the band table
// in services-connectivity-config v1.1.0.
//
//	Online      — 15m (consec=0, reachable: nothing's changing)
//	Degraded    —  5m (consec>=1, reachable: watch closely)
//	Critical    —  2m (consec<3, unreachable: confirm fast)
//	Down        — 30m (consec>=3: back off, don't hammer dead)
//	Maintenance — 60m (UI/persisted band, not yet auto-applied)
func DefaultConnectivity() ConnectivityConfig {
	return ConnectivityConfig{
		OnlineSec:            900,
		DegradedSec:          300,
		CriticalSec:          120,
		DownSec:              1800,
		MaintenanceSec:       3600,
		TimeoutSec:           5,
		UnreachableThreshold: 2,
		RateLimit:            50,
		MaintenanceGlobal:    false,
	}
}

// IntelligenceConfig is the typed shape stored under KeyIntelligence.
//
// Spec: system-intelligence-scheduler v1.0.0 C-06 + C-07.
//
// IntervalSec is the per-host cadence the scheduler advances
// next_intelligence_at by after a successful RunCycle. RateLimit
// caps the bounded worker pool the scheduler uses to dispatch
// per-tick. MaintenanceGlobal pauses the entire loop (mirrors the
// connectivity flag).
type IntelligenceConfig struct {
	IntervalSec       int  `json:"interval_sec"`
	RateLimit         int  `json:"rate_limit"`
	MaintenanceGlobal bool `json:"maintenance_global"`
}

// DefaultIntelligence returns the baked-in defaults.
//
//	IntervalSec       — 3600 (1 hour per host)
//	RateLimit         —   10 (concurrent RunCycles per scheduler)
//	MaintenanceGlobal — false
func DefaultIntelligence() IntelligenceConfig {
	return IntelligenceConfig{
		IntervalSec:       3600,
		RateLimit:         10,
		MaintenanceGlobal: false,
	}
}

// Validate enforces the bounds in system-intelligence-scheduler C-06,
// C-07. Returns a wrapped ErrInvalidConfig naming the offending field.
func (c IntelligenceConfig) Validate() error {
	if c.IntervalSec < 300 || c.IntervalSec > 86400 {
		return fmt.Errorf("%w: interval_sec=%d must be 300..86400", ErrInvalidConfig, c.IntervalSec)
	}
	if c.RateLimit < 1 || c.RateLimit > 200 {
		return fmt.Errorf("%w: rate_limit=%d must be 1..200", ErrInvalidConfig, c.RateLimit)
	}
	return nil
}

// ErrInvalidConfig is returned by validation when a field is out of
// bounds. Wrap with %w so callers can errors.Is(err, ErrInvalidConfig).
var ErrInvalidConfig = errors.New("systemconfig: invalid config")

// SecurityConfig is the typed shape stored under KeySecurity.
//
// Spec: system-ssh-connectivity v1.1.0 C-09..C-12.
//
// AllowCredentialSudoPassword is the policy knob that gates the sudo -S
// password fallback in the SSH dial layer. Defaults to false (opt-in).
// When false, the collector and discovery probes behave exactly as in
// v1.0.0 — every sudo command goes through `sudo -n` and degrades
// gracefully on NOPASSWD-not-configured hosts.
type SecurityConfig struct {
	AllowCredentialSudoPassword bool `json:"allow_credential_sudo_password"`
}

// DefaultSecurity returns the baked-in defaults. Fallback is OFF.
func DefaultSecurity() SecurityConfig {
	return SecurityConfig{
		AllowCredentialSudoPassword: false,
	}
}

// Validate is a no-op for the current SecurityConfig — the single field
// is a boolean. Kept symmetric with the other configs so the resolver
// can call Validate() uniformly.
func (SecurityConfig) Validate() error { return nil }

// DiscoveryConfig is the typed shape stored under KeyDiscovery.
//
// Spec: system-discovery-scheduler v1.0.0 C-04 + C-05.
//
// IntervalSec is the per-host cadence the scheduler treats as "due
// again"; a host with os_discovered_at older than now() - IntervalSec
// re-enters listDiscoveryTargets. RateLimit caps the number of jobs
// enqueued per tick — bounds the thundering-herd shape when many hosts
// hit NULL os_discovered_at at once. DetectOnFirstContact gates the
// host-create auto-enqueue (when false, new hosts stay NULL until the
// sweeper or an explicit operator click finds them).
// MaintenanceGlobal pauses the entire scheduler loop.
type DiscoveryConfig struct {
	IntervalSec          int  `json:"interval_sec"`
	RateLimit            int  `json:"rate_limit"`
	DetectOnFirstContact bool `json:"detect_on_first_contact"`
	MaintenanceGlobal    bool `json:"maintenance_global"`
}

// DefaultDiscovery returns the baked-in defaults.
//
//	IntervalSec          — 86400  (24h per host)
//	RateLimit            —    25  (max jobs enqueued per tick)
//	DetectOnFirstContact —  true  (host create still auto-fingerprints)
//	MaintenanceGlobal    — false
func DefaultDiscovery() DiscoveryConfig {
	return DiscoveryConfig{
		IntervalSec:          86400,
		RateLimit:            25,
		DetectOnFirstContact: true,
		MaintenanceGlobal:    false,
	}
}

// Validate enforces the bounds in system-discovery-scheduler C-04, C-05.
// Returns a wrapped ErrInvalidConfig naming the offending field.
func (c DiscoveryConfig) Validate() error {
	if c.IntervalSec < 3600 || c.IntervalSec > 604800 {
		return fmt.Errorf("%w: interval_sec=%d must be 3600..604800", ErrInvalidConfig, c.IntervalSec)
	}
	if c.RateLimit < 1 || c.RateLimit > 500 {
		return fmt.Errorf("%w: rate_limit=%d must be 1..500", ErrInvalidConfig, c.RateLimit)
	}
	return nil
}

// Validate enforces the bounds in services-connectivity-config C-01.
// Returns a wrapped ErrInvalidConfig naming the offending field.
func (c ConnectivityConfig) Validate() error {
	for _, f := range []struct {
		name string
		val  int
	}{
		{"online_sec", c.OnlineSec},
		{"degraded_sec", c.DegradedSec},
		{"critical_sec", c.CriticalSec},
		{"down_sec", c.DownSec},
		{"maintenance_sec", c.MaintenanceSec},
	} {
		if f.val < 60 || f.val > 86400 {
			return fmt.Errorf("%w: %s=%d must be 60..86400", ErrInvalidConfig, f.name, f.val)
		}
	}
	if c.TimeoutSec < 1 || c.TimeoutSec > 30 {
		return fmt.Errorf("%w: timeout_sec=%d must be 1..30", ErrInvalidConfig, c.TimeoutSec)
	}
	if c.UnreachableThreshold < 1 || c.UnreachableThreshold > 10 {
		return fmt.Errorf("%w: unreachable_threshold=%d must be 1..10", ErrInvalidConfig, c.UnreachableThreshold)
	}
	if c.RateLimit < 1 || c.RateLimit > 200 {
		return fmt.Errorf("%w: rate_limit=%d must be 1..200", ErrInvalidConfig, c.RateLimit)
	}
	return nil
}

// ScanConfig is the typed shape stored under KeyScan — the adaptive
// compliance scan scheduler's operator-editable knobs.
//
// Spec: system-scheduler v3.0.0 C-01 (tier ladder from systemconfig,
// replacing the v2 signed schedules-policy file per scan plan decision
// #4) + api-system-scan-config.
//
// The six *Mins fields are the tier ladder: how long after a scan a
// host in that compliance state waits before its next scheduled scan.
// Riskier states re-scan sooner. Values are minutes; the scheduler
// clamps them into [5m, 48h] at load time (C-08), and Normalize
// applies the same clamp at PUT time so what the operator reads back
// is what the scheduler runs.
type ScanConfig struct {
	Enabled bool `json:"enabled"`

	// Per-state scan intervals in minutes — the tier ladder.
	UnknownMins         int `json:"unknown_mins"`
	CriticalMins        int `json:"critical_mins"`
	NonCompliantMins    int `json:"non_compliant_mins"`
	PartialMins         int `json:"partial_mins"`
	MostlyCompliantMins int `json:"mostly_compliant_mins"`
	CompliantMins       int `json:"compliant_mins"`

	// RateLimit caps hosts dispatched per scheduler tick (1..100).
	RateLimit int `json:"rate_limit"`
	// MaintenanceGlobal pauses the entire dispatch loop (mirrors the
	// connectivity / intelligence / discovery flags).
	MaintenanceGlobal bool `json:"maintenance_global"`
}

// DefaultScan returns the baked-in defaults. Auto-scan is ON by
// default (the OpenWatch OS model is auto-scan centric); the ladder
// re-scans riskier states sooner.
//
//	unknown            —  360m (6h: classified on first scan anyway)
//	critical           —  240m (4h)
//	non_compliant      —  480m (8h)
//	partial            —  720m (12h)
//	mostly_compliant   — 1440m (24h)
//	compliant          — 2880m (48h ceiling)
//	rate_limit         —    25 hosts per tick
func DefaultScan() ScanConfig {
	return ScanConfig{
		Enabled:             true,
		UnknownMins:         360,
		CriticalMins:        240,
		NonCompliantMins:    480,
		PartialMins:         720,
		MostlyCompliantMins: 1440,
		CompliantMins:       2880,
		RateLimit:           25,
		MaintenanceGlobal:   false,
	}
}

// ScanIntervalMinFloor / ScanIntervalMaxCap bound the ladder values in
// minutes. They mirror scheduler.MinIntervalFloor / MaxIntervalCap;
// duplicated as ints here so systemconfig does not import the
// scheduler package.
const (
	ScanIntervalMinFloor = 5
	ScanIntervalMaxCap   = 2880
)

// Normalize returns a copy with every ladder value clamped into
// [ScanIntervalMinFloor, ScanIntervalMaxCap] and the rate limit into
// [1, 100]. PUT /system/scan/config clamps rather than rejects (scan
// plan Phase 4: "server clamps to the scheduler's bounds") so operator
// typos degrade safely instead of bouncing the whole save.
func (c ScanConfig) Normalize() ScanConfig {
	clamp := func(v int) int {
		if v < ScanIntervalMinFloor {
			return ScanIntervalMinFloor
		}
		if v > ScanIntervalMaxCap {
			return ScanIntervalMaxCap
		}
		return v
	}
	c.UnknownMins = clamp(c.UnknownMins)
	c.CriticalMins = clamp(c.CriticalMins)
	c.NonCompliantMins = clamp(c.NonCompliantMins)
	c.PartialMins = clamp(c.PartialMins)
	c.MostlyCompliantMins = clamp(c.MostlyCompliantMins)
	c.CompliantMins = clamp(c.CompliantMins)
	if c.RateLimit < 1 {
		c.RateLimit = 1
	}
	if c.RateLimit > 100 {
		c.RateLimit = 100
	}
	return c
}

// Validate is satisfied by construction after Normalize — kept so the
// store's Set path stays uniform with the sibling configs. It rejects
// values Normalize would have fixed, catching callers that skip it.
func (c ScanConfig) Validate() error {
	for _, f := range []struct {
		name string
		val  int
	}{
		{"unknown_mins", c.UnknownMins},
		{"critical_mins", c.CriticalMins},
		{"non_compliant_mins", c.NonCompliantMins},
		{"partial_mins", c.PartialMins},
		{"mostly_compliant_mins", c.MostlyCompliantMins},
		{"compliant_mins", c.CompliantMins},
	} {
		if f.val < ScanIntervalMinFloor || f.val > ScanIntervalMaxCap {
			return fmt.Errorf("%w: %s=%d must be %d..%d", ErrInvalidConfig,
				f.name, f.val, ScanIntervalMinFloor, ScanIntervalMaxCap)
		}
	}
	if c.RateLimit < 1 || c.RateLimit > 100 {
		return fmt.Errorf("%w: rate_limit=%d must be 1..100", ErrInvalidConfig, c.RateLimit)
	}
	return nil
}
