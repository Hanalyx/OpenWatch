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
