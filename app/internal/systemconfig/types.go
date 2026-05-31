package systemconfig

import (
	"errors"
	"fmt"
)

// Key namespaces. One constant per config domain — keep them grouped
// here so the audit trail's config_key field has a stable enum.
const (
	KeyConnectivity = "connectivity"
)

// ConnectivityConfig is the typed shape stored under KeyConnectivity.
//
// Spec: services-connectivity-config C-01 + C-06. Field bounds and
// defaults match the liveness Default* constants verbatim so an
// out-of-the-box deployment with zero system_config rows behaves
// exactly like Slice B did before this config layer landed.
type ConnectivityConfig struct {
	IntervalSec          int  `json:"interval_sec"`
	TimeoutSec           int  `json:"timeout_sec"`
	UnreachableThreshold int  `json:"unreachable_threshold"`
	RateLimit            int  `json:"rate_limit"`
	MaintenanceGlobal    bool `json:"maintenance_global"`
}

// DefaultConnectivity returns the baked-in defaults. Matches
// liveness.DefaultProbeInterval (5m = 300s),
// liveness.DefaultProbeTimeout (5s), and
// liveness.DefaultUnreachableThreshold (2).
func DefaultConnectivity() ConnectivityConfig {
	return ConnectivityConfig{
		IntervalSec:          300,
		TimeoutSec:           5,
		UnreachableThreshold: 2,
		RateLimit:            50,
		MaintenanceGlobal:    false,
	}
}

// ErrInvalidConfig is returned by validation when a field is out of
// bounds. Wrap with %w so callers can errors.Is(err, ErrInvalidConfig).
var ErrInvalidConfig = errors.New("systemconfig: invalid config")

// Validate enforces the bounds in services-connectivity-config C-01.
// Returns a wrapped ErrInvalidConfig naming the offending field.
func (c ConnectivityConfig) Validate() error {
	if c.IntervalSec < 60 || c.IntervalSec > 86400 {
		return fmt.Errorf("%w: interval_sec=%d must be 60..86400", ErrInvalidConfig, c.IntervalSec)
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
