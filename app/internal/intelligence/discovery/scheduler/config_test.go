// @spec system-discovery-scheduler
//
// AC traceability (this file):
//
//	AC-01  TestDiscoveryConfig_Defaults
//	AC-02  TestDiscoveryConfig_ValidateIntervalSecBounds
//	AC-03  TestDiscoveryConfig_ValidateRateLimitBounds
//	AC-04  TestService_EffectiveInterval_Clamped

package scheduler

import (
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// @ac AC-01
func TestDiscoveryConfig_Defaults(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-01", func(t *testing.T) {
		c := systemconfig.DefaultDiscovery()
		if c.IntervalSec != 86400 {
			t.Errorf("default IntervalSec=%d, want 86400", c.IntervalSec)
		}
		if c.RateLimit != 25 {
			t.Errorf("default RateLimit=%d, want 25", c.RateLimit)
		}
		if !c.DetectOnFirstContact {
			t.Errorf("default DetectOnFirstContact=false, want true")
		}
		if c.MaintenanceGlobal {
			t.Errorf("default MaintenanceGlobal=true, want false")
		}
	})
}

// @ac AC-02
func TestDiscoveryConfig_ValidateIntervalSecBounds(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-02", func(t *testing.T) {
		base := systemconfig.DefaultDiscovery()

		below := base
		below.IntervalSec = 600
		if err := below.Validate(); !errors.Is(err, systemconfig.ErrInvalidConfig) {
			t.Errorf("IntervalSec=600 should fail ErrInvalidConfig, got %v", err)
		}
		above := base
		above.IntervalSec = 700000
		if err := above.Validate(); !errors.Is(err, systemconfig.ErrInvalidConfig) {
			t.Errorf("IntervalSec=700000 should fail ErrInvalidConfig, got %v", err)
		}
		for _, v := range []int{3600, 86400, 604800} {
			c := base
			c.IntervalSec = v
			if err := c.Validate(); err != nil {
				t.Errorf("IntervalSec=%d should pass, got %v", v, err)
			}
		}
	})
}

// @ac AC-03
func TestDiscoveryConfig_ValidateRateLimitBounds(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-03", func(t *testing.T) {
		base := systemconfig.DefaultDiscovery()
		for _, v := range []int{0, 501, -1} {
			c := base
			c.RateLimit = v
			if err := c.Validate(); !errors.Is(err, systemconfig.ErrInvalidConfig) {
				t.Errorf("RateLimit=%d should fail ErrInvalidConfig, got %v", v, err)
			}
		}
		for _, v := range []int{1, 25, 500} {
			c := base
			c.RateLimit = v
			if err := c.Validate(); err != nil {
				t.Errorf("RateLimit=%d should pass, got %v", v, err)
			}
		}
	})
}

// @ac AC-04
func TestService_EffectiveInterval_Clamped(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-04", func(t *testing.T) {
		svc := NewService(nil)
		if got := svc.effectiveInterval(); got != DefaultTickInterval {
			t.Errorf("default effectiveInterval=%v, want %v", got, DefaultTickInterval)
		}

		svc.WithTickInterval(1 * time.Second)
		if got := svc.effectiveInterval(); got != MinTickInterval {
			t.Errorf("clamped-low effectiveInterval=%v, want %v", got, MinTickInterval)
		}

		svc.WithTickInterval(10 * time.Minute)
		if got := svc.effectiveInterval(); got != MaxTickInterval {
			t.Errorf("clamped-high effectiveInterval=%v, want %v", got, MaxTickInterval)
		}

		svc.WithTickInterval(45 * time.Second)
		if got := svc.effectiveInterval(); got != 45*time.Second {
			t.Errorf("in-range effectiveInterval=%v, want 45s", got)
		}
	})
}
