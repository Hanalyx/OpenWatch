// @spec system-intelligence-scheduler
//
// AC traceability (this file):
//
//	AC-02  TestIntelligenceConfig_Defaults
//	AC-03  TestIntelligenceConfig_ValidateIntervalSecBounds
//	AC-04  TestIntelligenceConfig_ValidateRateLimitBounds
//	AC-05  TestService_EffectiveInterval_Clamped
//	AC-10  TestComputeBackoff_ExponentialWithCap

package scheduler

import (
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// @ac AC-02
func TestIntelligenceConfig_Defaults(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-02", func(t *testing.T) {
		c := systemconfig.DefaultIntelligence()
		if c.IntervalSec != 3600 {
			t.Errorf("default IntervalSec=%d, want 3600", c.IntervalSec)
		}
		if c.RateLimit != 10 {
			t.Errorf("default RateLimit=%d, want 10", c.RateLimit)
		}
		if c.MaintenanceGlobal {
			t.Errorf("default MaintenanceGlobal=true, want false")
		}
	})
}

// @ac AC-03
func TestIntelligenceConfig_ValidateIntervalSecBounds(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-03", func(t *testing.T) {
		base := systemconfig.DefaultIntelligence()

		below := base
		below.IntervalSec = 60
		if err := below.Validate(); !errors.Is(err, systemconfig.ErrInvalidConfig) {
			t.Errorf("IntervalSec=60 should fail ErrInvalidConfig, got %v", err)
		}
		above := base
		above.IntervalSec = 100000
		if err := above.Validate(); !errors.Is(err, systemconfig.ErrInvalidConfig) {
			t.Errorf("IntervalSec=100000 should fail ErrInvalidConfig, got %v", err)
		}
		// Boundary OK.
		for _, v := range []int{300, 3600, 86400} {
			c := base
			c.IntervalSec = v
			if err := c.Validate(); err != nil {
				t.Errorf("IntervalSec=%d should pass, got %v", v, err)
			}
		}
	})
}

// @ac AC-04
func TestIntelligenceConfig_ValidateRateLimitBounds(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-04", func(t *testing.T) {
		base := systemconfig.DefaultIntelligence()
		bad := []int{0, 201, -1}
		for _, v := range bad {
			c := base
			c.RateLimit = v
			if err := c.Validate(); !errors.Is(err, systemconfig.ErrInvalidConfig) {
				t.Errorf("RateLimit=%d should fail ErrInvalidConfig, got %v", v, err)
			}
		}
		good := []int{1, 10, 200}
		for _, v := range good {
			c := base
			c.RateLimit = v
			if err := c.Validate(); err != nil {
				t.Errorf("RateLimit=%d should pass, got %v", v, err)
			}
		}
	})
}

// @ac AC-05
func TestService_EffectiveInterval_Clamped(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-05", func(t *testing.T) {
		// Default (no tickInterval set) → DefaultTickInterval = 30s.
		svc := NewService(nil, nil)
		if got := svc.effectiveInterval(); got != DefaultTickInterval {
			t.Errorf("default effectiveInterval=%v, want %v", got, DefaultTickInterval)
		}

		// Below floor → clamp up.
		svc.WithTickInterval(1 * time.Second)
		if got := svc.effectiveInterval(); got != MinTickInterval {
			t.Errorf("clamped-low effectiveInterval=%v, want %v", got, MinTickInterval)
		}

		// Above ceiling → clamp down.
		svc.WithTickInterval(10 * time.Minute)
		if got := svc.effectiveInterval(); got != MaxTickInterval {
			t.Errorf("clamped-high effectiveInterval=%v, want %v", got, MaxTickInterval)
		}

		// In-range → unchanged.
		svc.WithTickInterval(45 * time.Second)
		if got := svc.effectiveInterval(); got != 45*time.Second {
			t.Errorf("in-range effectiveInterval=%v, want 45s", got)
		}
	})
}

// @ac AC-10
func TestComputeBackoff_ExponentialWithCap(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-10", func(t *testing.T) {
		base := 3600 * time.Second
		max := 86400 * time.Second

		// consec=1 → base
		if got := computeBackoff(1, base, max); got != base {
			t.Errorf("consec=1 backoff=%v, want %v", got, base)
		}
		// consec=4 → base * 2^3 = 8 * 3600 = 28800
		want4 := 28800 * time.Second
		if got := computeBackoff(4, base, max); got != want4 {
			t.Errorf("consec=4 backoff=%v, want %v", got, want4)
		}
		// consec=10 → max (would otherwise overflow base)
		if got := computeBackoff(10, base, max); got != max {
			t.Errorf("consec=10 backoff=%v, want max %v", got, max)
		}
	})
}
