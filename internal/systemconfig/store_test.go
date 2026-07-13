// @spec services-connectivity-config
//
// AC traceability (this file):
//
//   AC-01  TestLoadConnectivity_NoRow_ReturnsDefaults
//   AC-02  TestSetThenLoad_RoundTripsSavedSnapshot
//   AC-03  TestSetConnectivity_RejectsIntervalBelowMinimum
//   AC-04  TestSetConnectivity_RejectsThresholdZero
//   AC-05  TestSetConnectivity_EmitsConfigChangedWithOldAndNew
//   AC-07  (covered by AC-02 + AC-05 — persisted maintenance_global is
//          read back; the live-service maintenance check is exercised
//          in liveness/service_test.go)
//   AC-06  TestConcurrentSet_LastWriterWins_NoDeadlock

package systemconfig

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE system_config CASCADE"); err != nil {
		t.Logf("truncate (ok if table just created): %v", err)
	}
	return pool
}

// capture collects emitted audit events so we can assert on AC-05.
type capture struct {
	mu     sync.Mutex
	events []captured
}

type captured struct {
	code audit.Code
	ev   audit.Event
}

func (c *capture) emit(_ context.Context, code audit.Code, ev audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, captured{code, ev})
}

func (c *capture) snapshot() []captured {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]captured, len(c.events))
	copy(out, c.events)
	return out
}

// AC-01: no row → defaults, no error.
// @ac AC-01
func TestLoadConnectivity_NoRow_ReturnsDefaults(t *testing.T) {
	t.Run("services-connectivity-config/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		s := NewStore(pool, nil)
		got, err := s.LoadConnectivity(context.Background())
		if err != nil {
			t.Fatalf("LoadConnectivity: %v", err)
		}
		want := DefaultConnectivity()
		if got != want {
			t.Errorf("expected defaults %+v, got %+v", want, got)
		}
	})
}

// AC-02: Set then Load returns the saved snapshot.
// @ac AC-02
func TestSetThenLoad_RoundTripsSavedSnapshot(t *testing.T) {
	t.Run("services-connectivity-config/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		cap := &capture{}
		s := NewStore(pool, cap.emit)

		want := ConnectivityConfig{
			OnlineSec:            600,
			DegradedSec:          180,
			CriticalSec:          60,
			DownSec:              1200,
			MaintenanceSec:       1800,
			TimeoutSec:           10,
			UnreachableThreshold: 3,
			RateLimit:            25,
			MaintenanceGlobal:    true,
		}
		if err := s.SetConnectivity(context.Background(), want, "alice"); err != nil {
			t.Fatalf("SetConnectivity: %v", err)
		}
		got, err := s.LoadConnectivity(context.Background())
		if err != nil {
			t.Fatalf("LoadConnectivity: %v", err)
		}
		if got != want {
			t.Errorf("expected %+v, got %+v", want, got)
		}
	})
}

// AC-03: out-of-range online_sec rejected; persisted state unchanged.
// @ac AC-03
func TestSetConnectivity_RejectsIntervalBelowMinimum(t *testing.T) {
	t.Run("services-connectivity-config/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		s := NewStore(pool, nil)
		bad := DefaultConnectivity()
		bad.OnlineSec = 10 // below 60
		err := s.SetConnectivity(context.Background(), bad, "alice")
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("expected ErrInvalidConfig, got %v", err)
		}
		// Persisted state stays at defaults.
		got, _ := s.LoadConnectivity(context.Background())
		if got != DefaultConnectivity() {
			t.Errorf("persisted state should be defaults, got %+v", got)
		}
	})
}

// AC-04: down_sec above maximum rejected.
// @ac AC-04
func TestSetConnectivity_RejectsThresholdZero(t *testing.T) {
	t.Run("services-connectivity-config/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		s := NewStore(pool, nil)
		bad := DefaultConnectivity()
		bad.DownSec = 100000 // above 86400
		err := s.SetConnectivity(context.Background(), bad, "alice")
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("expected ErrInvalidConfig, got %v", err)
		}
	})
}

// AC-05: a successful Set emits exactly one system.config.changed
// event with old_value (snapshot prior to write) and new_value populated.
// @ac AC-05
func TestSetConnectivity_EmitsConfigChangedWithOldAndNew(t *testing.T) {
	t.Run("services-connectivity-config/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		cap := &capture{}
		s := NewStore(pool, cap.emit)

		// First Set populates the row with custom values.
		first := DefaultConnectivity()
		first.OnlineSec = 600
		first.TimeoutSec = 10
		first.UnreachableThreshold = 3
		first.RateLimit = 25
		if err := s.SetConnectivity(context.Background(), first, "alice"); err != nil {
			t.Fatalf("first Set: %v", err)
		}
		// Second Set should capture the first as old_value.
		second := DefaultConnectivity()
		second.OnlineSec = 1200
		second.TimeoutSec = 15
		second.UnreachableThreshold = 4
		second.RateLimit = 30
		second.MaintenanceGlobal = true
		if err := s.SetConnectivity(context.Background(), second, "bob"); err != nil {
			t.Fatalf("second Set: %v", err)
		}

		got := cap.snapshot()
		if len(got) != 2 {
			t.Fatalf("expected 2 audit events, got %d", len(got))
		}
		for _, ev := range got {
			if ev.code != audit.SystemConfigChanged {
				t.Errorf("expected SystemConfigChanged, got %s", ev.code)
			}
		}

		// Inspect the second event — old_value should be `first`, new_value `second`.
		var detail struct {
			ConfigKey string             `json:"config_key"`
			OldValue  ConnectivityConfig `json:"old_value"`
			NewValue  ConnectivityConfig `json:"new_value"`
			ChangedBy string             `json:"changed_by"`
		}
		if err := json.Unmarshal(got[1].ev.Detail, &detail); err != nil {
			t.Fatalf("unmarshal detail: %v", err)
		}
		if detail.ConfigKey != KeyConnectivity {
			t.Errorf("expected config_key=%q, got %q", KeyConnectivity, detail.ConfigKey)
		}
		if detail.OldValue != first {
			t.Errorf("old_value mismatch: want %+v, got %+v", first, detail.OldValue)
		}
		if detail.NewValue != second {
			t.Errorf("new_value mismatch: want %+v, got %+v", second, detail.NewValue)
		}
		if detail.ChangedBy != "bob" {
			t.Errorf("changed_by: want bob, got %s", detail.ChangedBy)
		}
	})
}

// AC-06: two concurrent Set calls complete cleanly; final state is one
// of the two writers' inputs.
// @ac AC-06
func TestConcurrentSet_LastWriterWins_NoDeadlock(t *testing.T) {
	t.Run("services-connectivity-config/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		s := NewStore(pool, nil)

		a := DefaultConnectivity()
		a.OnlineSec = 600
		b := DefaultConnectivity()
		b.OnlineSec = 1200

		done := make(chan error, 2)
		go func() { done <- s.SetConnectivity(context.Background(), a, "alice") }()
		go func() { done <- s.SetConnectivity(context.Background(), b, "bob") }()

		for i := 0; i < 2; i++ {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("concurrent Set returned error: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("timeout waiting for concurrent Set — possible deadlock")
			}
		}

		got, err := s.LoadConnectivity(context.Background())
		if err != nil {
			t.Fatalf("LoadConnectivity: %v", err)
		}
		if got != a && got != b {
			t.Errorf("final state %+v matched neither writer", got)
		}
	})
}

// @spec system-compliance-lens
// @ac AC-01
// AC-01: ComplianceConfig defaults to All rules (empty), Validate bounds the
// family token, and Set/Load round-trips the value; a fresh store returns the
// empty default.
func TestComplianceConfig_DefaultValidateRoundTrip(t *testing.T) {
	t.Run("system-compliance-lens/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		s := NewStore(pool, nil)
		ctx := context.Background()

		// Fresh store (no row) → All rules (empty).
		got, err := s.LoadCompliance(ctx)
		if err != nil {
			t.Fatalf("LoadCompliance (no row): %v", err)
		}
		if got.DefaultFramework != "" {
			t.Errorf("default = %q, want empty (All rules)", got.DefaultFramework)
		}

		// Validate: empty + valid token OK; garbage + over-long rejected.
		for _, ok := range []string{"", "stig", "nist_800_53", "cis"} {
			if err := (ComplianceConfig{DefaultFramework: ok}).Validate(); err != nil {
				t.Errorf("Validate(%q) = %v, want nil", ok, err)
			}
		}
		for _, bad := range []string{"STIG!", "has space", string(make([]byte, 65))} {
			if err := (ComplianceConfig{DefaultFramework: bad}).Validate(); err == nil {
				t.Errorf("Validate(%q) = nil, want error", bad)
			}
		}

		// Set then Load round-trips.
		if _, err := s.SetCompliance(ctx, ComplianceConfig{DefaultFramework: "stig"}, "admin"); err != nil {
			t.Fatalf("SetCompliance: %v", err)
		}
		got, err = s.LoadCompliance(ctx)
		if err != nil {
			t.Fatalf("LoadCompliance: %v", err)
		}
		if got.DefaultFramework != "stig" {
			t.Errorf("round-trip default = %q, want stig", got.DefaultFramework)
		}
	})
}

// @spec system-compliance-lens
// @ac AC-05
// AC-05: EnabledFrameworks allowlist defaults empty, Validate bounds it and
// enforces the default-must-be-enabled invariant, and Set/Load round-trips it.
func TestComplianceConfig_EnabledFrameworksAllowlist(t *testing.T) {
	t.Run("system-compliance-lens/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		s := NewStore(pool, nil)
		ctx := context.Background()

		// Fresh store → empty allowlist (all families available).
		got, err := s.LoadCompliance(ctx)
		if err != nil {
			t.Fatalf("LoadCompliance (no row): %v", err)
		}
		if len(got.EnabledFrameworks) != 0 {
			t.Errorf("enabled = %v, want empty", got.EnabledFrameworks)
		}

		// Empty + valid lists accepted.
		for _, okList := range [][]string{nil, {"stig"}, {"stig", "cis", "nist_800_53"}} {
			if err := (ComplianceConfig{EnabledFrameworks: okList}).Validate(); err != nil {
				t.Errorf("Validate(enabled=%v) = %v, want nil", okList, err)
			}
		}
		// Over-long list rejected.
		big := make([]string, ComplianceMaxEnabledFrameworks+1)
		for i := range big {
			big[i] = "stig"
		}
		if err := (ComplianceConfig{EnabledFrameworks: big}).Validate(); err == nil {
			t.Error("Validate(over-long allowlist) = nil, want error")
		}
		// Invalid entry rejected.
		if err := (ComplianceConfig{EnabledFrameworks: []string{"STIG!"}}).Validate(); err == nil {
			t.Error("Validate(invalid entry) = nil, want error")
		}
		// Invariant: a non-empty default must be one of a non-empty allowlist.
		if err := (ComplianceConfig{DefaultFramework: "stig", EnabledFrameworks: []string{"cis"}}).Validate(); err == nil {
			t.Error("Validate(default not in allowlist) = nil, want error")
		}
		if err := (ComplianceConfig{DefaultFramework: "stig", EnabledFrameworks: []string{"stig", "cis"}}).Validate(); err != nil {
			t.Errorf("Validate(default in allowlist) = %v, want nil", err)
		}

		// Set then Load round-trips the allowlist.
		if _, err := s.SetCompliance(ctx,
			ComplianceConfig{DefaultFramework: "stig", EnabledFrameworks: []string{"stig", "cis"}}, "admin"); err != nil {
			t.Fatalf("SetCompliance: %v", err)
		}
		got, err = s.LoadCompliance(ctx)
		if err != nil {
			t.Fatalf("LoadCompliance: %v", err)
		}
		if len(got.EnabledFrameworks) != 2 || got.EnabledFrameworks[0] != "stig" || got.EnabledFrameworks[1] != "cis" {
			t.Errorf("round-trip allowlist = %v, want [stig cis]", got.EnabledFrameworks)
		}
	})
}
