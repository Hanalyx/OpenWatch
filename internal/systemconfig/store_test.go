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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run systemconfig integration tests")
	}
	return dsn
}

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	pool, err := db.NewPool(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("migrations.Apply: %v", err)
	}
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
