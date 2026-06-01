// @spec system-alert-router
//
// AC traceability (this file):
//
//	AC-16  TestMigration0020_AlertsTableSchema
//	AC-17  TestRouter_PersistBeforeDispatch
//	AC-18  TestRouter_PersistFailure_SkipsDispatch
//	AC-19  TestRouter_ChannelReceivesPersistedID
//	AC-20  TestRouter_DuplicatePersist_NoSecondRow

package alertrouter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/google/uuid"
)

// @ac AC-16
// AC-16: Migration 0020 defines the alerts table with the required
// columns, state CHECK, and UNIQUE (dedup_key, occurred_at).
func TestMigration0020_AlertsTableSchema(t *testing.T) {
	t.Run("system-alert-router/AC-16", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)
		var migPath string
		for i := 0; i < 8; i++ {
			cand := filepath.Join(dir, "db", "migrations", "0020_alerts.sql")
			if _, err := os.Stat(cand); err == nil {
				migPath = cand
				break
			}
			dir = filepath.Dir(dir)
		}
		if migPath == "" {
			t.Fatalf("could not locate migration 0020")
		}
		raw, err := os.ReadFile(migPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		s := string(raw)
		want := []string{
			"CREATE TABLE alerts",
			"id           UUID",
			"dedup_key    TEXT         NOT NULL",
			"alert_type   TEXT         NOT NULL",
			"severity     TEXT         NOT NULL",
			"state        TEXT         NOT NULL DEFAULT 'active'",
			"CHECK (state IN ('active','silenced','acknowledged','resolved','dismissed'))",
			"CHECK (severity IN ('critical','high','medium','low','info'))",
			"UNIQUE (dedup_key, occurred_at)",
		}
		for _, w := range want {
			if !strings.Contains(s, w) {
				t.Errorf("migration 0020 missing required text: %q", w)
			}
		}
	})
}

// @ac AC-17
// AC-17: Router.handle on a fresh alert INSERTs one row before any
// Channel.Send. Verified by ordering: persist call happens before
// any channel receives the alert.
func TestRouter_PersistBeforeDispatch(t *testing.T) {
	t.Run("system-alert-router/AC-17", func(t *testing.T) {
		store := &stubStore{}
		ch := &orderCapture{}
		r := newRouterWithStore(t, store)
		r.Register(ChannelRegistration{Channel: ch})

		r.handle(context.Background(), heartbeatPulseDown())
		waitForSends(r)

		if got := store.Calls(); got != 1 {
			t.Errorf("store.Insert calls = %d, want 1", got)
		}
		if got := ch.Calls(); got != 1 {
			t.Fatalf("channel.Send calls = %d, want 1", got)
		}
		if !ch.SawAfter(store.LastAt()) {
			t.Errorf("channel.Send happened before store.Insert (persist MUST come first)")
		}
	})
}

// waitForSends blocks until dispatch's per-channel goroutines complete.
// Tests need this because dispatch fans out via go routines; reading
// channel state in the calling goroutine racing with the send goroutine
// would yield stale zero-values.
func waitForSends(r *Router) {
	r.sendWG.Wait()
}

// @ac AC-18
// AC-18: When store.Insert fails, Channel.Send is NOT called.
// PersistFailed counter increments; RoutedCount does not.
func TestRouter_PersistFailure_SkipsDispatch(t *testing.T) {
	t.Run("system-alert-router/AC-18", func(t *testing.T) {
		store := &stubStore{err: errors.New("db unreachable")}
		ch := &orderCapture{}
		r := newRouterWithStore(t, store)
		r.Register(ChannelRegistration{Channel: ch})

		r.handle(context.Background(), heartbeatPulseDown())
		waitForSends(r)

		if r.metrics.PersistFailed.Load() != 1 {
			t.Errorf("PersistFailed = %d, want 1", r.metrics.PersistFailed.Load())
		}
		if r.metrics.RoutedCount.Load() != 0 {
			t.Errorf("RoutedCount = %d on persist failure, want 0", r.metrics.RoutedCount.Load())
		}
		if ch.Calls() != 0 {
			t.Errorf("channel.Send called %d times on persist failure, want 0", ch.Calls())
		}
		if r.metrics.ReceivedCount.Load() != 1 {
			t.Errorf("ReceivedCount = %d, want 1 (event was received)", r.metrics.ReceivedCount.Load())
		}
	})
}

// @ac AC-19
// AC-19: Channel receives Alert.ID populated by the store.
func TestRouter_ChannelReceivesPersistedID(t *testing.T) {
	t.Run("system-alert-router/AC-19", func(t *testing.T) {
		expected, _ := uuid.NewV7()
		store := &stubStore{returnID: expected}
		ch := &orderCapture{}
		r := newRouterWithStore(t, store)
		r.Register(ChannelRegistration{Channel: ch})

		r.handle(context.Background(), heartbeatPulseDown())
		waitForSends(r)

		got := ch.LastAlert()
		if got.ID == uuid.Nil {
			t.Errorf("channel received Alert.ID = uuid.Nil — router did not propagate persisted ID")
		}
		if got.ID != expected {
			t.Errorf("channel Alert.ID = %s, want %s", got.ID, expected)
		}
	})
}

// @ac AC-20
// AC-20: A second handle with the same alert in the same dedup window
// is dropped by the in-memory dedup gate; store.Insert is NOT called a
// second time. The DB UNIQUE constraint provides defense-in-depth for
// router-restart scenarios — also covered by store_db_test (DB integration).
func TestRouter_DuplicatePersist_NoSecondRow(t *testing.T) {
	t.Run("system-alert-router/AC-20", func(t *testing.T) {
		store := &stubStore{}
		ch := &orderCapture{}
		r := newRouterWithStore(t, store)
		r.Register(ChannelRegistration{Channel: ch})

		r.handle(context.Background(), heartbeatPulseDown())
		r.handle(context.Background(), heartbeatPulseDown())
		waitForSends(r)

		if got := store.Calls(); got != 1 {
			t.Errorf("store.Insert calls = %d (dedup gate should have caught the second event), want 1", got)
		}
		if got := r.metrics.DedupedCount.Load(); got != 1 {
			t.Errorf("DedupedCount = %d, want 1 (second event was a duplicate)", got)
		}
	})
}

// ---- helpers ------------------------------------------------------

func newRouterWithStore(t *testing.T, s Store) *Router {
	t.Helper()
	bus := eventbus.NewBus()
	t.Cleanup(bus.Shutdown)
	r, err := NewRouter(bus, Config{})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	r.WithStore(s)
	return r
}

func heartbeatPulseDown() eventbus.HeartbeatPulse {
	return eventbus.HeartbeatPulse{
		HostID:         uuid.MustParse("00000000-0000-0000-0000-000000000010"),
		Reachable:      false,
		PriorReachable: true,
		OccurredAt:     time.Unix(1700000000, 0).UTC(),
	}
}

// stubStore is a unit-test Store. Optionally returns err to simulate
// DB failure; otherwise returns returnID (or a generated UUID if zero).
type stubStore struct {
	mu       sync.Mutex
	calls    atomic.Int64
	lastAt   time.Time
	err      error
	returnID uuid.UUID
}

func (s *stubStore) Insert(_ context.Context, _ Alert) (uuid.UUID, error) {
	s.calls.Add(1)
	s.mu.Lock()
	s.lastAt = time.Now()
	s.mu.Unlock()
	if s.err != nil {
		return uuid.Nil, s.err
	}
	if s.returnID != uuid.Nil {
		return s.returnID, nil
	}
	id, _ := uuid.NewV7()
	return id, nil
}

func (s *stubStore) Calls() int64 { return s.calls.Load() }
func (s *stubStore) LastAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAt
}

// orderCapture is a Channel that records the alert it received and the
// time. Lets tests assert persist-before-dispatch ordering + ID
// propagation.
type orderCapture struct {
	mu    sync.Mutex
	last  Alert
	at    time.Time
	count atomic.Int64
}

func (c *orderCapture) Name() string { return "test-order-capture" }
func (c *orderCapture) Send(_ context.Context, a Alert) error {
	c.count.Add(1)
	c.mu.Lock()
	c.last = a
	c.at = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *orderCapture) Calls() int64 { return c.count.Load() }
func (c *orderCapture) LastAlert() Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}
func (c *orderCapture) SawAfter(t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.at.IsZero() && !c.at.Before(t)
}
