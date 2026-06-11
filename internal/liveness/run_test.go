// @spec system-liveness-loop
//
// AC traceability (this file):
//   AC-16  TestRun_EmptyInventory_TicksWithoutPanic
//   AC-17  TestRun_WalksAllActiveHosts
//   AC-18  TestRun_SkipsBackoffSuppressedHosts
//   AC-19  TestRun_ReturnsOnCtxCancel
//   AC-20  TestPublishHeartbeat_ReachableToUnreachable
//   AC-21  TestPublishHeartbeat_UnreachableToReachable
//   AC-22  TestPublishHeartbeat_SteadyState_NoPublish
//   AC-23  TestNewService_NilBus_AuditStillFires

package liveness

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/eventbus"
)

// recordingProbe captures every (hostID, addr) invocation. Returns
// the reachable result by default; tests can override per call.
type recordingProbe struct {
	mu     sync.Mutex
	calls  []uuid.UUID
	result ProbeResult
}

func newRecordingProbe(result ProbeResult) *recordingProbe {
	return &recordingProbe{result: result}
}

func (p *recordingProbe) fn() ProbeFunc {
	return func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
		p.mu.Lock()
		p.calls = append(p.calls, hostFromAddr(addr))
		p.mu.Unlock()
		return p.result
	}
}

func (p *recordingProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

// hostFromAddr is a placeholder — the ProbeFunc receives only the
// addr (host:port), not the host_id. Tests use a constant address per
// host and inspect probe counts rather than per-host identity.
func hostFromAddr(addr string) uuid.UUID { return uuid.Nil }

// seedBackoff inserts a host_backoff_state row with the given
// suppress_until.
func seedBackoff(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, suppressUntil time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_backoff_state (host_id, probe_type, consecutive_failures, suppress_until)
		VALUES ($1, 'scan', 3, $2)`,
		hostID, suppressUntil,
	)
	if err != nil {
		t.Fatalf("seed backoff: %v", err)
	}
}

// @ac AC-16
// AC-16: Run on a fleet with no hosts ticks without panic and produces
// zero probes per tick. We let one tick fire via the initial Run-then-
// cancel path.
func TestRun_EmptyInventory_TicksWithoutPanic(t *testing.T) {
	t.Run("system-liveness-loop/AC-16", func(t *testing.T) {
		pool := freshPool(t)
		var mu sync.Mutex
		var calls []emitCall
		probe := newRecordingProbe(ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond})

		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).
			WithProbeFunc(probe.fn()).
			WithInterval(100 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()

		done := make(chan struct{})
		go func() {
			svc.Run(ctx)
			close(done)
		}()
		<-done

		if probe.count() != 0 {
			t.Errorf("empty inventory triggered %d probes; want 0", probe.count())
		}
	})
}

// @ac AC-17
// AC-17: Run walks active hosts. 3 hosts seeded, 1 tick → 3 probes.
func TestRun_WalksAllActiveHosts(t *testing.T) {
	t.Run("system-liveness-loop/AC-17", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		for i := 0; i < 3; i++ {
			seedHost(t, pool, user)
		}
		var mu sync.Mutex
		var calls []emitCall
		probe := newRecordingProbe(ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond})

		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).
			WithProbeFunc(probe.fn()).
			WithInterval(time.Hour) // never re-ticks; relies on initial tick

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		done := make(chan struct{})
		go func() { svc.Run(ctx); close(done) }()
		<-done

		if probe.count() != 3 {
			t.Errorf("got %d probes; want 3", probe.count())
		}
	})
}

// @ac AC-18
// AC-18: Run skips hosts whose host_backoff_state.suppress_until is
// in the future. 3 hosts seeded; 1 with future suppress → 2 probes per tick.
func TestRun_SkipsBackoffSuppressedHosts(t *testing.T) {
	t.Run("system-liveness-loop/AC-18", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		h1 := seedHost(t, pool, user)
		_ = seedHost(t, pool, user)
		_ = seedHost(t, pool, user)
		// h1 is back-offed for 1h.
		seedBackoff(t, pool, h1, time.Now().Add(1*time.Hour))

		var mu sync.Mutex
		var calls []emitCall
		probe := newRecordingProbe(ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond})

		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).
			WithProbeFunc(probe.fn()).
			WithInterval(time.Hour)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		done := make(chan struct{})
		go func() { svc.Run(ctx); close(done) }()
		<-done

		if probe.count() != 2 {
			t.Errorf("got %d probes; want 2 (1 host suppressed by backoff)", probe.count())
		}
	})
}

// @ac AC-19
// AC-19: Run returns within 2s of ctx cancel.
func TestRun_ReturnsOnCtxCancel(t *testing.T) {
	t.Run("system-liveness-loop/AC-19", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall
		var probesStarted atomic.Int64
		slowProbe := ProbeFunc(func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
			probesStarted.Add(1)
			// Honor ctx — that's the AC; a misbehaving probe could
			// hang. We sleep up to 500ms but ctx cancellation
			// short-circuits.
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
			}
			return ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond}
		})

		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).
			WithProbeFunc(slowProbe).
			WithInterval(time.Hour)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		start := time.Now()
		go func() { svc.Run(ctx); close(done) }()
		// Cancel after 100ms so a probe is in-flight.
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case <-done:
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("Run took %v to exit after ctx cancel; want < 2s", elapsed)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return within 2s of ctx cancel")
		}
	})
}

// @ac AC-20
// AC-20: reachable -> unreachable transition publishes HeartbeatPulse{Reachable=false}.
func TestPublishHeartbeat_ReachableToUnreachable(t *testing.T) {
	t.Run("system-liveness-loop/AC-20", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		bus := eventbus.NewBus()
		defer bus.Shutdown()
		sub := bus.Subscribe(eventbus.SubscribeOptions{
			Kinds: []eventbus.EventKind{eventbus.EventKindHeartbeatPulse},
		})
		defer sub.Unsubscribe()

		// First probe — reachable — establishes the prior state.
		svc := NewService(pool, fakeEmitter(&mu, &calls), bus).
			WithProbeFunc(func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
				return ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond}
			})
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")

		// Drain the reachable-transition event so we only assert on
		// the next one.
		select {
		case <-sub.Events():
		case <-time.After(200 * time.Millisecond):
			t.Fatal("did not receive initial first-seen event")
		}

		// Threshold = 2 consecutive failures, so probe twice failing.
		svc2 := NewService(pool, fakeEmitter(&mu, &calls), bus).
			WithProbeFunc(func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
				return ProbeResult{Reachable: false, ResponseTime: 0}
			})
		_, _ = svc2.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		_, _ = svc2.ProbeHost(context.Background(), hostID, "192.0.2.10:22")

		select {
		case ev := <-sub.Events():
			hp, ok := ev.(eventbus.HeartbeatPulse)
			if !ok {
				t.Fatalf("got %T, want HeartbeatPulse", ev)
			}
			if hp.Reachable {
				t.Errorf("HeartbeatPulse.Reachable = true, want false (transition to unreachable)")
			}
			if !hp.PriorReachable {
				t.Errorf("HeartbeatPulse.PriorReachable = false, want true")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("no HeartbeatPulse received within 500ms")
		}
	})
}

// @ac AC-21
// AC-21: unreachable -> reachable transition publishes HeartbeatPulse{Reachable=true, PriorReachable=false}.
func TestPublishHeartbeat_UnreachableToReachable(t *testing.T) {
	t.Run("system-liveness-loop/AC-21", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		bus := eventbus.NewBus()
		defer bus.Shutdown()
		sub := bus.Subscribe(eventbus.SubscribeOptions{
			Kinds: []eventbus.EventKind{eventbus.EventKindHeartbeatPulse},
		})
		defer sub.Unsubscribe()

		// Probe twice failing to drive the host to unreachable.
		svc := NewService(pool, fakeEmitter(&mu, &calls), bus).
			WithProbeFunc(func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
				return ProbeResult{Reachable: false}
			})
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")

		// Drain the first-seen + transition-to-unreachable events.
		for i := 0; i < 2; i++ {
			select {
			case <-sub.Events():
			case <-time.After(200 * time.Millisecond):
			}
		}

		// Now probe successfully.
		svc2 := NewService(pool, fakeEmitter(&mu, &calls), bus).
			WithProbeFunc(func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
				return ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond}
			})
		_, _ = svc2.ProbeHost(context.Background(), hostID, "192.0.2.10:22")

		select {
		case ev := <-sub.Events():
			hp, ok := ev.(eventbus.HeartbeatPulse)
			if !ok {
				t.Fatalf("got %T", ev)
			}
			if !hp.Reachable {
				t.Errorf("HeartbeatPulse.Reachable = false, want true")
			}
			if hp.PriorReachable {
				t.Errorf("HeartbeatPulse.PriorReachable = true, want false")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("no HeartbeatPulse received")
		}
	})
}

// @ac AC-22
// AC-22: steady-state probe (no transition) does NOT publish.
func TestPublishHeartbeat_SteadyState_NoPublish(t *testing.T) {
	t.Run("system-liveness-loop/AC-22", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		bus := eventbus.NewBus()
		defer bus.Shutdown()
		sub := bus.Subscribe(eventbus.SubscribeOptions{
			Kinds: []eventbus.EventKind{eventbus.EventKindHeartbeatPulse},
		})
		defer sub.Unsubscribe()

		svc := NewService(pool, fakeEmitter(&mu, &calls), bus).
			WithProbeFunc(func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
				return ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond}
			})

		// First probe: first-seen transition. Drain.
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		select {
		case <-sub.Events():
		case <-time.After(200 * time.Millisecond):
			t.Fatal("did not receive first-seen event")
		}

		// Second probe: same state, no transition, no publish expected.
		_, _ = svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		select {
		case ev := <-sub.Events():
			t.Errorf("received unexpected HeartbeatPulse on steady state: %+v", ev)
		case <-time.After(150 * time.Millisecond):
			// Expected — no event.
		}
	})
}

// @ac AC-23
// AC-23: NewService with nil bus still emits audit on transitions.
func TestNewService_NilBus_AuditStillFires(t *testing.T) {
	t.Run("system-liveness-loop/AC-23", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		svc := NewService(pool, fakeEmitter(&mu, &calls), nil).
			WithProbeFunc(func(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
				return ProbeResult{Reachable: true, ResponseTime: 10 * time.Millisecond}
			})

		_, err := svc.ProbeHost(context.Background(), hostID, "192.0.2.10:22")
		if err != nil {
			t.Fatalf("ProbeHost: %v", err)
		}
		// First-seen transition → audit fires.
		mu.Lock()
		got := len(calls)
		mu.Unlock()
		if got == 0 {
			t.Error("nil bus suppressed audit emission; want audit still fires")
		}
	})
}
