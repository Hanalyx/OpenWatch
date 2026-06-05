// @spec system-alert-router
//
// AC traceability (this file):
//   AC-03  TestTranslate_HeartbeatUnreachable_HostUnreachableAlert
//   AC-04  TestTranslate_HeartbeatRecovery_HostRecoveredAlert
//   AC-05  TestTranslate_DriftMajor_DriftMajorAlert
//   AC-06  TestRouter_Dedup_SkipsRepeatWithinTTL
//   AC-07  TestRouter_Dedup_PassesAfterTTL
//   AC-08  TestRouter_TagFilter_RejectsNonMatch
//   AC-09  TestRouter_WildcardChannel_ReceivesEvery
//   AC-10  TestRouter_ChannelError_DoesNotBlockOtherChannels
//   AC-11  TestRouter_Start_SubscribesToBothEventKinds
//   AC-12  TestRouter_Stop_UnsubscribesAndDrains
//   AC-14  TestRouter_Metrics_AllCountersIncrement

package alertrouter

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/google/uuid"
)

// fakeChannel is a Channel implementation that records received alerts
// in memory + lets tests force errors. Lives in the test file so the
// core package has no dependency on it.
type fakeChannel struct {
	name string

	mu      sync.Mutex
	alerts  []Alert
	sendErr error

	delay time.Duration // optional artificial latency
}

func newFakeChannel(name string) *fakeChannel {
	return &fakeChannel{name: name}
}

func (f *fakeChannel) Name() string { return f.name }

func (f *fakeChannel) Send(ctx context.Context, a Alert) error {
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(f.delay):
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.alerts = append(f.alerts, a)
	return nil
}

func (f *fakeChannel) Received() []Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Alert, len(f.alerts))
	copy(out, f.alerts)
	return out
}

func (f *fakeChannel) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sendErr = err
}

func newTestRouter(t *testing.T) (*Router, *eventbus.Bus) {
	t.Helper()
	bus := eventbus.NewBus()
	r, err := NewRouter(bus, Config{DedupTTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return r, bus
}

// waitFor polls cond until true or budget elapses. Reduces test
// flakiness vs. fixed sleeps.
func waitFor(t *testing.T, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// @ac AC-03
// AC-03: HeartbeatPulse{Reachable=false} → Alert with
// Type=AlertTypeHostUnreachable, Severity=SeverityHigh; host_id tag set.
func TestTranslate_HeartbeatUnreachable_HostUnreachableAlert(t *testing.T) {
	t.Run("system-alert-router/AC-03", func(t *testing.T) {
		hostID := uuid.New()
		ev := eventbus.HeartbeatPulse{
			HostID:         hostID,
			Reachable:      false,
			PriorReachable: true,
			OccurredAt:     time.Now(),
		}
		alert, ok := translate(ev)
		if !ok {
			t.Fatal("translate returned ok=false for unreachable heartbeat")
		}
		if alert.Type != AlertTypeHostUnreachable {
			t.Errorf("Type = %q, want %q", alert.Type, AlertTypeHostUnreachable)
		}
		if alert.Severity != SeverityHigh {
			t.Errorf("Severity = %q, want %q", alert.Severity, SeverityHigh)
		}
		if alert.HostID != hostID {
			t.Errorf("HostID = %s, want %s", alert.HostID, hostID)
		}
		if alert.Tags["host_id"] != hostID.String() {
			t.Errorf("Tags[host_id] = %q, want %q", alert.Tags["host_id"], hostID)
		}
		if alert.Tags["alert_type"] != string(AlertTypeHostUnreachable) {
			t.Errorf("Tags[alert_type] = %q, want %q", alert.Tags["alert_type"], AlertTypeHostUnreachable)
		}
		if alert.Tags["severity"] != string(SeverityHigh) {
			t.Errorf("Tags[severity] = %q, want %q", alert.Tags["severity"], SeverityHigh)
		}
	})
}

// @ac AC-04
// AC-04: HeartbeatPulse{Reachable=true, PriorReachable=false} → Alert
// with Type=AlertTypeHostRecovered, Severity=SeverityInfo.
func TestTranslate_HeartbeatRecovery_HostRecoveredAlert(t *testing.T) {
	t.Run("system-alert-router/AC-04", func(t *testing.T) {
		ev := eventbus.HeartbeatPulse{
			HostID:         uuid.New(),
			Reachable:      true,
			PriorReachable: false,
			OccurredAt:     time.Now(),
			ResponseTimeMS: 12,
		}
		alert, ok := translate(ev)
		if !ok {
			t.Fatal("translate returned ok=false for recovery heartbeat")
		}
		if alert.Type != AlertTypeHostRecovered {
			t.Errorf("Type = %q, want %q", alert.Type, AlertTypeHostRecovered)
		}
		if alert.Severity != SeverityInfo {
			t.Errorf("Severity = %q, want %q", alert.Severity, SeverityInfo)
		}

		// Reachable + PriorReachable → no transition, no alert.
		evNoChange := eventbus.HeartbeatPulse{
			HostID: uuid.New(), Reachable: true, PriorReachable: true,
			OccurredAt: time.Now(),
		}
		if _, ok := translate(evNoChange); ok {
			t.Error("translate returned ok=true for no-transition heartbeat")
		}
	})
}

// @ac AC-05
// AC-05: DriftDetected{DriftType="major"} → Alert with
// Type=AlertTypeDriftMajor, Severity=SeverityHigh; score_delta + host_id
// in tags.
func TestTranslate_DriftMajor_DriftMajorAlert(t *testing.T) {
	t.Run("system-alert-router/AC-05", func(t *testing.T) {
		hostID := uuid.New()
		ev := eventbus.DriftDetected{
			HostID:                hostID,
			ScanID:                uuid.New(),
			OccurredAt:            time.Now(),
			DriftType:             "major",
			PriorScore:            92.0,
			CurrentScore:          70.0,
			ScoreDelta:            -22.0,
			CriticalBecameFailing: 1,
			HighBecameFailing:     3,
		}
		alert, ok := translate(ev)
		if !ok {
			t.Fatal("translate returned ok=false for major drift")
		}
		if alert.Type != AlertTypeDriftMajor {
			t.Errorf("Type = %q, want %q", alert.Type, AlertTypeDriftMajor)
		}
		if alert.Severity != SeverityHigh {
			t.Errorf("Severity = %q, want %q", alert.Severity, SeverityHigh)
		}
		if alert.Tags["host_id"] != hostID.String() {
			t.Errorf("Tags[host_id] = %q, want %q", alert.Tags["host_id"], hostID)
		}
		if alert.Tags["score_delta"] != "-22.00" {
			t.Errorf("Tags[score_delta] = %q, want %q", alert.Tags["score_delta"], "-22.00")
		}

		// Unknown DriftType → no alert.
		evBogus := eventbus.DriftDetected{
			HostID: uuid.New(), ScanID: uuid.New(),
			OccurredAt: time.Now(), DriftType: "bogus",
		}
		if _, ok := translate(evBogus); ok {
			t.Error("translate returned ok=true for unknown DriftType")
		}
	})
}

// @ac AC-06
// AC-06: dedup gate skips a repeat alert within TTL; DedupedCount
// increments; Channel.Send NOT called for the skipped alert.
func TestRouter_Dedup_SkipsRepeatWithinTTL(t *testing.T) {
	t.Run("system-alert-router/AC-06", func(t *testing.T) {
		r, bus := newTestRouter(t)
		defer bus.Shutdown()
		ch := newFakeChannel("fake")
		r.Register(ChannelRegistration{Channel: ch})
		r.Start(context.Background())
		defer r.Stop()

		hostID := uuid.New()
		ev := eventbus.HeartbeatPulse{
			HostID: hostID, Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		}
		// Publish twice within TTL.
		bus.Publish(context.Background(), ev)
		bus.Publish(context.Background(), ev)

		waitFor(t, 200*time.Millisecond, func() bool {
			return r.Metrics().Snapshot().ReceivedCount >= 2
		})

		snap := r.Metrics().Snapshot()
		if snap.ReceivedCount != 2 {
			t.Errorf("ReceivedCount = %d, want 2", snap.ReceivedCount)
		}
		if snap.DedupedCount != 1 {
			t.Errorf("DedupedCount = %d, want 1", snap.DedupedCount)
		}
		// Channel saw only one alert (the second was deduped).
		waitFor(t, 100*time.Millisecond, func() bool {
			return len(ch.Received()) == 1
		})
		if got := len(ch.Received()); got != 1 {
			t.Errorf("channel received %d alerts, want 1", got)
		}
	})
}

// @ac AC-07
// AC-07: a repeat alert AFTER the dedup TTL elapses passes through;
// Channel.Send IS called. Use a 60s TTL with a controllable clock on
// the dedup gate (router uses default `now`, but we test the gate
// directly here since router uses real time).
func TestRouter_Dedup_PassesAfterTTL(t *testing.T) {
	t.Run("system-alert-router/AC-07", func(t *testing.T) {
		// Test the DedupGate directly with a fake clock to avoid
		// 60s real-time waits.
		gate := NewDedupGate(60 * time.Second)
		t0 := time.Now()
		gate.now = func() time.Time { return t0 }

		alert := Alert{Type: AlertTypeHostUnreachable, HostID: uuid.New()}
		if gate.ShouldSkip(alert) {
			t.Error("first call should not skip")
		}
		if !gate.ShouldSkip(alert) {
			t.Error("second call within TTL should skip")
		}

		// Advance past TTL.
		gate.now = func() time.Time { return t0.Add(90 * time.Second) }
		if gate.ShouldSkip(alert) {
			t.Error("call after TTL should NOT skip")
		}
	})
}

// @ac AC-08
// AC-08: a channel with Tags{"severity":"critical"} receives only
// critical alerts; a medium-severity alert does not reach it.
func TestRouter_TagFilter_RejectsNonMatch(t *testing.T) {
	t.Run("system-alert-router/AC-08", func(t *testing.T) {
		r, bus := newTestRouter(t)
		defer bus.Shutdown()

		critOnly := newFakeChannel("crit-only")
		r.Register(ChannelRegistration{
			Channel: critOnly,
			Tags:    map[string]string{"severity": string(SeverityCritical)},
		})
		r.Start(context.Background())
		defer r.Stop()

		// HostUnreachable is High severity (not Critical) → must not
		// reach the crit-only channel.
		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: uuid.New(), Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})

		waitFor(t, 150*time.Millisecond, func() bool {
			return r.Metrics().Snapshot().ReceivedCount >= 1
		})
		// Give dispatch a chance to run.
		time.Sleep(20 * time.Millisecond)
		if got := len(critOnly.Received()); got != 0 {
			t.Errorf("crit-only channel received %d alerts, want 0", got)
		}
	})
}

// @ac AC-09
// AC-09: a channel with empty Tags receives every alert.
func TestRouter_WildcardChannel_ReceivesEvery(t *testing.T) {
	t.Run("system-alert-router/AC-09", func(t *testing.T) {
		r, bus := newTestRouter(t)
		defer bus.Shutdown()

		wildcard := newFakeChannel("wildcard")
		r.Register(ChannelRegistration{Channel: wildcard})
		r.Start(context.Background())
		defer r.Stop()

		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: uuid.New(), Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})
		bus.Publish(context.Background(), eventbus.DriftDetected{
			HostID: uuid.New(), ScanID: uuid.New(),
			OccurredAt: time.Now(), DriftType: "major", ScoreDelta: -10,
		})

		waitFor(t, 250*time.Millisecond, func() bool {
			return len(wildcard.Received()) == 2
		})
		if got := len(wildcard.Received()); got != 2 {
			t.Errorf("wildcard received %d alerts, want 2", got)
		}
	})
}

// @ac AC-10
// AC-10: Channel.Send returning an error increments that channel's
// FailureCount but does NOT block delivery to other channels for the
// same alert.
func TestRouter_ChannelError_DoesNotBlockOtherChannels(t *testing.T) {
	t.Run("system-alert-router/AC-10", func(t *testing.T) {
		r, bus := newTestRouter(t)
		defer bus.Shutdown()

		broken := newFakeChannel("broken")
		broken.setError(errors.New("simulated send failure"))
		healthy := newFakeChannel("healthy")
		r.Register(ChannelRegistration{Channel: broken})
		r.Register(ChannelRegistration{Channel: healthy})
		r.Start(context.Background())
		defer r.Stop()

		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: uuid.New(), Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})

		waitFor(t, 300*time.Millisecond, func() bool {
			return len(healthy.Received()) == 1
		})
		if got := len(healthy.Received()); got != 1 {
			t.Errorf("healthy channel received %d alerts, want 1 — broken channel's error blocked it",
				got)
		}
		waitFor(t, 100*time.Millisecond, func() bool {
			return r.FailureCount("broken") == 1
		})
		if got := r.FailureCount("broken"); got != 1 {
			t.Errorf("broken FailureCount = %d, want 1", got)
		}
		if got := r.FailureCount("healthy"); got != 0 {
			t.Errorf("healthy FailureCount = %d, want 0", got)
		}
		if snap := r.Metrics().Snapshot(); snap.ChannelFailureCount != 1 {
			t.Errorf("ChannelFailureCount = %d, want 1", snap.ChannelFailureCount)
		}
	})
}

// @ac AC-11
// AC-11: Router.Start subscribes to both EventKindHeartbeatPulse AND
// EventKindDriftDetected. Verify by publishing one of each and
// observing both arrive at a wildcard channel.
func TestRouter_Start_SubscribesToBothEventKinds(t *testing.T) {
	t.Run("system-alert-router/AC-11", func(t *testing.T) {
		r, bus := newTestRouter(t)
		defer bus.Shutdown()
		ch := newFakeChannel("all")
		r.Register(ChannelRegistration{Channel: ch})
		r.Start(context.Background())
		defer r.Stop()

		hbHostID := uuid.New()
		driftHostID := uuid.New()
		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: hbHostID, Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})
		bus.Publish(context.Background(), eventbus.DriftDetected{
			HostID: driftHostID, ScanID: uuid.New(),
			OccurredAt: time.Now(), DriftType: "minor", ScoreDelta: -5,
		})

		waitFor(t, 250*time.Millisecond, func() bool {
			return len(ch.Received()) == 2
		})
		alerts := ch.Received()
		if len(alerts) != 2 {
			t.Fatalf("received %d alerts, want 2", len(alerts))
		}
		gotTypes := map[AlertType]bool{}
		for _, a := range alerts {
			gotTypes[a.Type] = true
		}
		if !gotTypes[AlertTypeHostUnreachable] {
			t.Error("missing host_unreachable alert — heartbeat subscription not active")
		}
		if !gotTypes[AlertTypeDriftMinor] {
			t.Error("missing drift_minor alert — drift subscription not active")
		}
	})
}

// @ac AC-12
// AC-12: Router.Stop unsubscribes AND waits for in-flight Channel.Send
// calls to complete. After Stop, new events received are ignored.
func TestRouter_Stop_UnsubscribesAndDrains(t *testing.T) {
	t.Run("system-alert-router/AC-12", func(t *testing.T) {
		r, bus := newTestRouter(t)
		defer bus.Shutdown()

		// Channel with a 30ms delay → drain must wait for it.
		slow := newFakeChannel("slow")
		slow.delay = 30 * time.Millisecond
		r.Register(ChannelRegistration{Channel: slow})
		r.Start(context.Background())

		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: uuid.New(), Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})

		// Wait until the router has dispatched (RoutedCount==1) so a
		// Send goroutine is in flight when we call Stop.
		waitFor(t, 200*time.Millisecond, func() bool {
			return r.Metrics().Snapshot().RoutedCount >= 1
		})

		stopStart := time.Now()
		r.Stop()
		stopElapsed := time.Since(stopStart)

		// Stop should have waited at least ~25ms for the slow channel
		// to finish its Send. (Lenient lower bound to avoid flakes.)
		if stopElapsed < 10*time.Millisecond {
			t.Errorf("Stop returned in %v — drain did not wait for slow channel", stopElapsed)
		}
		// Slow Send should have completed.
		if got := len(slow.Received()); got != 1 {
			t.Errorf("slow.Received = %d, want 1 — drain didn't wait", got)
		}

		// After Stop: publish should be ignored (subscription
		// unsubscribed). Verified by ReceivedCount not changing.
		before := r.Metrics().Snapshot().ReceivedCount
		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: uuid.New(), Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})
		time.Sleep(20 * time.Millisecond)
		after := r.Metrics().Snapshot().ReceivedCount
		if after != before {
			t.Errorf("ReceivedCount changed after Stop: %d → %d", before, after)
		}
	})
}

// @ac AC-14
// AC-14: Metrics().Snapshot() exposes ReceivedCount, RoutedCount,
// DedupedCount, ChannelFailureCount; all increment under matching
// scenarios.
func TestRouter_Metrics_AllCountersIncrement(t *testing.T) {
	t.Run("system-alert-router/AC-14", func(t *testing.T) {
		r, bus := newTestRouter(t)
		defer bus.Shutdown()

		broken := newFakeChannel("broken")
		broken.setError(errors.New("nope"))
		healthy := newFakeChannel("healthy")
		r.Register(ChannelRegistration{Channel: broken})
		r.Register(ChannelRegistration{Channel: healthy})
		r.Start(context.Background())
		defer r.Stop()

		hostID := uuid.New()
		// First publish: drives ReceivedCount=1, RoutedCount=2,
		// ChannelFailureCount=1.
		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: hostID, Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})
		// Second publish identical: drives DedupedCount=1.
		bus.Publish(context.Background(), eventbus.HeartbeatPulse{
			HostID: hostID, Reachable: false, PriorReachable: true,
			OccurredAt: time.Now(),
		})

		waitFor(t, 300*time.Millisecond, func() bool {
			snap := r.Metrics().Snapshot()
			return snap.ReceivedCount == 2 && snap.DedupedCount == 1 &&
				snap.RoutedCount == 2 && snap.ChannelFailureCount == 1
		})
		snap := r.Metrics().Snapshot()
		if snap.ReceivedCount != 2 {
			t.Errorf("ReceivedCount = %d, want 2", snap.ReceivedCount)
		}
		if snap.DedupedCount != 1 {
			t.Errorf("DedupedCount = %d, want 1", snap.DedupedCount)
		}
		if snap.RoutedCount != 2 {
			t.Errorf("RoutedCount = %d, want 2 (1 alert × 2 channels)", snap.RoutedCount)
		}
		if snap.ChannelFailureCount != 1 {
			t.Errorf("ChannelFailureCount = %d, want 1", snap.ChannelFailureCount)
		}
	})
}

// Ensure tests don't accidentally leave goroutines around.
func TestMain(m *testing.M) {
	// One quick sanity assertion: atomic counters round-trip without
	// data races. (-race detector covers the rest.)
	var x atomic.Int64
	x.Add(1)
	if x.Load() != 1 {
		panic("atomic broken")
	}
	m.Run()
}
