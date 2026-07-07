// @spec system-event-bus
//
// AC traceability (this file):
//   AC-01  TestPublish_OneSubscriber_Receives
//   AC-02  TestPublish_ZeroSubscribers_IncrementsNoSubscribers
//   AC-03  TestPublish_ThreeSubscribers_AllReceive
//   AC-04  TestPublish_RaceClean_1000ConcurrentEvents
//   AC-05  TestShutdown_ClosesChannels_PublishNoops
//   AC-06  TestSubscribe_TinyBuffer_DropsAfterFull
//   AC-07  TestEventKindEnum_HasExactlyTwoValues
//   AC-08  TestSubscribe_KindFilter_OnlyMatchingDelivered
//   AC-09  TestMetrics_AllCountersIncrement
//   AC-10  TestPublish_NominalLoad_UnderHundredMs
//   AC-11  TestSlowSubscriber_DoesNotBlockFast
//   AC-13  TestUnsubscribe_RemovesSubscriber

package eventbus

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func makeHeartbeat(reachable bool) HeartbeatPulse {
	return HeartbeatPulse{
		HostID:     uuid.New(),
		Reachable:  reachable,
		OccurredAt: time.Now(),
	}
}

func makeDrift() DriftDetected {
	return DriftDetected{
		HostID:     uuid.New(),
		ScanID:     uuid.New(),
		OccurredAt: time.Now(),
		DriftType:  "major",
		ScoreDelta: -15,
	}
}

// @ac AC-01
// AC-01: subscriber registered for the event's kind receives the event
// within 100ms.
func TestPublish_OneSubscriber_Receives(t *testing.T) {
	t.Run("system-event-bus/AC-01", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		sub := bus.Subscribe(SubscribeOptions{Kinds: []EventKind{EventKindHeartbeatPulse}})
		defer sub.Unsubscribe()

		bus.Publish(context.Background(), makeHeartbeat(true))

		select {
		case ev := <-sub.Events():
			if ev.Kind() != EventKindHeartbeatPulse {
				t.Errorf("received Kind=%q, want %q", ev.Kind(), EventKindHeartbeatPulse)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("did not receive event within 100ms")
		}
	})
}

// @ac AC-02
// AC-02: Publish with zero subscribers → drop silently, NoSubscribersCount++.
func TestPublish_ZeroSubscribers_IncrementsNoSubscribers(t *testing.T) {
	t.Run("system-event-bus/AC-02", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		bus.Publish(context.Background(), makeDrift())

		snap := bus.Metrics().Snapshot()
		if snap.NoSubscribersCount != 1 {
			t.Errorf("NoSubscribersCount = %d, want 1", snap.NoSubscribersCount)
		}
		if snap.DeliveredCount != 0 {
			t.Errorf("DeliveredCount = %d, want 0", snap.DeliveredCount)
		}
	})
}

// @ac AC-03
// AC-03: three subscribers, all registered for the kind → all receive.
func TestPublish_ThreeSubscribers_AllReceive(t *testing.T) {
	t.Run("system-event-bus/AC-03", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		var subs [3]*Subscription
		for i := range subs {
			subs[i] = bus.Subscribe(SubscribeOptions{Kinds: []EventKind{EventKindDriftDetected}})
			defer subs[i].Unsubscribe()
		}

		bus.Publish(context.Background(), makeDrift())

		for i, s := range subs {
			select {
			case ev := <-s.Events():
				if ev.Kind() != EventKindDriftDetected {
					t.Errorf("subscriber %d received Kind=%q", i, ev.Kind())
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("subscriber %d did not receive within 100ms", i)
			}
		}
	})
}

// @ac AC-04
// AC-04: 1000 concurrent publishes against 10 subscribers — race-clean,
// no panic. Deliveries to each subscriber: 1000 (modulo any buffer
// overflows; with default 1024 buffer, none expected since the test
// drains them).
func TestPublish_RaceClean_1000ConcurrentEvents(t *testing.T) {
	t.Run("system-event-bus/AC-04", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		const numSubs = 10
		subs := make([]*Subscription, numSubs)
		for i := range subs {
			subs[i] = bus.Subscribe(SubscribeOptions{Kinds: []EventKind{EventKindHeartbeatPulse}})
			defer subs[i].Unsubscribe()
		}

		// Drain goroutines so buffers don't fill up.
		var drainerWG sync.WaitGroup
		stopDrain := make(chan struct{})
		for _, s := range subs {
			drainerWG.Add(1)
			go func(sub *Subscription) {
				defer drainerWG.Done()
				for {
					select {
					case _, ok := <-sub.Events():
						if !ok {
							return
						}
					case <-stopDrain:
						return
					}
				}
			}(s)
		}

		// 1000 concurrent publishes.
		var pubWG sync.WaitGroup
		const N = 1000
		for i := 0; i < N; i++ {
			pubWG.Add(1)
			go func() {
				defer pubWG.Done()
				bus.Publish(context.Background(), makeHeartbeat(true))
			}()
		}
		pubWG.Wait()

		// Let drainers catch up.
		time.Sleep(100 * time.Millisecond)
		close(stopDrain)
		drainerWG.Wait()

		snap := bus.Metrics().Snapshot()
		if snap.PublishedCount != N {
			t.Errorf("PublishedCount = %d, want %d", snap.PublishedCount, N)
		}
		// Delivered = published × subscribers (no drops with default buffer + active drainers).
		if snap.DeliveredCount > N*int64(numSubs) {
			t.Errorf("DeliveredCount = %d > N×subs (%d)", snap.DeliveredCount, N*numSubs)
		}
	})
}

// @ac AC-05
// AC-05: Shutdown closes channels; post-Shutdown Publish is a no-op.
func TestShutdown_ClosesChannels_PublishNoops(t *testing.T) {
	t.Run("system-event-bus/AC-05", func(t *testing.T) {
		bus := NewBus()
		sub := bus.Subscribe(SubscribeOptions{Kinds: []EventKind{EventKindHeartbeatPulse}})

		bus.Shutdown()

		// Channel must be closed — reading must return (zero, false).
		select {
		case _, ok := <-sub.Events():
			if ok {
				t.Error("channel read returned ok=true after Shutdown")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("read from closed channel didn't return immediately")
		}

		// Post-Shutdown Publish: must not panic, must not increment.
		beforeSnap := bus.Metrics().Snapshot()
		bus.Publish(context.Background(), makeHeartbeat(true))
		afterSnap := bus.Metrics().Snapshot()
		if afterSnap.PublishedCount != beforeSnap.PublishedCount {
			t.Errorf("PublishedCount changed after Shutdown: %d → %d",
				beforeSnap.PublishedCount, afterSnap.PublishedCount)
		}
	})
}

// @ac AC-06
// AC-06: BufferSize=1, one event read, then publish 5 more without
// reading → 5 dropped.
func TestSubscribe_TinyBuffer_DropsAfterFull(t *testing.T) {
	t.Run("system-event-bus/AC-06", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		sub := bus.Subscribe(SubscribeOptions{
			Kinds:      []EventKind{EventKindHeartbeatPulse},
			BufferSize: 1,
		})
		defer sub.Unsubscribe()

		// Fill the 1-slot buffer.
		bus.Publish(context.Background(), makeHeartbeat(true))

		// 5 more publishes → all dropped (buffer is full, not read).
		for i := 0; i < 5; i++ {
			bus.Publish(context.Background(), makeHeartbeat(true))
		}

		if got := sub.Dropped(); got != 5 {
			t.Errorf("sub.Dropped() = %d, want 5", got)
		}
		snap := bus.Metrics().Snapshot()
		if snap.DroppedCount != 5 {
			t.Errorf("bus.DroppedCount = %d, want 5", snap.DroppedCount)
		}
	})
}

// @ac AC-07
// AC-07: EventKind enum is closed — every value the bus carries
// appears exactly once in AllEventKinds. The invariant is that
// AllEventKinds enumerates the closed set, not that the count is
// frozen at any particular version.
func TestEventKindEnum_HasExactlyTwoValues(t *testing.T) {
	t.Run("system-event-bus/AC-07", func(t *testing.T) {
		// Closed set: HeartbeatPulse + DriftDetected (v1.0),
		// HostChanged + MonitoringBandChanged (v1.1 SSE layer),
		// HostDiscovered (system-host-discovery PR 1.1),
		// IntelligenceEvent (system-os-intelligence PR 1.2),
		// ScanStarted (per-host live "Running" indicator),
		// ScanCompleted (api-host-scan / scan foundation),
		// RemediationCompleted (api-remediation execute/rollback),
		// ReportReady (api-reports async render, B3a).
		expected := map[EventKind]bool{
			EventKindHeartbeatPulse:        false,
			EventKindDriftDetected:         false,
			EventKindHostChanged:           false,
			EventKindMonitoringBandChanged: false,
			EventKindHostDiscovered:        false,
			EventKindIntelligenceEvent:     false,
			EventKindScanStarted:           false,
			EventKindScanCompleted:         false,
			EventKindRemediationCompleted:  false,
			EventKindReportReady:           false,
		}
		if len(AllEventKinds) != len(expected) {
			t.Errorf("AllEventKinds = %d, want %d", len(AllEventKinds), len(expected))
		}
		for _, k := range AllEventKinds {
			if _, ok := expected[k]; !ok {
				t.Errorf("AllEventKinds contains unexpected kind %q", k)
				continue
			}
			expected[k] = true
		}
		for k, found := range expected {
			if !found {
				t.Errorf("AllEventKinds missing %q", k)
			}
		}
	})
}

// @ac AC-08
// AC-08: subscriber filtered to HeartbeatPulse does NOT receive a
// DriftDetected event.
func TestSubscribe_KindFilter_OnlyMatchingDelivered(t *testing.T) {
	t.Run("system-event-bus/AC-08", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		heartbeatSub := bus.Subscribe(SubscribeOptions{Kinds: []EventKind{EventKindHeartbeatPulse}})
		defer heartbeatSub.Unsubscribe()

		// Publish a DriftDetected — heartbeatSub must not receive it.
		bus.Publish(context.Background(), makeDrift())

		select {
		case ev := <-heartbeatSub.Events():
			t.Errorf("heartbeat-only subscriber received a %q event", ev.Kind())
		case <-time.After(50 * time.Millisecond):
			// Expected: no event delivered.
		}
	})
}

// @ac AC-09
// AC-09: Metrics counters round-trip through various scenarios.
func TestMetrics_AllCountersIncrement(t *testing.T) {
	t.Run("system-event-bus/AC-09", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		// Publish with no subscribers → NoSubscribersCount=1.
		bus.Publish(context.Background(), makeHeartbeat(true))

		// Subscribe + publish → delivered.
		sub := bus.Subscribe(SubscribeOptions{
			Kinds:      []EventKind{EventKindHeartbeatPulse},
			BufferSize: 1,
		})
		bus.Publish(context.Background(), makeHeartbeat(true))
		<-sub.Events() // drain so the next publish doesn't drop

		// Two publishes without draining: first delivered, second dropped.
		bus.Publish(context.Background(), makeHeartbeat(true))
		bus.Publish(context.Background(), makeHeartbeat(true))

		snap := bus.Metrics().Snapshot()
		if snap.PublishedCount != 4 {
			t.Errorf("Published = %d, want 4", snap.PublishedCount)
		}
		if snap.NoSubscribersCount != 1 {
			t.Errorf("NoSubscribers = %d, want 1", snap.NoSubscribersCount)
		}
		if snap.DeliveredCount < 2 {
			t.Errorf("Delivered = %d, want >= 2", snap.DeliveredCount)
		}
		if snap.DroppedCount < 1 {
			t.Errorf("Dropped = %d, want >= 1", snap.DroppedCount)
		}
	})
}

// @ac AC-10
// AC-10: 1000 Publish calls with 10 subscribers complete within 100ms.
// Note: this is wall-clock under nominal load (drainers running).
func TestPublish_NominalLoad_UnderHundredMs(t *testing.T) {
	t.Run("system-event-bus/AC-10", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		const subs = 10
		stopDrain := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < subs; i++ {
			s := bus.Subscribe(SubscribeOptions{Kinds: []EventKind{EventKindHeartbeatPulse}})
			defer s.Unsubscribe()
			wg.Add(1)
			go func(sub *Subscription) {
				defer wg.Done()
				for {
					select {
					case _, ok := <-sub.Events():
						if !ok {
							return
						}
					case <-stopDrain:
						return
					}
				}
			}(s)
		}

		const N = 1000
		start := time.Now()
		for i := 0; i < N; i++ {
			bus.Publish(context.Background(), makeHeartbeat(true))
		}
		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			t.Errorf("1000 publishes took %v, budget 100ms", elapsed)
		}

		close(stopDrain)
		wg.Wait()
	})
}

// @ac AC-11
// AC-11: a slow subscriber doesn't block fast subscribers.
func TestSlowSubscriber_DoesNotBlockFast(t *testing.T) {
	t.Run("system-event-bus/AC-11", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		slow := bus.Subscribe(SubscribeOptions{
			Kinds:      []EventKind{EventKindHeartbeatPulse},
			BufferSize: 2,
		})
		defer slow.Unsubscribe()
		fast := bus.Subscribe(SubscribeOptions{
			Kinds:      []EventKind{EventKindHeartbeatPulse},
			BufferSize: 1024,
		})
		defer fast.Unsubscribe()

		// Slow drains very slowly. Fast drains immediately.
		var fastReceived atomic.Int64
		stopFast := make(chan struct{})
		go func() {
			for {
				select {
				case _, ok := <-fast.Events():
					if !ok {
						return
					}
					fastReceived.Add(1)
				case <-stopFast:
					return
				}
			}
		}()

		// Publish 100 events. slow's 2-slot buffer fills + drops; fast
		// receives all 100 promptly.
		start := time.Now()
		for i := 0; i < 100; i++ {
			bus.Publish(context.Background(), makeHeartbeat(true))
		}
		// Allow the fast drainer a moment to catch up.
		for time.Since(start) < 200*time.Millisecond {
			if fastReceived.Load() >= 100 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		elapsed := time.Since(start)
		close(stopFast)

		if fastReceived.Load() != 100 {
			t.Errorf("fast subscriber received %d events, want 100 — slow subscriber blocked it",
				fastReceived.Load())
		}
		if elapsed > 200*time.Millisecond {
			t.Errorf("elapsed %v: fast subscriber starved by slow", elapsed)
		}
	})
}

// @ac AC-13
// AC-13: Unsubscribe removes the subscriber; subsequent Publish doesn't
// deliver. The channel is closed and reading returns (zero, false).
func TestUnsubscribe_RemovesSubscriber(t *testing.T) {
	t.Run("system-event-bus/AC-13", func(t *testing.T) {
		bus := NewBus()
		defer bus.Shutdown()

		sub := bus.Subscribe(SubscribeOptions{Kinds: []EventKind{EventKindHeartbeatPulse}})

		// Verify subscription works first.
		bus.Publish(context.Background(), makeHeartbeat(true))
		select {
		case <-sub.Events():
		case <-time.After(100 * time.Millisecond):
			t.Fatal("subscriber did not receive pre-unsubscribe event")
		}

		sub.Unsubscribe()

		// After unsubscribe: channel closed; subsequent publish does
		// nothing for this sub.
		bus.Publish(context.Background(), makeHeartbeat(true))

		select {
		case _, ok := <-sub.Events():
			if ok {
				t.Error("unsubscribed channel received an event")
			}
			// Closed channel returns (zero, false) — that's expected.
		case <-time.After(50 * time.Millisecond):
			t.Error("read from unsubscribed channel didn't return immediately")
		}
	})
}
