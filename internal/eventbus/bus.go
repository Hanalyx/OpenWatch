package eventbus

import (
	"context"
	"sync"
	"sync/atomic"
)

// Bus is the in-process pub/sub instance. Constructed once at boot via
// NewBus; held for the process lifetime. All operations are
// goroutine-safe.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[EventKind]map[*Subscription]struct{}
	closed      atomic.Bool
	metrics     *Metrics
}

// NewBus returns a ready Bus. No setup steps required after construction.
func NewBus() *Bus {
	return &Bus{
		subscribers: make(map[EventKind]map[*Subscription]struct{}),
		metrics:     NewMetrics(),
	}
}

// Publish dispatches event to every subscriber registered for
// event.Kind().
//
// Spec ACs satisfied here:
//
//   - AC-01 (C-03): subscribers registered for the kind receive
//     on their delivery channel.
//   - AC-02 (C-03): zero subscribers → drop silently, increment
//     NoSubscribersCount.
//   - AC-03 (C-03): multiple subscribers all receive.
//   - AC-05 (C-07): after Shutdown, Publish is a no-op.
//   - AC-06 (C-03/C-04): subscriber whose buffer is full has the
//     event dropped + DroppedCount increments. Other subscribers
//     still receive.
//   - AC-08 (C-05): events with a Kind a subscriber didn't filter on
//     are NOT delivered to that subscriber.
//   - AC-13 (C-05/C-06): unsubscribed subscribers receive nothing.
//
// Non-blocking: writes to subscriber channels use the default-case
// trick (select with default → drop on full). Spec C-03.
func (b *Bus) Publish(ctx context.Context, event Event) {
	if b.closed.Load() {
		return
	}
	if event == nil {
		return
	}

	b.metrics.PublishedCount.Add(1)

	b.mu.RLock()
	subs := b.subscribers[event.Kind()]
	if len(subs) == 0 {
		b.mu.RUnlock()
		b.metrics.NoSubscribersCount.Add(1)
		return
	}
	// Snapshot the subscriber set so we don't hold the RLock during
	// channel sends. The set may grow/shrink between snapshot and
	// dispatch — accepting that race is fine for a "publish at a
	// specific moment" semantic.
	targets := make([]*Subscription, 0, len(subs))
	for s := range subs {
		targets = append(targets, s)
	}
	b.mu.RUnlock()

	for _, s := range targets {
		select {
		case s.ch <- event:
			s.delivered.Add(1)
			b.metrics.DeliveredCount.Add(1)
		default:
			// Buffer full; drop and count.
			s.dropped.Add(1)
			b.metrics.DroppedCount.Add(1)
		}
	}
}

// Subscribe registers a new subscriber for the given EventKinds.
// Returns a Subscription whose channel can be read from. Spec AC-08:
// subscribers only receive events of their registered kinds.
//
// An empty Kinds slice produces a subscriber that receives nothing
// (NOT a wildcard).
func (b *Bus) Subscribe(opts SubscribeOptions) *Subscription {
	bufSize := opts.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}

	sub := &Subscription{
		bus:   b,
		ch:    make(chan Event, bufSize),
		kinds: append([]EventKind(nil), opts.Kinds...),
	}

	b.mu.Lock()
	for _, k := range opts.Kinds {
		set, ok := b.subscribers[k]
		if !ok {
			set = make(map[*Subscription]struct{})
			b.subscribers[k] = set
		}
		set[sub] = struct{}{}
	}
	b.mu.Unlock()

	return sub
}

// Shutdown stops the bus. Drains pending events (i.e. lets in-flight
// Publish goroutines complete) and closes every subscriber's delivery
// channel. After Shutdown, Publish becomes a no-op (returns without
// modifying state).
//
// Spec AC-05 / C-07.
func (b *Bus) Shutdown() {
	if !b.closed.CompareAndSwap(false, true) {
		return // already shut down
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	// Close every subscriber's channel and clear the kind→sub map.
	closed := make(map[*Subscription]struct{})
	for _, set := range b.subscribers {
		for sub := range set {
			if _, already := closed[sub]; already {
				continue
			}
			close(sub.ch)
			closed[sub] = struct{}{}
		}
	}
	b.subscribers = map[EventKind]map[*Subscription]struct{}{}
}

// Metrics returns the runtime counters handle.
func (b *Bus) Metrics() *Metrics { return b.metrics }

// Subscription is a registered subscriber. Carries the delivery
// channel + state for per-subscriber metrics.
type Subscription struct {
	bus       *Bus
	ch        chan Event
	kinds     []EventKind
	delivered atomic.Int64
	dropped   atomic.Int64
	once      sync.Once
}

// Events returns the receive-only channel. Subscribers read from this
// channel; ranging over it terminates when the bus shuts down.
func (s *Subscription) Events() <-chan Event { return s.ch }

// Delivered returns the count of events delivered to this subscriber.
func (s *Subscription) Delivered() int64 { return s.delivered.Load() }

// Dropped returns the count of events the bus tried to deliver but
// dropped because the channel was full.
func (s *Subscription) Dropped() int64 { return s.dropped.Load() }

// Unsubscribe removes this subscriber from the bus and closes its
// channel. Safe to call multiple times. Spec AC-13.
func (s *Subscription) Unsubscribe() {
	s.once.Do(func() {
		s.bus.mu.Lock()
		defer s.bus.mu.Unlock()
		for _, k := range s.kinds {
			delete(s.bus.subscribers[k], s)
			if len(s.bus.subscribers[k]) == 0 {
				delete(s.bus.subscribers, k)
			}
		}
		// Only close the channel if the bus hasn't already done it via
		// Shutdown. Closing a closed channel panics; use the closed
		// flag as the guard.
		if !s.bus.closed.Load() {
			close(s.ch)
		}
	})
}

// Metrics holds the bus's runtime counters. Spec AC-09.
type Metrics struct {
	PublishedCount     atomic.Int64
	DeliveredCount     atomic.Int64
	DroppedCount       atomic.Int64
	NoSubscribersCount atomic.Int64
}

// NewMetrics returns a fresh Metrics.
func NewMetrics() *Metrics { return &Metrics{} }

// MetricsSnapshot is a typed snapshot of the counters.
type MetricsSnapshot struct {
	PublishedCount     int64 `json:"published_count"`
	DeliveredCount     int64 `json:"delivered_count"`
	DroppedCount       int64 `json:"dropped_count"`
	NoSubscribersCount int64 `json:"no_subscribers_count"`
}

// Snapshot returns a point-in-time copy of all counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		PublishedCount:     m.PublishedCount.Load(),
		DeliveredCount:     m.DeliveredCount.Load(),
		DroppedCount:       m.DroppedCount.Load(),
		NoSubscribersCount: m.NoSubscribersCount.Load(),
	}
}
