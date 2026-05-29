package alertrouter

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hanalyx/openwatch/internal/eventbus"
)

// stopDrainTimeout is the max time Router.Stop waits for in-flight
// Channel.Send calls to complete before returning. Spec C-08.
const stopDrainTimeout = 10 * time.Second

// Router subscribes to the event bus and dispatches alerts to
// registered channels.
//
// Construct with NewRouter, register channels via Register, then call
// Start to begin reading from the bus. Call Stop to unsubscribe and
// drain in-flight deliveries.
type Router struct {
	bus      *eventbus.Bus
	dedup    *DedupGate
	metrics  *Metrics
	logger   *slog.Logger
	dedupTTL time.Duration

	mu       sync.RWMutex
	channels []*channelEntry

	started atomic.Bool
	stopped atomic.Bool

	heartbeatSub *eventbus.Subscription
	driftSub     *eventbus.Subscription

	// loopWG covers the two reader goroutines (heartbeat, drift).
	loopWG sync.WaitGroup

	// sendWG covers in-flight Channel.Send goroutines so Stop can wait
	// for them to complete with a bounded timeout.
	sendWG sync.WaitGroup
}

// channelEntry binds a ChannelRegistration to its per-channel failure
// counter. Pointer because we mutate the counter atomically.
type channelEntry struct {
	reg          ChannelRegistration
	failureCount atomic.Int64
}

// Config holds optional Router parameters.
type Config struct {
	// DedupTTL is the time window for the dedup gate. Must be in
	// [MinDedupTTL, MaxDedupTTL] per ValidateDedupTTL. Zero defaults to
	// DefaultDedupTTL.
	DedupTTL time.Duration

	// Logger is the structured logger for failure/diagnostic messages.
	// nil uses slog.Default.
	Logger *slog.Logger
}

// NewRouter constructs a Router bound to the given event bus. The
// router is not yet subscribed; call Start.
func NewRouter(bus *eventbus.Bus, cfg Config) (*Router, error) {
	if bus == nil {
		return nil, fmt.Errorf("alertrouter: bus is required")
	}
	ttl := cfg.DedupTTL
	if ttl == 0 {
		ttl = DefaultDedupTTL
	}
	if err := ValidateDedupTTL(ttl); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Router{
		bus:      bus,
		dedup:    NewDedupGate(ttl),
		metrics:  NewMetrics(),
		logger:   logger,
		dedupTTL: ttl,
	}, nil
}

// Register adds a channel + filter to the router. Safe to call before
// or after Start. Spec C-05.
func (r *Router) Register(reg ChannelRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels = append(r.channels, &channelEntry{reg: reg})
}

// Start subscribes to EventKindHeartbeatPulse + EventKindDriftDetected
// on the bus and begins dispatching. Idempotent (re-calling has no
// effect). Spec AC-11.
func (r *Router) Start(ctx context.Context) {
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	r.heartbeatSub = r.bus.Subscribe(eventbus.SubscribeOptions{
		Kinds: []eventbus.EventKind{eventbus.EventKindHeartbeatPulse},
	})
	r.driftSub = r.bus.Subscribe(eventbus.SubscribeOptions{
		Kinds: []eventbus.EventKind{eventbus.EventKindDriftDetected},
	})

	r.loopWG.Add(2)
	go r.run(ctx, r.heartbeatSub)
	go r.run(ctx, r.driftSub)
}

// Stop unsubscribes from the bus and waits up to stopDrainTimeout for
// in-flight Channel.Send calls to complete. After Stop, new events are
// ignored. Spec AC-12 / C-08.
func (r *Router) Stop() {
	if !r.stopped.CompareAndSwap(false, true) {
		return
	}
	// Unsubscribe from the bus. The reader goroutines see closed
	// channels and return.
	if r.heartbeatSub != nil {
		r.heartbeatSub.Unsubscribe()
	}
	if r.driftSub != nil {
		r.driftSub.Unsubscribe()
	}
	// Wait for the reader loops to exit so no new Channel.Send calls
	// will be spawned after this point.
	r.loopWG.Wait()

	// Drain in-flight sends with a bounded timeout.
	done := make(chan struct{})
	go func() {
		r.sendWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopDrainTimeout):
		r.logger.WarnContext(context.Background(),
			"alertrouter: Stop drain timeout exceeded; some in-flight sends abandoned",
			slog.Duration("timeout", stopDrainTimeout))
	}
}

// run is the per-subscription reader loop. Each event is translated to
// an Alert, run through the dedup gate, and fanned out to matching
// channels.
func (r *Router) run(ctx context.Context, sub *eventbus.Subscription) {
	defer r.loopWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.Events():
			if !ok {
				return
			}
			r.handle(ctx, ev)
		}
	}
}

// handle is the per-event translation + dispatch pipeline. Exported
// only via run; tests use translate + dispatch directly when finer
// granularity is needed.
func (r *Router) handle(ctx context.Context, ev eventbus.Event) {
	alert, ok := translate(ev)
	if !ok {
		return
	}
	r.metrics.ReceivedCount.Add(1)
	if r.dedup.ShouldSkip(alert) {
		r.metrics.DedupedCount.Add(1)
		return
	}
	r.dispatch(ctx, alert)
}

// dispatch fans the alert out to every channel whose filter matches.
// Each Channel.Send runs in its own goroutine so a slow channel does
// not delay others. Spec C-07 / AC-10.
func (r *Router) dispatch(ctx context.Context, alert Alert) {
	r.mu.RLock()
	targets := make([]*channelEntry, 0, len(r.channels))
	for _, c := range r.channels {
		if c.reg.matches(alert) {
			targets = append(targets, c)
		}
	}
	r.mu.RUnlock()

	for _, c := range targets {
		r.metrics.RoutedCount.Add(1)
		r.sendWG.Add(1)
		go func(entry *channelEntry) {
			defer r.sendWG.Done()
			defer func() {
				if rec := recover(); rec != nil {
					// A channel panicked. Count it as a failure and log;
					// the router itself stays up.
					entry.failureCount.Add(1)
					r.metrics.ChannelFailureCount.Add(1)
					r.logger.ErrorContext(ctx,
						"alertrouter: channel panicked during Send",
						slog.String("channel", entry.reg.Channel.Name()),
						slog.Any("panic", rec))
				}
			}()
			if err := entry.reg.Channel.Send(ctx, alert); err != nil {
				entry.failureCount.Add(1)
				r.metrics.ChannelFailureCount.Add(1)
				r.logger.WarnContext(ctx,
					"alertrouter: channel send failed",
					slog.String("channel", entry.reg.Channel.Name()),
					slog.String("alert_type", string(alert.Type)),
					slog.String("severity", string(alert.Severity)),
					slog.Any("error", err))
			}
		}(c)
	}
}

// translate converts a bus event into a typed Alert. Returns ok=false
// for events that don't map to any AlertType (e.g., a heartbeat with
// no state change). Spec AC-03 / AC-04 / AC-05.
func translate(ev eventbus.Event) (Alert, bool) {
	switch e := ev.(type) {
	case eventbus.HeartbeatPulse:
		return translateHeartbeat(e)
	case eventbus.DriftDetected:
		return translateDrift(e)
	default:
		return Alert{}, false
	}
}

func translateHeartbeat(e eventbus.HeartbeatPulse) (Alert, bool) {
	switch {
	case !e.Reachable:
		// Host went unreachable.
		a := Alert{
			Type:       AlertTypeHostUnreachable,
			HostID:     e.HostID,
			OccurredAt: e.OccurredAt,
			Title:      fmt.Sprintf("Host %s unreachable", e.HostID),
			Body:       fmt.Sprintf("Liveness probe failed for host %s.", e.HostID),
		}
		a.Severity = defaultSeverityFor(a.Type)
		a.Tags = baseTags(a)
		return a, true
	case e.Reachable && !e.PriorReachable:
		// Host recovered (was unreachable, now reachable).
		a := Alert{
			Type:       AlertTypeHostRecovered,
			HostID:     e.HostID,
			OccurredAt: e.OccurredAt,
			Title:      fmt.Sprintf("Host %s recovered", e.HostID),
			Body:       fmt.Sprintf("Host %s is reachable again (response_time=%dms).", e.HostID, e.ResponseTimeMS),
		}
		a.Severity = defaultSeverityFor(a.Type)
		a.Tags = baseTags(a)
		return a, true
	default:
		// Reachable AND prior reachable: no transition, no alert.
		return Alert{}, false
	}
}

func translateDrift(e eventbus.DriftDetected) (Alert, bool) {
	var t AlertType
	switch e.DriftType {
	case "major":
		t = AlertTypeDriftMajor
	case "minor":
		t = AlertTypeDriftMinor
	case "improvement":
		t = AlertTypeDriftImprovement
	default:
		return Alert{}, false
	}
	a := Alert{
		Type:       t,
		HostID:     e.HostID,
		OccurredAt: e.OccurredAt,
		Title:      fmt.Sprintf("Compliance drift (%s) on host %s", e.DriftType, e.HostID),
		Body: fmt.Sprintf(
			"Scan %s: score %.2f → %.2f (Δ %.2f). Critical→fail: %d, High→fail: %d.",
			e.ScanID, e.PriorScore, e.CurrentScore, e.ScoreDelta,
			e.CriticalBecameFailing, e.HighBecameFailing),
	}
	a.Severity = defaultSeverityFor(a.Type)
	a.Tags = baseTags(a)
	a.Tags["score_delta"] = fmt.Sprintf("%.2f", e.ScoreDelta)
	return a, true
}

// baseTags is the minimum tag set every alert carries. Spec C-06.
func baseTags(a Alert) map[string]string {
	return map[string]string{
		"severity":   string(a.Severity),
		"alert_type": string(a.Type),
		"host_id":    a.HostID.String(),
	}
}

// Metrics returns the router's runtime counters handle.
func (r *Router) Metrics() *Metrics { return r.metrics }

// FailureCount returns the per-channel failure counter for the channel
// with the given Name(). Returns -1 if no such channel is registered.
// Test helper.
func (r *Router) FailureCount(name string) int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.channels {
		if c.reg.Channel.Name() == name {
			return c.failureCount.Load()
		}
	}
	return -1
}
