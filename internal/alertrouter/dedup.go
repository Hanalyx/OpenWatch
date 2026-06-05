package alertrouter

import (
	"sync"
	"time"
)

// DedupGate filters out repeat alerts with the same dedup key seen
// within the configured TTL. Per Spec C-03 / C-04 / AC-06 / AC-07.
//
// Implementation: in-memory map keyed by Alert.DedupKey(). Each entry
// holds the last-seen timestamp; ShouldSkip compares now() against
// that timestamp + TTL. Stale entries are reaped opportunistically on
// every ShouldSkip call to keep the map from growing unbounded under
// churn.
type DedupGate struct {
	ttl  time.Duration
	now  func() time.Time
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewDedupGate constructs a DedupGate with the given TTL. Caller is
// expected to have validated the TTL via ValidateDedupTTL.
func NewDedupGate(ttl time.Duration) *DedupGate {
	return &DedupGate{
		ttl:  ttl,
		now:  time.Now,
		seen: make(map[string]time.Time),
	}
}

// ShouldSkip reports whether the alert should be skipped because it
// matches a recently-seen dedup key. As a side effect, on a non-skip
// outcome it records the alert's timestamp so the next call within
// TTL will skip.
//
// Spec AC-06: a repeat within TTL is skipped.
// Spec AC-07: a repeat after TTL passes through.
func (g *DedupGate) ShouldSkip(alert Alert) bool {
	key := alert.DedupKey()
	now := g.now()

	g.mu.Lock()
	defer g.mu.Unlock()

	// Opportunistic reap: drop entries past TTL. Cheap because the map
	// is small (one entry per active alert tuple). Avoids unbounded
	// growth under high churn.
	for k, ts := range g.seen {
		if now.Sub(ts) > g.ttl {
			delete(g.seen, k)
		}
	}

	if last, ok := g.seen[key]; ok {
		if now.Sub(last) <= g.ttl {
			return true
		}
	}
	g.seen[key] = now
	return false
}

// Size returns the number of tracked dedup keys. Test helper.
func (g *DedupGate) Size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
