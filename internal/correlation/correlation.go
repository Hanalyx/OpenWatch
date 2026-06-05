// Package correlation propagates a request-scoped correlation ID across
// HTTP entry, audit emission, log lines, and outbound calls.
//
// One ID per top-level intent. See app/docs/correlation_id_propagation.md
// for the full design and app/specs/system/correlation.spec.yaml for the
// behavioral contract.
//
// IDs are formatted as "<prefix>-<16 hex chars>", where the hex portion is
// the high-order 8 bytes of a UUIDv7 (so they are roughly time-ordered
// when sorted lexicographically). Prefixes signal origin:
//
//	req-   HTTP request
//	cron-  scheduled job tick
//	boot-  process startup
//	test-  test harness (reserved)
package correlation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Prefix is the origin marker on a correlation ID.
type Prefix string

// Origin prefixes. boot/cron/test are reserved — clients sending these
// via X-Correlation-Id are rejected and regenerated.
const (
	PrefixRequest Prefix = "req"
	PrefixCron    Prefix = "cron"
	PrefixBoot    Prefix = "boot"
	PrefixTest    Prefix = "test"
)

// reservedPrefixes are not accepted from clients.
var reservedPrefixes = []string{"boot-", "cron-", "test-"}

// validIDPattern: alphanumeric + dash + underscore, length 1-64.
var validIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// monotonic state for the per-millisecond counter; bytes 6-7 of the 8-byte
// ID body are derived from this. Within the same ms the counter increments;
// when ms advances the counter is reseeded with random bits to avoid
// predictable ID sequences.
//
// Trade-off: a 16-bit counter wraps after 65536 IDs in a single millisecond,
// which is ~65M IDs/sec. Far beyond any realistic OpenWatch request rate;
// if observed, alert and re-design.
var (
	monoMu      sync.Mutex
	monoLastMs  uint64
	monoCounter uint16
)

// Generate returns a fresh correlation ID with the given prefix.
//
// Format: <prefix>-<16 hex chars>. The 16 hex chars are 8 bytes:
//   - Bytes 0-5: 48-bit unix-millisecond timestamp (time-ordered when sorted)
//   - Bytes 6-7: 16-bit monotonic counter, randomly seeded each ms
//
// IDs sort lexicographically in time order; within the same millisecond they
// sort by counter (monotonically increasing, distinct).
//
// Panics on rand.Read failure — that condition signals the OS RNG is broken,
// which is not recoverable.
func Generate(prefix Prefix) string {
	// UnixMilli() returns a non-negative int64 for any time after the
	// Unix epoch (1970-01-01). Safe to widen to uint64.
	nowMs := uint64(time.Now().UnixMilli()) //nolint:gosec // post-epoch wall clock is non-negative
	c := nextCounter(nowMs)

	var u [8]byte
	u[0] = byte(nowMs >> 40)
	u[1] = byte(nowMs >> 32)
	u[2] = byte(nowMs >> 24)
	u[3] = byte(nowMs >> 16)
	u[4] = byte(nowMs >> 8)
	u[5] = byte(nowMs)
	u[6] = byte(c >> 8)
	u[7] = byte(c)
	return string(prefix) + "-" + hex.EncodeToString(u[:])
}

// nextCounter returns the next monotonic counter value for the given ms.
// If ms advanced since the last call, the counter is reseeded with random
// bits. Otherwise it increments. A wrap (back to 0) in the same ms is
// theoretically possible at extreme rates and would produce a duplicate
// ID; in practice this would require ~65M generates per millisecond.
func nextCounter(nowMs uint64) uint16 {
	monoMu.Lock()
	defer monoMu.Unlock()

	if nowMs != monoLastMs {
		// New millisecond: reseed.
		monoLastMs = nowMs
		var r [2]byte
		if _, err := rand.Read(r[:]); err != nil {
			panic(fmt.Errorf("correlation: rand.Read: %w", err))
		}
		monoCounter = uint16(r[0])<<8 | uint16(r[1])
	} else {
		monoCounter++
	}
	return monoCounter
}

// SanitizeOrGenerate inspects a client-supplied X-Correlation-Id header
// and returns either the original (when valid) or a freshly generated
// req- ID. The regenerated flag is true when the input was rejected and
// callers may want to log a warning.
//
// Empty input is not a rejection — it just means "no client header,
// generate one." Rejection happens for:
//   - input that fails validIDPattern (charset/length)
//   - input that starts with a reserved prefix
func SanitizeOrGenerate(client string) (id string, regenerated bool) {
	if client == "" {
		return Generate(PrefixRequest), false
	}
	if !validIDPattern.MatchString(client) {
		return Generate(PrefixRequest), true
	}
	for _, rp := range reservedPrefixes {
		if strings.HasPrefix(client, rp) {
			return Generate(PrefixRequest), true
		}
	}
	return client, false
}

// ctxKey is unexported to prevent collisions; the only way to get a
// correlation ID onto a context is via Set.
type ctxKey struct{}

// Set returns a new context carrying the given correlation ID.
func Set(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// From returns the correlation ID on the context, if any. The bool is
// false when no ID is set; callers should treat that as "logs/audit
// will have no correlation_id attached for this code path."
func From(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
