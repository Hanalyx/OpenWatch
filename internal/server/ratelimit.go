package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a small dependency-free sliding-window limiter keyed by an
// arbitrary string (here: client IP). Goroutine-safe. Used to throttle the
// authentication endpoints against online password/OTP guessing.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: make(map[string][]time.Time), limit: limit, window: window}
}

// allow records an attempt for key and reports whether it is within the
// limit. Expired timestamps are pruned on access (and a key with no recent
// hits is dropped, so the map stays bounded by the number of ACTIVE keys).
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// authRateLimitPerMinute is the per-IP attempt budget on the auth
// endpoints. Generous enough that legitimate sign-ins never trip it, low
// enough to make online guessing impractical.
const authRateLimitPerMinute = 20

// authRateLimitPaths are the POST endpoints throttled per client IP — the
// online-guessing surfaces (login + MFA verification).
var authRateLimitPaths = map[string]bool{
	"/api/v1/auth/login":      true,
	"/api/v1/auth/mfa:verify": true,
}

// rateLimitAuth throttles the auth endpoints per client IP. Over the limit
// returns 429 with Retry-After. The client IP is taken from the direct
// connection (RemoteAddr), NOT a client-supplied X-Forwarded-For header —
// trusting that would let an attacker rotate the key (see the trusted-proxy
// follow-up). Spec system-http-server C-13 / AC-18.
func rateLimitAuth(rl *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && authRateLimitPaths[r.URL.Path] {
				if !rl.allow(clientIP(r)) {
					w.Header().Set("Retry-After", "60")
					writeError(w, http.StatusTooManyRequests, "rate.limited", "client",
						"too many authentication attempts; retry later", true)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP returns the host portion of the direct connection's RemoteAddr.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
