package license

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/correlation"
)

// RequireFeature returns a chi middleware that rejects requests when the
// named feature is not enabled. Use for routes wired directly via chi.
//
// For oapi-codegen-mounted routes, prefer calling EnforceFeature inside
// the generated handler (the codegen wrapper makes it awkward to inject
// per-route middleware after HandlerFromMux runs).
//
// Spec: app/specs/system/license-features.spec.yaml AC-10, AC-11.
func RequireFeature(f Feature) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if EnforceFeature(w, r, f) {
				return // denied; response already written
			}
			next.ServeHTTP(w, r)
		})
	}
}

// EnforceFeature checks the feature gate inside a handler. If the
// feature is not enabled, it writes the 402 envelope + emits the audit
// event and returns true (handler should return immediately). If the
// feature is enabled, returns false and the caller continues.
//
// Used by oapi-codegen-generated handlers where per-route middleware is
// awkward to inject.
func EnforceFeature(w http.ResponseWriter, r *http.Request, f Feature) (denied bool) {
	if IsEnabled(f) {
		return false
	}
	DenyFeature(w, r, f)
	return true
}

// DenyFeature writes the 402 envelope and emits the audit event.
// Exported for handlers that want the deny path without a check (e.g.,
// after their own pre-condition logic).
func DenyFeature(w http.ResponseWriter, r *http.Request, f Feature) {
	errBody := map[string]any{
		"code":          "license.feature_unavailable",
		"fault":         "policy",
		"retryable":     false,
		"human_message": "this feature requires an OpenWatch+ license",
		"detail": map[string]any{
			"feature": string(f),
		},
	}
	// Per api_design_principles.md §8.1, the error envelope MUST include
	// correlation_id when one is on the request context. Lets operators
	// grep logs by the same ID the API consumer sees.
	if cid, ok := correlation.From(r.Context()); ok {
		errBody["correlation_id"] = cid
	}
	envelope := map[string]any{"error": errBody}
	body, _ := json.Marshal(envelope)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_, _ = w.Write(body)

	// Audit the denial (rate-limited per (feature, actor_id)).
	emitDenial(r, f)
}

// denialKey tracks dedup state for the feature-denied audit emit.
type denialKey struct {
	feature Feature
	actor   string
}

type denialState struct {
	lastEmit time.Time
	count    int
}

var (
	denialMu  sync.Mutex
	denialMap = make(map[denialKey]*denialState)
	denialTTL = 60 * time.Second

	// Sweep entries that have aged past TTL*2 so an attacker spraying
	// distinct (feature, ip) pairs cannot grow the map without bound.
	denialSweepEvery = 5 * time.Minute
	denialMaxAge     = 5 * time.Minute
)

func init() {
	go denialSweeper()
}

// denialSweeper runs forever and prunes denialMap entries older than
// denialMaxAge. Tiny cost (one map walk every 5 min) but bounds memory
// against repeated denials from distinct source IPs.
func denialSweeper() {
	ticker := time.NewTicker(denialSweepEvery)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		denialMu.Lock()
		for k, s := range denialMap {
			if now.Sub(s.lastEmit) > denialMaxAge {
				delete(denialMap, k)
			}
		}
		denialMu.Unlock()
	}
}

// emitDenial emits a license.feature_check_denied audit event, but
// suppresses repeats inside the 60-second dedup window. Suppressed
// denials increment a counter that is reported on the next emit's
// detail.suppressed_count.
func emitDenial(r *http.Request, f Feature) {
	// Stage 0: actor_id is unknown (auth lands Stage 2). Use a placeholder
	// derived from remote_addr so dedup still works per-client.
	actor := r.RemoteAddr

	denialMu.Lock()
	key := denialKey{feature: f, actor: actor}
	s, ok := denialMap[key]
	now := time.Now()

	var suppressed int
	emit := true
	if ok {
		if now.Sub(s.lastEmit) < denialTTL {
			// Within window — increment count, don't emit.
			s.count++
			emit = false
			suppressed = s.count
		} else {
			// Window expired — emit and reset.
			suppressed = s.count
			s.lastEmit = now
			s.count = 0
		}
	} else {
		denialMap[key] = &denialState{lastEmit: now, count: 0}
	}
	denialMu.Unlock()

	if !emit {
		return
	}

	detail := map[string]any{
		"feature": string(f),
	}
	if suppressed > 0 {
		detail["suppressed_count"] = suppressed
	}
	audit.Emit(r.Context(), audit.LicenseFeatureCheckDenied, audit.Event{
		ActorType: "user",
		ActorIP:   r.RemoteAddr,
		Detail:    audit.MakeDetail(detail),
	})
}
