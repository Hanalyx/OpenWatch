// @spec system-license-features
//
// AC traceability:
//
//	AC-15  TestDenialAudit_ActorAndDedupPerPrincipal
//
// bugs/OW-101: a license denial was recorded as actor_type "user" with no
// actor id, for every caller, and deduplicated by remote address.
package license

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
)

type denialRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *denialRecorder) InsertEvent(_ audit.Ctx, ev *audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, *ev)
	return nil
}

func (r *denialRecorder) denials() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, e := range r.events {
		if e.Action == audit.LicenseFeatureCheckDenied {
			out = append(out, e)
		}
	}
	return out
}

// waitDenials polls until the batched writer's count holds steady.
func (r *denialRecorder) waitDenials(t *testing.T, want int) []audit.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	last, steady := -1, 0
	for time.Now().Before(deadline) {
		n := len(r.denials())
		if n == last {
			steady++
			if steady >= 3 && n >= want {
				break
			}
		} else {
			steady = 0
		}
		last = n
		time.Sleep(60 * time.Millisecond)
	}
	return r.denials()
}

// @ac AC-15
func TestDenialAudit_ActorAndDedupPerPrincipal(t *testing.T) {
	t.Run("system-license-features/AC-15", func(t *testing.T) {
		rec := &denialRecorder{}
		audit.Init(rec, audit.DefaultWriterOptions())
		t.Cleanup(func() { audit.Shutdown(time.Second) })
		denialMu.Lock()
		denialMap = make(map[denialKey]*denialState)
		denialMu.Unlock()

		user := uuid.New()
		tokenA, tokenB := uuid.New(), uuid.New()
		deny := func(id *auth.Identity, remote string) {
			r := httptest.NewRequest(http.MethodPost, "/x", nil)
			r.RemoteAddr = remote
			if id != nil {
				r = r.WithContext(auth.SetIdentity(r.Context(), *id))
			}
			DenyFeature(httptest.NewRecorder(), r, ComplianceAttestation)
		}
		sess := auth.Identity{ID: user.String(), UserID: user, RoleID: auth.RoleAdmin}
		tokA := auth.Identity{ID: tokenA.String(), UserID: user, RoleID: auth.RoleAdmin, IsAPIToken: true}
		tokB := auth.Identity{ID: tokenB.String(), UserID: user, RoleID: auth.RoleAdmin, IsAPIToken: true}

		// Same port for every authenticated call: a remote-address key would
		// merge them, a principal key must not.
		deny(&sess, "192.0.2.10:5000")
		deny(&tokA, "192.0.2.10:5000")
		deny(&tokB, "192.0.2.10:5000")
		deny(&tokA, "192.0.2.10:5000") // repeat inside the window: suppressed
		deny(nil, "198.51.100.7:4000") // anonymous
		deny(nil, "198.51.100.7:4000") // repeat: suppressed

		got := rec.waitDenials(t, 4)
		if len(got) != 4 {
			t.Fatalf("license denial events = %d, want 4 (session, token A, token B, anonymous)", len(got))
		}
		seen := map[string]string{}
		for _, e := range got {
			seen[e.ActorType+":"+e.ActorID] = e.ActorIP
		}
		want := []string{
			audit.ActorUser + ":" + user.String(),
			audit.ActorAPIKey + ":" + tokenA.String(),
			audit.ActorAPIKey + ":" + tokenB.String(),
			audit.ActorAnonymous + ":",
		}
		for _, w := range want {
			if _, ok := seen[w]; !ok {
				t.Errorf("no denial attributed to %q; got %v", w, seen)
			}
		}
		for k := range seen {
			if k == audit.ActorUser+":" {
				t.Errorf("a denial was recorded as a user with no id (the OW-101 shape)")
			}
			if k == audit.ActorUser+":"+tokenA.String() || k == audit.ActorUser+":"+tokenB.String() {
				t.Errorf("a token's denial was typed user: %s", k)
			}
		}
		if ip := seen[audit.ActorAnonymous+":"]; ip != "198.51.100.7:4000" {
			t.Errorf("anonymous denial actor_ip = %q, want the remote address", ip)
		}
		for _, e := range got {
			if e.ActorType == audit.ActorAPIKey && e.ActorID == user.String() {
				t.Errorf("a token's denial names its owner as actor")
			}
		}
	})
}
