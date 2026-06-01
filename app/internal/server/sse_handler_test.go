// @spec api-events-stream
//
// AC traceability (this file):
//
//	AC-01  TestEventsStream_RespondsWithEventStreamHeaders
//	AC-02  TestEventsStream_NoTopicsReturns400
//	AC-03  TestEventsStream_OnlyUnknownTopicsReturns400
//	AC-04  TestEventsStream_PublishingMessageWritesFramedSSE
//	AC-05  TestEventsStream_AnonymousReturns403
//	AC-06  TestEventsStream_NoBearerTokenViaQueryString
//	AC-07  TestEventsStream_DisconnectsOnContextCancel

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/google/uuid"
)

// @ac AC-01
// AC-01: 200 response with text/event-stream Content-Type, served via
// an httptest.Server so the flusher path actually runs.
func TestEventsStream_RespondsWithEventStreamHeaders(t *testing.T) {
	t.Run("api-events-stream/AC-01", func(t *testing.T) {
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		h := &handlers{bus: bus}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.GetEventsStream(w, r.WithContext(withMergedIdentity(r.Context(), adminIdentity(t))))
		}))
		defer ts.Close()

		req, _ := http.NewRequest(http.MethodGet, ts.URL+"?topics=host.changed", nil)
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
			t.Errorf("Content-Type = %q, want text/event-stream", got)
		}
		if !strings.Contains(resp.Header.Get("Cache-Control"), "no-cache") {
			t.Errorf("Cache-Control = %q, want no-cache", resp.Header.Get("Cache-Control"))
		}
	})
}

// @ac AC-02
// AC-02: no ?topics → 400.
func TestEventsStream_NoTopicsReturns400(t *testing.T) {
	t.Run("api-events-stream/AC-02", func(t *testing.T) {
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		h := &handlers{bus: bus}
		// EnforcePermission needs a bound identity to proceed past the
		// auth guard. Stub one in via context.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).
			WithContext(adminIdentity(t))
		w := httptest.NewRecorder()
		h.GetEventsStream(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
		if !strings.Contains(w.Body.String(), "no topics requested") {
			t.Errorf("body = %q, want 'no topics requested'", w.Body.String())
		}
	})
}

// @ac AC-03
// AC-03: only-unknown topics → 400.
func TestEventsStream_OnlyUnknownTopicsReturns400(t *testing.T) {
	t.Run("api-events-stream/AC-03", func(t *testing.T) {
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		h := &handlers{bus: bus}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events?topics=does.not.exist,nope", nil).
			WithContext(adminIdentity(t))
		w := httptest.NewRecorder()
		h.GetEventsStream(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})
}

// @ac AC-04
// AC-04: publishing eventbus.HostChanged writes the SSE-framed JSON.
// We open a real chi-less httptest.Server here so we get a flusher
// and a real socket the client can read off.
func TestEventsStream_PublishingMessageWritesFramedSSE(t *testing.T) {
	t.Run("api-events-stream/AC-04", func(t *testing.T) {
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		h := &handlers{bus: bus}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Inject the same admin identity the request would have
			// after passing through the identity binder.
			h.GetEventsStream(w, r.WithContext(withMergedIdentity(r.Context(), adminIdentity(t))))
		}))
		defer ts.Close()

		req, _ := http.NewRequest(http.MethodGet, ts.URL+"?topics=host.changed", nil)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.Header.Get("Content-Type") != "text/event-stream" {
			t.Errorf("Content-Type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
		}

		// Give the subscriber goroutine a beat to register.
		time.Sleep(50 * time.Millisecond)
		hostID, _ := uuid.NewV7()
		bus.Publish(context.Background(), eventbus.HostChanged{
			HostID:     hostID,
			Change:     eventbus.HostChangeMaintenance,
			OccurredAt: time.Now().UTC(),
		})

		// Read the first SSE frame.
		buf := make([]byte, 4096)
		n, err := resp.Body.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got := string(buf[:n])
		if !strings.HasPrefix(got, "event: host.changed\n") {
			t.Errorf("missing event line; got:\n%s", got)
		}
		dataIdx := strings.Index(got, "data: ")
		if dataIdx < 0 {
			t.Errorf("no data line; got:\n%s", got)
		}
		dataEnd := strings.Index(got[dataIdx:], "\n\n")
		if dataEnd < 0 {
			t.Errorf("frame not terminated by blank line; got:\n%s", got)
		}
		var env sseEnvelope
		dataStart := dataIdx + len("data: ")
		if err := json.Unmarshal([]byte(got[dataStart:dataIdx+dataEnd]), &env); err != nil {
			t.Errorf("data JSON invalid: %v / %s", err, got[dataIdx:dataIdx+dataEnd])
		}
		if env.Kind != string(eventbus.EventKindHostChanged) {
			t.Errorf("kind = %q, want host.changed", env.Kind)
		}
	})
}

// @ac AC-05
// AC-05: anonymous identity is rejected by the auth guard. The
// EnforcePermission path returns 403 (no permissions) — that's the
// canonical "you can't see this" response.
func TestEventsStream_AnonymousReturns403(t *testing.T) {
	t.Run("api-events-stream/AC-05", func(t *testing.T) {
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		h := &handlers{bus: bus}
		// No identity bound — the default Identity has IsAnonymous=true.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events?topics=host.changed", nil)
		w := httptest.NewRecorder()
		h.GetEventsStream(w, req)
		if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 or 403", w.Code)
		}
	})
}

// @ac AC-06
// AC-06: handler must NOT call r.URL.Query().Get("token"). Source
// inspection — the literal call would expose bearer tokens via the
// access log of any intermediary that records URLs.
func TestEventsStream_NoBearerTokenViaQueryString(t *testing.T) {
	t.Run("api-events-stream/AC-06", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		path := filepath.Join(filepath.Dir(file), "sse_handler.go")
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read sse_handler.go: %v", err)
		}
		if strings.Contains(string(src), `r.URL.Query().Get("token")`) {
			t.Errorf("sse_handler.go reads ?token= — forbidden by C-06")
		}
	})
}

// @ac AC-07
// AC-07: cancelling the request context drains the handler within
// 500ms and leaves no subscribers behind on the bus.
func TestEventsStream_DisconnectsOnContextCancel(t *testing.T) {
	t.Run("api-events-stream/AC-07", func(t *testing.T) {
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		h := &handlers{bus: bus}

		ctx, cancel := context.WithCancel(adminIdentity(t))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events?topics=host.changed", nil).WithContext(ctx)
		w := httptest.NewRecorder()

		done := make(chan struct{})
		go func() {
			h.GetEventsStream(w, req)
			close(done)
		}()
		// Let the handler reach the select loop.
		time.Sleep(50 * time.Millisecond)
		cancel()

		select {
		case <-done:
			// good
		case <-time.After(500 * time.Millisecond):
			t.Fatal("handler did not return within 500ms of ctx cancel")
		}

		// Publish a tombstone — if the subscription leaked, the bus
		// would still try to deliver. NoSubscribersCount must advance.
		before := bus.Metrics().Snapshot().NoSubscribersCount
		bus.Publish(context.Background(), eventbus.HostChanged{HostID: uuid.New(), Change: eventbus.HostChangeUpdated, OccurredAt: time.Now().UTC()})
		after := bus.Metrics().Snapshot().NoSubscribersCount
		if after <= before {
			t.Errorf("NoSubscribersCount did not advance — subscription likely leaked")
		}
	})
}

// adminIdentity returns a context with an auth.Identity bound to the
// admin role's permission set. Mirrors what the identity binder would
// produce after a successful cookie/Bearer auth.
func adminIdentity(t *testing.T) context.Context {
	t.Helper()
	return auth.SetIdentity(context.Background(), auth.Identity{
		ID:     "test-admin",
		RoleID: auth.RoleAdmin,
	})
}

// withMergedIdentity copies the bound identity from src into dst,
// because httptest's server creates a fresh request context.
func withMergedIdentity(dst, src context.Context) context.Context {
	id := auth.FromContext(src)
	if id.IsAnonymous {
		return dst
	}
	return auth.SetIdentity(dst, id)
}
