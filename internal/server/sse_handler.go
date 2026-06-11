// Server-Sent Events stream for live UI updates.
//
// One persistent connection per browser tab carries every relevant
// event (host CRUD, monitoring band transitions, …). The frontend
// maps each event to a TanStack Query invalidation so open pages
// refresh in place without polling.
//
// Auth: same-origin cookie session via the standard identity binder.
// Bearer tokens via ?token=… are explicitly NOT supported (C-06 — URL
// params are logged by intermediaries and would leak the credential).
//
// Topics: clients filter with ?topics=monitoring.band.changed,host.changed
// (CSV of EventKind values). Empty/missing topics = 400 (matches
// eventbus.Subscribe semantics — no wildcard).
//
// Spec: app/specs/api/events-stream.spec.yaml.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/eventbus"
)

// sseEnvelope is the JSON payload emitted in the SSE `data:` field.
// `kind` mirrors eventbus.EventKind so the client can switch on a
// stable string; `payload` is event-specific.
type sseEnvelope struct {
	Kind      string `json:"kind"`
	Timestamp string `json:"timestamp"`
	Payload   any    `json:"payload"`
}

// GetEventsStream subscribes the caller to the event bus and writes
// matching events as SSE messages until the client disconnects. Spec
// api-events-stream AC-01.
func (h *handlers) GetEventsStream(w http.ResponseWriter, r *http.Request) {
	// Auth FIRST — anonymous callers don't get to consume the bus.
	// AC-05. host:read mirrors GET /hosts because the events carry
	// host_id values.
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	if h.bus == nil {
		http.Error(w, "events stream not wired", http.StatusServiceUnavailable)
		return
	}

	// Parse the topic filter. Empty = 400 (matches eventbus.Subscribe
	// semantics; we want operators to declare intent rather than
	// firehose by default). AC-02, AC-03.
	topics := parseTopics(r.URL.Query().Get("topics"))
	if len(topics) == 0 {
		http.Error(w, "no topics requested", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// SSE headers. text/event-stream is mandatory; Cache-Control
	// prevents intermediaries from buffering; X-Accel-Buffering
	// tells nginx to disable its proxy buffer on a per-response basis.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	sub := h.bus.Subscribe(eventbus.SubscribeOptions{Kinds: topics})
	defer sub.Unsubscribe()

	// Keepalive heartbeats every 15s — a comment line (":keepalive\n\n")
	// is ignored by EventSource but keeps the TCP socket warm through
	// intermediaries with short idle timeouts.
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if _, err := w.Write([]byte(":keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case ev, open := <-sub.Events():
			if !open {
				return
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// parseTopics turns "host.changed,monitoring.band.changed" into a
// closed-set slice. Unknown kinds are silently dropped — we don't want
// a typo'd query string to 500 the entire stream.
func parseTopics(csv string) []eventbus.EventKind {
	if csv == "" {
		return nil
	}
	known := make(map[eventbus.EventKind]bool, len(eventbus.AllEventKinds))
	for _, k := range eventbus.AllEventKinds {
		known[k] = true
	}
	parts := strings.Split(csv, ",")
	out := make([]eventbus.EventKind, 0, len(parts))
	for _, p := range parts {
		k := eventbus.EventKind(strings.TrimSpace(p))
		if known[k] {
			out = append(out, k)
		}
	}
	return out
}

// writeSSE serialises an event into an SSE-framed JSON line. Format:
//
//	event: <kind>
//	data: {"kind":"...","timestamp":"...","payload":{...}}
//
// Two newlines terminate the message.
func writeSSE(w http.ResponseWriter, ev eventbus.Event) error {
	env := sseEnvelope{
		Kind:      string(ev.Kind()),
		Timestamp: ev.Timestamp().UTC().Format(time.RFC3339Nano),
		Payload:   ev,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	// SSE requires LF, not CRLF.
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind(), body); err != nil {
		return err
	}
	return nil
}
