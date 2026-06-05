// @spec system-correlation
//
// AC traceability:
// @ac AC-12  (TestCorrelationHandler_AddsAttrFromCtx)
// @ac AC-13  (TestCorrelationHandler_OmitsWhenAbsent)

package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/Hanalyx/openwatch/internal/correlation"
)

// @ac AC-12  (When ctx has a correlation ID, the emitted JSON record contains)
// "correlation_id": "<the id>".
func TestCorrelationHandler_AddsAttrFromCtx(t *testing.T) {
	t.Run("system-correlation/AC-12", func(t *testing.T) {

		var buf bytes.Buffer
		h := NewCorrelationHandler(slog.NewJSONHandler(&buf, nil))
		logger := slog.New(h)

		ctx := correlation.Set(context.Background(), "req-deadbeef00000001")
		logger.InfoContext(ctx, "hello")

		var rec map[string]any
		if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal: %v\nraw=%s", err, buf.String())
		}
		got, ok := rec["correlation_id"]
		if !ok {
			t.Fatalf("emitted record missing correlation_id; got: %s", buf.String())
		}
		if got != "req-deadbeef00000001" {
			t.Errorf("correlation_id = %v, want req-deadbeef00000001", got)
		}
	})
}

// @ac AC-13  (When ctx has no ID (e.g. Background()), correlation_id is NOT)
// emitted as an empty-string attr.
func TestCorrelationHandler_OmitsWhenAbsent(t *testing.T) {
	t.Run("system-correlation/AC-13", func(t *testing.T) {

		var buf bytes.Buffer
		h := NewCorrelationHandler(slog.NewJSONHandler(&buf, nil))
		logger := slog.New(h)

		logger.InfoContext(context.Background(), "hello")

		var rec map[string]any
		if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal: %v\nraw=%s", err, buf.String())
		}
		if _, present := rec["correlation_id"]; present {
			t.Errorf("expected correlation_id absent; record: %s", buf.String())
		}
	})
}

// @ac AC-12  ((companion): WithAttrs preserves correlation tagging.)
func TestCorrelationHandler_WithAttrsPreservesTagging(t *testing.T) {
	t.Run("system-correlation/AC-12", func(t *testing.T) {

		var buf bytes.Buffer
		h := NewCorrelationHandler(slog.NewJSONHandler(&buf, nil))
		logger := slog.New(h).With(slog.String("component", "test"))

		ctx := correlation.Set(context.Background(), "req-aaaa")
		logger.InfoContext(ctx, "hello")

		var rec map[string]any
		if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if rec["correlation_id"] != "req-aaaa" {
			t.Errorf("correlation_id missing after WithAttrs: %s", buf.String())
		}
		if rec["component"] != "test" {
			t.Errorf("component attr missing: %s", buf.String())
		}
	})
}
