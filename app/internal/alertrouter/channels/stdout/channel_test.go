// @spec system-daemon-orchestration
//
// AC traceability (this file):
//   AC-07  TestStdoutChannel_NameAndSend
//          TestStdoutChannel_DefaultName

package stdout

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
)

// @ac AC-07
// AC-13 (partial — channel surface): the stdout channel returns its
// configured Name and emits a structured slog record on Send carrying
// alert_type / severity / host_id / rule_id / title fields.
func TestStdoutChannel_NameAndSend(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-07", func(t *testing.T) {
		// Capture slog output into a buffer.
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
		t.Cleanup(func() { slog.SetDefault(prev) })

		ch := New("stdout-test")
		if got := ch.Name(); got != "stdout-test" {
			t.Errorf("Name() = %q, want %q", got, "stdout-test")
		}

		hostID := uuid.New()
		err := ch.Send(context.Background(), alertrouter.Alert{
			Type:       alertrouter.AlertTypeHostUnreachable,
			Severity:   alertrouter.SeverityHigh,
			HostID:     hostID,
			OccurredAt: time.Now(),
			Title:      "Host went away",
		})
		if err != nil {
			t.Fatalf("Send returned non-nil error: %v", err)
		}

		// Decode the captured JSON log line.
		line := strings.TrimSpace(buf.String())
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode slog record: %v; raw=%s", err, line)
		}
		if rec["msg"] != "alertrouter.alert.sent" {
			t.Errorf("msg = %v, want alertrouter.alert.sent", rec["msg"])
		}
		if rec["alert_type"] != string(alertrouter.AlertTypeHostUnreachable) {
			t.Errorf("alert_type = %v, want %q", rec["alert_type"], alertrouter.AlertTypeHostUnreachable)
		}
		if rec["severity"] != string(alertrouter.SeverityHigh) {
			t.Errorf("severity = %v, want %q", rec["severity"], alertrouter.SeverityHigh)
		}
		if rec["host_id"] != hostID.String() {
			t.Errorf("host_id = %v, want %q", rec["host_id"], hostID)
		}
	})
}

// @ac AC-07
// AC-13 (default-name path): New("") falls back to "stdout".
func TestStdoutChannel_DefaultName(t *testing.T) {
	t.Run("system-daemon-orchestration/AC-07", func(t *testing.T) {
		if got := New("").Name(); got != "stdout" {
			t.Errorf("New(\"\").Name() = %q, want \"stdout\"", got)
		}
	})
}
