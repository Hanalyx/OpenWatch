// @spec system-notifications
//
// Source-inspection guards: the list/read path redacts secrets (it may
// surface non-secret email fields, but never the password / URL / token),
// and the package pulls in no external notification SDK.

package notification

import (
	"os"
	"strings"
	"testing"
)

// readSource returns the concatenated source of the package's non-test
// .go files.
func readSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		data, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		b.Write(data)
		b.WriteString("\n")
	}
	return b.String()
}

// @ac AC-02
// The list/read path MAY decrypt to surface non-secret email fields, but it
// MUST redact secrets: redactConfig clears the email password and returns an
// empty Config for slack/webhook (the URL is itself the secret). List + Get
// route through the redacting scan.
func TestReadPathRedactsSecrets(t *testing.T) {
	t.Run("system-notifications/AC-02", func(t *testing.T) {
		raw, err := os.ReadFile("store.go")
		if err != nil {
			t.Fatalf("read store.go: %v", err)
		}
		src := string(raw)
		// List + Get scan via the redacting path, never returning raw config.
		if !strings.Contains(src, "scanRedacted(") {
			t.Error("List/Get must route through scanRedacted")
		}
		// redactConfig drops the email password and exposes nothing for
		// slack/webhook.
		idx := strings.Index(src, "func redactConfig")
		if idx < 0 {
			t.Fatal("redactConfig missing")
		}
		body := src[idx:]
		if end := strings.Index(body, "\n}\n"); end > 0 {
			body = body[:end]
		}
		if !strings.Contains(body, `cfg.Password = ""`) {
			t.Error("redactConfig must clear the email password")
		}
		if !strings.Contains(body, "return Config{}") {
			t.Error("redactConfig must return an empty Config for slack/webhook")
		}
	})
}

// @ac AC-07
// The package must not import any external notification SDK; delivery is
// net/http + encoding/json only.
func TestNoExternalNotificationSDK(t *testing.T) {
	t.Run("system-notifications/AC-07", func(t *testing.T) {
		src := readSource(t)
		banned := []string{
			"slack-go/slack",
			"nlopes/slack",
			"go-resty",
			"gomail",
			"sendgrid",
		}
		for _, b := range banned {
			if strings.Contains(src, b) {
				t.Errorf("notification package imports banned SDK %q", b)
			}
		}
		// Positive: delivery uses net/http.
		if !strings.Contains(src, "\"net/http\"") {
			t.Error("expected net/http for delivery")
		}
	})
}
