// @spec system-notifications
//
// SSRF guard + payload + dispatch tag-matching. No DB required.

package notification

import (
	"net"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
)

// @ac AC-03
func TestSafeURLHost(t *testing.T) {
	t.Run("system-notifications/AC-03", func(t *testing.T) {
		// Rejected: non-https + private/loopback/link-local + localhost.
		for _, bad := range []string{
			"http://hooks.slack.com/x",
			"https://127.0.0.1/x",
			"https://10.0.0.1/x",
			"https://192.168.1.5/x",
			"https://169.254.169.254/latest/meta-data",
			"https://[::1]/x",
			"https://localhost/x",
			"ftp://example.com/x",
			"not a url at all ::::",
		} {
			if _, err := safeURLHost(bad); err == nil {
				t.Errorf("safeURLHost(%q) = nil err, want rejection", bad)
			}
		}
		// Accepted: public https host returns its hostname.
		host, err := safeURLHost("https://hooks.slack.com/services/T/B/x")
		if err != nil {
			t.Fatalf("safeURLHost(public) err = %v", err)
		}
		if host != "hooks.slack.com" {
			t.Errorf("host = %q, want hooks.slack.com", host)
		}
	})
}

// @ac AC-04
func TestIsBlockedIPAndDialControl(t *testing.T) {
	t.Run("system-notifications/AC-04", func(t *testing.T) {
		blocked := []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "169.254.169.254", "::1", "0.0.0.0"}
		for _, s := range blocked {
			if !isBlockedIP(net.ParseIP(s)) {
				t.Errorf("isBlockedIP(%s) = false, want true", s)
			}
		}
		public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34"}
		for _, s := range public {
			if isBlockedIP(net.ParseIP(s)) {
				t.Errorf("isBlockedIP(%s) = true, want false", s)
			}
		}
		// Dial Control refuses a blocked resolved address, allows a public one.
		if err := ssrfControl("tcp", "10.0.0.1:443", nil); err == nil {
			t.Error("ssrfControl(private) = nil, want block")
		}
		if err := ssrfControl("tcp", "1.1.1.1:443", nil); err != nil {
			t.Errorf("ssrfControl(public) = %v, want nil", err)
		}
	})
}

// @ac AC-05
func TestMatchesTags(t *testing.T) {
	t.Run("system-notifications/AC-05", func(t *testing.T) {
		alertTags := map[string]string{"severity": "critical", "alert_type": "drift"}
		// Empty filter = wildcard.
		if !matchesTags(map[string]string{}, alertTags) {
			t.Error("empty filter should match")
		}
		if !matchesTags(nil, alertTags) {
			t.Error("nil filter should match")
		}
		// Matching subset.
		if !matchesTags(map[string]string{"severity": "critical"}, alertTags) {
			t.Error("matching subset should match")
		}
		// Non-matching value.
		if matchesTags(map[string]string{"severity": "info"}, alertTags) {
			t.Error("non-matching value should not match")
		}
		// Key absent in alert.
		if matchesTags(map[string]string{"team": "secops"}, alertTags) {
			t.Error("absent key should not match")
		}
	})
}

// @ac AC-08
func TestValidateEmailAndMessage(t *testing.T) {
	t.Run("system-notifications/AC-08", func(t *testing.T) {
		// Missing fields rejected.
		bad := []Config{
			{SMTPPort: 587, From: "a@x.com", To: []string{"b@x.com"}},                           // no host
			{SMTPHost: "mail.x.com", From: "a@x.com", To: []string{"b@x.com"}},                  // no port
			{SMTPHost: "mail.x.com", SMTPPort: 587, To: []string{"b@x.com"}},                    // no from
			{SMTPHost: "mail.x.com", SMTPPort: 587, From: "a@x.com"},                            // no recipients
			{SMTPHost: "mail.x.com", SMTPPort: 99999, From: "a@x.com", To: []string{"b@x.com"}}, // bad port
		}
		for i, c := range bad {
			if _, err := validateEmail(c); err == nil {
				t.Errorf("validateEmail(bad[%d]) = nil, want rejection", i)
			}
		}
		// Internal relay host is allowed (no SSRF block for SMTP); host is
		// the target_hint.
		host, err := validateEmail(Config{
			SMTPHost: "10.0.0.25", SMTPPort: 587, From: "ow@corp.com", To: []string{"sec@corp.com"},
		})
		if err != nil {
			t.Fatalf("validateEmail(internal relay) = %v, want nil", err)
		}
		if host != "10.0.0.25" {
			t.Errorf("target_hint = %q, want 10.0.0.25", host)
		}
		// Message carries From/To/Subject/body.
		msg := string(buildEmailMessage("ow@corp.com", []string{"a@corp.com", "b@corp.com"}, "Subj", "Body"))
		for _, want := range []string{"From: ow@corp.com", "To: a@corp.com, b@corp.com", "Subject: Subj", "Body"} {
			if !strings.Contains(msg, want) {
				t.Errorf("email message missing %q:\n%s", want, msg)
			}
		}
	})
}

func TestRenderPayload(t *testing.T) {
	a := alertrouter.Alert{Type: "drift", Severity: "critical", Title: "Rule failed", Body: "details"}
	slack, err := renderPayload(TypeSlack, a)
	if err != nil {
		t.Fatalf("slack render: %v", err)
	}
	if !strings.Contains(string(slack), `"text"`) || !strings.Contains(string(slack), "Rule failed") {
		t.Errorf("slack payload missing text: %s", slack)
	}
	hook, err := renderPayload(TypeWebhook, a)
	if err != nil {
		t.Fatalf("webhook render: %v", err)
	}
	for _, want := range []string{`"severity"`, `"title"`, `"type"`} {
		if !strings.Contains(string(hook), want) {
			t.Errorf("webhook payload missing %s: %s", want, hook)
		}
	}
}
