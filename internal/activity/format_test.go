// @spec system-activity
//
// Unit coverage for the human-readable formatters (no DB).
//   AC-24  TestFormatters_HumanReadable
//   AC-25  TestFormatters_GracefulFallback

package activity

import "testing"

// @ac AC-24
func TestFormatters_HumanReadable(t *testing.T) {
	t.Run("system-activity/AC-24", func(t *testing.T) {
		titler := func(id string) (string, bool) {
			if id == "auditd_enabled" {
				return "Ensure auditd is enabled", true
			}
			return "", false
		}

		// --- compliance / transaction ---
		title, summary := formatTransaction("auditd_enabled", "fail", "state_changed", titler)
		if title != "Ensure auditd is enabled" {
			t.Errorf("txn title = %q, want the catalog title", title)
		}
		if summary != "Changed: now Fail" {
			t.Errorf("txn summary = %q, want %q", summary, "Changed: now Fail")
		}
		if _, s := formatTransaction("r", "pass", "first_seen", nil); s != "First seen: Pass" {
			t.Errorf("first_seen summary = %q", s)
		}

		// --- intelligence ---
		title, summary = formatIntelligence("system.package.updated",
			[]byte(`{"name":"curl","from":"7.64","to":"7.81"}`))
		if title != "Package updated" {
			t.Errorf("intel title = %q, want %q", title, "Package updated")
		}
		if summary != "curl: 7.64 → 7.81" {
			t.Errorf("intel summary = %q, want %q", summary, "curl: 7.64 → 7.81")
		}
		// subject-only detail.
		if _, s := formatIntelligence("account.user.created", []byte(`{"username":"alice"}`)); s != "alice" {
			t.Errorf("user-created summary = %q, want alice", s)
		}

		// --- audit ---
		title, summary = FormatAudit("host.created", "alice@example.com", "user", "host")
		if title != "alice@example.com created a host" {
			t.Errorf("audit title = %q", title)
		}
		if summary != "Host" {
			t.Errorf("audit summary = %q, want Host", summary)
		}
		// actor_label empty -> readable actor_type; no UUID anywhere.
		title, _ = FormatAudit("authz.permission.denied", "", "system", "")
		if title != "System was denied permission" {
			t.Errorf("audit fallback title = %q", title)
		}
	})
}

// @ac AC-25
// AC-25: an unmapped code never leaks as a raw dotted enum — it is humanized
// (no '.' separators) for every leg.
func TestFormatters_GracefulFallback(t *testing.T) {
	t.Run("system-activity/AC-25", func(t *testing.T) {
		// Unknown intelligence code.
		title, _ := formatIntelligence("system.future.thing", nil)
		if title != "System future thing" {
			t.Errorf("unmapped intel title = %q, want humanized", title)
		}
		if containsDot(title) {
			t.Errorf("intel title %q still contains a raw dotted code", title)
		}

		// Unknown audit action.
		title, _ = FormatAudit("widget.frobnicated", "bob", "user", "")
		if containsDot(title) {
			t.Errorf("audit title %q still contains a raw dotted code", title)
		}
		if title != "bob widget frobnicated" {
			t.Errorf("unmapped audit title = %q", title)
		}

		// Unknown transaction change_kind degrades to the status word.
		if _, s := formatTransaction("r", "error", "weird_kind", nil); s != "Error" {
			t.Errorf("unmapped change_kind summary = %q, want Error", s)
		}
	})
}

func containsDot(s string) bool {
	for _, r := range s {
		if r == '.' {
			return true
		}
	}
	return false
}
