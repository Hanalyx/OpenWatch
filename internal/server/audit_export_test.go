// @spec api-audit-events-query
//
//	AC-14  TestCSVSafe (csvSafe neutralizes formula injection)

package server

import "testing"

// @ac AC-14
func TestCSVSafe(t *testing.T) {
	t.Run("api-audit-events-query/AC-14", func(t *testing.T) {
		dangerous := []string{"=cmd", "+1", "-1", "@x", "\tlead", "\rlead"}
		for _, in := range dangerous {
			if got := csvSafe(in); got != "'"+in {
				t.Errorf("csvSafe(%q) = %q, want quote-prefixed", in, got)
			}
		}
		for _, in := range []string{"", "alice@example.com created a host", "host.created", "2026-06-20T00:00:00Z"} {
			if got := csvSafe(in); got != in {
				t.Errorf("csvSafe(%q) = %q, want unchanged", in, got)
			}
		}
	})
}
