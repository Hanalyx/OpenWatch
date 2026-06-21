// @spec system-audit-emission
//
//	AC-16  TestClipDetail

package audit

import "strings"

import "testing"

// @ac AC-16
func TestClipDetail(t *testing.T) {
	t.Run("system-audit-emission/AC-16", func(t *testing.T) {
		// Short clean string unchanged.
		if got := ClipDetail("Mozilla/5.0"); got != "Mozilla/5.0" {
			t.Errorf("clean = %q, want unchanged", got)
		}
		// Control chars replaced with spaces (log-forging neutralized).
		if got := ClipDetail("a\nb\tc\x00d"); got != "a b c d" {
			t.Errorf("control = %q, want 'a b c d'", got)
		}
		// Truncated to MaxDetailFieldLen runes (bloat bounded).
		long := strings.Repeat("x", MaxDetailFieldLen+50)
		if got := ClipDetail(long); len([]rune(got)) != MaxDetailFieldLen {
			t.Errorf("len = %d, want %d", len([]rune(got)), MaxDetailFieldLen)
		}
	})
}
