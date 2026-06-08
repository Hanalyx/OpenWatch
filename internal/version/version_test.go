package version

import (
	"strings"
	"testing"
)

// Go() must return the toolchain version, never empty, and look like a Go
// version string.
func TestGo_NonEmptyAndPrefixed(t *testing.T) {
	got := Go()
	if got == "" {
		t.Fatal("Go() is empty")
	}
	if !strings.HasPrefix(got, "go") {
		t.Errorf("Go() = %q, want a 'go'-prefixed version", got)
	}
	t.Logf("Go() = %q", got)
}

// Kensa() must never be empty. In a module build it resolves to the linked
// Kensa version; when build info is unavailable it falls back to "unknown".
func TestKensa_NonEmpty(t *testing.T) {
	got := Kensa()
	if got == "" {
		t.Fatal("Kensa() is empty; want a version or 'unknown'")
	}
	t.Logf("Kensa() = %q", got)
}
