// @spec system-worker-subcommand
//
// AC traceability (this file):
//
//	AC-15  TestHostLockKey_Deterministic_FNV1a64
//	       TestHostLockKey_DifferentHosts_DifferentKeys

package worker

import (
	"hash/fnv"
	"testing"

	"github.com/google/uuid"
)

// AC-15 — derivation result is deterministic and matches a fresh
// independent FNV-1a 64-bit computation over the same bytes. Anyone
// changing hostLockKey's strategy makes this test fail.
func TestHostLockKey_Deterministic_FNV1a64(t *testing.T) {
	t.Run("system-worker-subcommand/AC-15", func(t *testing.T) {
		id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

		got := hostLockKey(id)

		h := fnv.New64a()
		h.Write(id[:])
		want := int64(h.Sum64())

		if got != want {
			t.Errorf("hostLockKey = %d, independent FNV-1a 64-bit = %d", got, want)
		}

		// Calling twice with the same input MUST return the same key.
		if hostLockKey(id) != got {
			t.Errorf("hostLockKey not deterministic across calls")
		}
	})
}

// AC-15 — two distinct host UUIDs MUST produce two distinct keys. The
// math is well-known; this is a smoke test against a future refactor
// that returns a constant by mistake.
func TestHostLockKey_DifferentHosts_DifferentKeys(t *testing.T) {
	t.Run("system-worker-subcommand/AC-15", func(t *testing.T) {
		a := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
		b := uuid.MustParse("550e8400-e29b-41d4-a716-446655440001")
		if hostLockKey(a) == hostLockKey(b) {
			t.Errorf("hostLockKey collided on distinct UUIDs (a=%v b=%v)", a, b)
		}
	})
}
