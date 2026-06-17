// @spec system-ssh-connectivity
//
// PostgreSQL known-hosts store. Skipped without OPENWATCH_TEST_DSN (uses the
// shared per-package isolated test DB).
package knownhosts

import (
	"testing"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// @ac AC-22
// AC-22: the store round-trips Put/Get, returns not-found for an absent
// host, and (the durable-TOFU guarantee) a key persisted by one Store
// instance is visible to a fresh instance on the same DB — proving TOFU
// survives a process restart, which the in-memory store could not.
func TestStore_DurableTOFU(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-22", func(t *testing.T) {
		pool := dbtest.Pool(t)
		s := NewStore(pool)
		key := []byte("ssh-ed25519-marshalled-key-bytes-host-a")

		// Absent host → not found.
		if _, ok := s.Get("host-a"); ok {
			t.Fatal("Get on an absent host returned ok=true")
		}

		// Put then Get round-trips.
		if err := s.Put("host-a", key); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, ok := s.Get("host-a")
		if !ok || string(got) != string(key) {
			t.Fatalf("Get = (%q, %v), want (%q, true)", got, ok, key)
		}

		// "Restart": a fresh Store on the same DB still sees the key — the
		// durable-TOFU guarantee the in-memory store lacked.
		fresh := NewStore(pool)
		got2, ok2 := fresh.Get("host-a")
		if !ok2 || string(got2) != string(key) {
			t.Errorf("after restart Get = (%q, %v), want the persisted key", got2, ok2)
		}

		// Re-Put of the SAME key is idempotent (refreshes last_seen, no error).
		if err := s.Put("host-a", key); err != nil {
			t.Errorf("idempotent re-Put: %v", err)
		}
	})
}
