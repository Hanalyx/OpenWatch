// @spec system-auth-identity
//
//	AC-32  TestBurnPasswordVerify_DoesRealKeyStretching
package identity

import (
	"testing"
	"time"
)

// @ac AC-32
// AC-32: the decoy verification does REAL Argon2id work.
//
// The point of BurnPasswordVerify is that a username miss costs what a hit
// costs. A sleep, a constant, or a no-op would satisfy a naive reading and
// close nothing: a sleep is trivially distinguishable under load, and a no-op
// leaves the original oracle intact. So assert the work actually happens, by
// comparing it against a genuine verification of a real hash.
func TestBurnPasswordVerify_DoesRealKeyStretching(t *testing.T) {
	t.Run("system-auth-identity/AC-32", func(t *testing.T) {
		hash, err := HashPassword("a-real-password-for-comparison")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}

		// Cost of a real failed verification: the work an attacker observes
		// when the username EXISTS and the password is wrong.
		start := time.Now()
		_ = VerifyPassword("wrong-password", hash)
		real := time.Since(start)

		// Warm the decoy so its one-time hash computation is not counted.
		BurnPasswordVerify()

		start = time.Now()
		BurnPasswordVerify()
		decoy := time.Since(start)

		if decoy <= 0 {
			t.Fatal("decoy did no measurable work")
		}
		// Generous bound: this asserts the same ORDER of work, not a constant
		// time guarantee, and it must not flake on a loaded CI runner. A
		// sleep-based or no-op implementation fails this by orders of
		// magnitude; normal scheduler jitter does not.
		if decoy < real/8 {
			t.Errorf("decoy work %v is far below a real verification %v; "+
				"the enumeration oracle is not closed", decoy, real)
		}
	})
}
