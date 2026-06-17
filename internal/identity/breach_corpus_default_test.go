// @spec system-auth-identity
package identity

import (
	"errors"
	"testing"
)

// @ac AC-27
// AC-27: the embedded default breach corpus is non-empty and rejects common
// compromised passwords via ValidatePassword. Production now wires
// DefaultBreachCorpus instead of nil, so breached passwords are no longer
// silently accepted (the pre-release finding: every prod wiring passed nil,
// disabling the breach check entirely).
func TestDefaultBreachCorpus_RejectsCommonPasswords(t *testing.T) {
	t.Run("system-auth-identity/AC-27", func(t *testing.T) {
		corpus := DefaultBreachCorpus()
		if corpus.Size() < 50 {
			t.Fatalf("default corpus size = %d, want a meaningful baseline", corpus.Size())
		}
		policy := PasswordPolicy{MinLength: 8, MaxLength: 128}
		// Common breached passwords that pass the length floor must be rejected.
		for _, pw := range []string{"password123", "qwerty123", "iloveyou", "Password1"} {
			if err := ValidatePassword(pw, policy, corpus); !errors.Is(err, ErrPasswordBreached) {
				t.Errorf("ValidatePassword(%q) = %v, want ErrPasswordBreached", pw, err)
			}
		}
		// A strong unique password is accepted.
		if err := ValidatePassword("Ztq9-vmK2!pLx7we", policy, corpus); err != nil {
			t.Errorf("strong unique password rejected: %v", err)
		}
	})
}
