// @spec system-connection-profile
//
// AC traceability (this file):
//
//	AC-04  TestOrderedAuthMethods_PreferenceNotExclusion / TestAuthObserver_RecordsLast

package ssh

import "testing"

// @ac AC-04
// AC-04: every available auth method is offered (preference orders, does
// not exclude), so a stale hint still falls back within the one handshake.
func TestOrderedAuthMethods_PreferenceNotExclusion(t *testing.T) {
	t.Run("system-connection-profile/AC-04", func(t *testing.T) {
		both, _ := generateEd25519CredAndAuthKey(t)
		both.Password = "pw" // promote to a key+password credential

		// Both methods offered regardless of which is preferred.
		for _, prefer := range []string{"", PreferKey, PreferPassword} {
			m, err := orderedAuthMethods(both, prefer, &authObserver{})
			if err != nil {
				t.Fatalf("prefer %q: %v", prefer, err)
			}
			if len(m) != 2 {
				t.Errorf("prefer %q: %d methods, want 2 (preference is order, not exclusion)", prefer, len(m))
			}
		}

		// Key-only and password-only creds offer exactly their one method.
		keyOnly := *both
		keyOnly.Password = ""
		if m, _ := orderedAuthMethods(&keyOnly, "", &authObserver{}); len(m) != 1 {
			t.Errorf("key-only: %d methods, want 1", len(m))
		}
		pwOnly := *both
		pwOnly.PrivateKey = ""
		if m, _ := orderedAuthMethods(&pwOnly, "", &authObserver{}); len(m) != 1 {
			t.Errorf("password-only: %d methods, want 1", len(m))
		}
	})
}

// @ac AC-04
// AC-04 (observation): the observer reports the last method attempted,
// which after a successful handshake is the one that authenticated.
func TestAuthObserver_RecordsLast(t *testing.T) {
	t.Run("system-connection-profile/AC-04", func(t *testing.T) {
		o := &authObserver{}
		if o.Last() != "" {
			t.Errorf("fresh observer Last = %q, want empty", o.Last())
		}
		o.note(PreferKey)
		o.note(PreferPassword) // key rejected, password accepted -> last wins
		if o.Last() != PreferPassword {
			t.Errorf("Last = %q, want %q", o.Last(), PreferPassword)
		}
	})
}
