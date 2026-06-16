// @spec system-connection-profile
//
// AC traceability (this file):
//
//	AC-06  TestDefaultSecurity_FallbackOnByDefault

package systemconfig

import "testing"

// @ac AC-06
// AC-06: the sudo -S password fallback is ON by default. OpenWatch
// supports the full SSH matrix out of the box; the flag is a kill-switch,
// not an opt-in.
func TestDefaultSecurity_FallbackOnByDefault(t *testing.T) {
	t.Run("system-connection-profile/AC-06", func(t *testing.T) {
		if !DefaultSecurity().AllowCredentialSudoPassword {
			t.Error("DefaultSecurity().AllowCredentialSudoPassword = false, want true (default-on kill-switch)")
		}
	})
}
