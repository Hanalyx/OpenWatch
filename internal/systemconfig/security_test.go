// @spec system-connection-profile
//
// AC traceability (this file):
//
//	AC-06  TestDefaultSecurity_FallbackOnByDefault
//
// Also hosts the system-account-policy config AC:
//	AC-03  TestSecurityConfig_PasswordExpiryWarnWindow

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

// @spec system-account-policy
// @ac AC-03
// AC-03: WarnDaysBeforePasswordExpiry defaults to 14; Validate rejects a
// value outside [1, 365] and accepts 0 (treated as unset by the sweep).
func TestSecurityConfig_PasswordExpiryWarnWindow(t *testing.T) {
	t.Run("system-account-policy/AC-03", func(t *testing.T) {
		if got := DefaultSecurity().WarnDaysBeforePasswordExpiry; got != 14 {
			t.Errorf("default warn days = %d, want 14", got)
		}
		valid := []int{0, 1, 14, 365}
		for _, v := range valid {
			c := SecurityConfig{WarnDaysBeforePasswordExpiry: v}
			if err := c.Validate(); err != nil {
				t.Errorf("Validate(%d) = %v, want nil", v, err)
			}
		}
		for _, v := range []int{-1, 366, 100000} {
			c := SecurityConfig{WarnDaysBeforePasswordExpiry: v}
			if err := c.Validate(); err == nil {
				t.Errorf("Validate(%d) = nil, want an error", v)
			}
		}
	})
}
