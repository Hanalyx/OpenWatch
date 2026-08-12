// @spec system-auth-identity
//
//	AC-33  TestLogout_ReportsIncompleteRevoke
package server

import (
	"os"
	"strings"
	"testing"
)

// @ac AC-33
// AC-33: logout does not report success it did not achieve.
//
// Source inspection rather than a live failure injection: making the revoke
// fail for real needs a seam through the pool that does not exist, and adding
// one only for this would be a larger change than the fix. What must not
// regress is structural and is checkable directly: the two revoke errors must
// not be discarded, and the handler must be able to answer with something
// other than 204.
//
// The bug: both revokes were `_ = ...` and the handler returned 204
// unconditionally. Cookies are cleared either way, so the user saw a clean
// logout while a stolen session or refresh token stayed live. Someone logging
// out on a shared or compromised machine is precisely the person who cannot
// afford that.
func TestLogout_ReportsIncompleteRevoke(t *testing.T) {
	t.Run("system-auth-identity/AC-33", func(t *testing.T) {
		raw, err := os.ReadFile("auth_handlers.go")
		if err != nil {
			t.Fatalf("read auth_handlers.go: %v", err)
		}
		src := string(raw)
		i := strings.Index(src, "func (h *handlers) PostAuthLogout(")
		if i < 0 {
			t.Fatal("PostAuthLogout not found")
		}
		body := src[i:]
		if j := strings.Index(body[1:], "\nfunc "); j >= 0 {
			body = body[:j]
		}

		// Neither revoke may be discarded.
		for _, discarded := range []string{
			"_ = identity.RevokeSession(",
			"_ = identity.RevokeRefreshToken(",
		} {
			if strings.Contains(body, discarded) {
				t.Errorf("logout still discards a revoke error: %s", discarded)
			}
		}

		// A failed revoke must be observable to the operator and to the caller.
		if !strings.Contains(body, "slog.ErrorContext") {
			t.Error("a failed revoke must be logged at error level")
		}
		if !strings.Contains(body, "auth.logout_incomplete") {
			t.Error("logout must be able to tell the caller the revoke did not complete")
		}

		// Cookies must still be cleared even on the failure path, so the
		// browser stops presenting a credential the server could not kill.
		clearIdx := strings.Index(body, "MaxAge:   -1")
		failIdx := strings.Index(body, "auth.logout_incomplete")
		if clearIdx < 0 || failIdx < 0 || clearIdx > failIdx {
			t.Error("cookies must be cleared BEFORE the incomplete-revoke response, not skipped by it")
		}
	})
}
