// @spec system-api-tokens
//
// Source-inspection guard for the binder routing (AC-04). No DB.

package apitoken

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// @ac AC-04
// The identity binder must route auth.APITokenPrefix bearer values to the
// token authenticator and fall through to JWT otherwise.
func TestBinderRoutesAPITokens(t *testing.T) {
	t.Run("system-api-tokens/AC-04", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join("..", "identity", "binder.go"))
		if err != nil {
			t.Fatalf("read binder.go: %v", err)
		}
		s := string(src)
		// Routes prefixed bearer values to the token authenticator.
		if !strings.Contains(s, "auth.APITokenPrefix") {
			t.Error("binder does not reference auth.APITokenPrefix")
		}
		if !strings.Contains(s, "cfg.tokenAuth.AuthenticateToken") {
			t.Error("binder does not call cfg.tokenAuth.AuthenticateToken")
		}
		// A token-auth error falls through to anonymous with the canonical
		// reason, not a JWT parse.
		if !strings.Contains(s, "invalid_api_token") {
			t.Error("binder lacks the invalid_api_token rejection reason")
		}
		// The JWT path is still present (non-prefixed bearer values).
		if !strings.Contains(s, "VerifyJWT(token)") {
			t.Error("binder lost the JWT path")
		}
	})
}
