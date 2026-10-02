package server

import (
	"net/http"
	"testing"
)

// assertTokenRefused sends one request with an owk_ bearer and fails unless
// it answers 403 auth.api_token_not_allowed. bugs/OW-098.
func assertTokenRefused(t *testing.T, url, raw, method, path string, body any) {
	t.Helper()
	st, code, b := bearerDo(t, url, raw, method, path, body)
	if st != http.StatusForbidden || code != "auth.api_token_not_allowed" {
		t.Errorf("%s %s with a token = %d %s, want 403 auth.api_token_not_allowed", method, path, st, code)
	}
	if items, ok := b["items"]; ok {
		t.Errorf("%s %s returned items to a token: %v", method, path, items)
	}
}
