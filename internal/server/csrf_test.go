// @spec system-http-server
package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-19
// AC-19: a cookie-authenticated unsafe request with no/mismatched
// X-CSRF-Token is 403 authz.csrf_invalid; a matching one proceeds.
// Regression guard for the finding that the frontend's double-submit was
// theater (server never set the cookie nor validated the header).
func TestCSRF_Enforcement(t *testing.T) {
	t.Run("system-http-server/AC-19", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		session := roleCookies[auth.RoleAdmin]

		// Cookie-authenticated unsafe request WITHOUT a CSRF token → 403.
		req, _ := http.NewRequest("POST", url+"/api/v1/tokens",
			bytes.NewReader([]byte(`{"name":"csrf-x","role_id":"viewer"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(session)
		// Bypass doReq (which would helpfully attach the token) so the raw,
		// token-less request reaches csrfProtect.
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("no-CSRF mutating request = %d, want 403", resp.StatusCode)
		}
		if !strings.Contains(string(body), "authz.csrf_invalid") {
			t.Errorf("expected authz.csrf_invalid, got: %s", body)
		}

		// Same request WITH a matching double-submit pair proceeds (201).
		ok := doReq(t, asRole(t, "POST", url+"/api/v1/tokens", auth.RoleAdmin,
			map[string]any{"name": "csrf-y", "role_id": "viewer"}))
		defer ok.Body.Close()
		if ok.StatusCode == http.StatusForbidden {
			t.Errorf("request with a matching CSRF token was 403'd")
		}
	})
}

// AC-19 (exemptions): a request with no session cookie is exempt (CSRF only
// matters with ambient cookie authority) — so an anonymous mutating request
// reaches the handler's own auth check (401/403), not a CSRF 403.
func TestCSRF_NoSessionCookieExempt(t *testing.T) {
	url, _ := freshAPIServer(t)
	req, _ := http.NewRequest("POST", url+"/api/v1/tokens",
		bytes.NewReader([]byte(`{"name":"z","role_id":"viewer"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp := doReq(t, req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Must be denied by RBAC/auth, NOT by CSRF (no ambient session to abuse).
	if strings.Contains(string(body), "authz.csrf_invalid") {
		t.Errorf("anonymous request hit CSRF check; should be exempt: %s", body)
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("anonymous mutating request = %d, want 401/403 from auth", resp.StatusCode)
	}
}
