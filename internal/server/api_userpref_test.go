// @spec system-user-preferences
//
// AC traceability (this file):
//   AC-01  TestUserPrefs_Get_EmptyWhenUnset
//   AC-02  TestUserPrefs_Patch_ShallowMerge
//   AC-03  TestUserPrefs_Patch_InvalidEnumRejected
//   AC-04  TestUserPrefs_AnonymousRejected

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
)

type prefsBody struct {
	HostsViewDefault *string `json:"hosts_view_default"`
	Density          *string `json:"density"`
	AccentColor      *string `json:"accent_color"`
}

func getPrefs(t *testing.T, url string, role auth.RoleID) (int, prefsBody) {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/users/me/preferences", role, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	var p prefsBody
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatalf("decode prefs: %v", err)
		}
	}
	return resp.StatusCode, p
}

func patchPrefs(t *testing.T, url string, role auth.RoleID, body any) (int, prefsBody) {
	t.Helper()
	req := asRole(t, "PATCH", url+"/api/v1/users/me/preferences", role, body)
	resp := doReq(t, req)
	defer resp.Body.Close()
	var p prefsBody
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatalf("decode prefs: %v", err)
		}
	}
	return resp.StatusCode, p
}

// @ac AC-01
func TestUserPrefs_Get_EmptyWhenUnset(t *testing.T) {
	t.Run("system-user-preferences/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		status, p := getPrefs(t, url, auth.RoleAdmin)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if p.HostsViewDefault != nil || p.Density != nil || p.AccentColor != nil {
			t.Errorf("unset prefs returned %+v, want all nil (empty object)", p)
		}
	})
}

// @ac AC-02
func TestUserPrefs_Patch_ShallowMerge(t *testing.T) {
	t.Run("system-user-preferences/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// First PATCH sets hosts_view_default.
		status, p := patchPrefs(t, url, auth.RoleAdmin, map[string]any{"hosts_view_default": "table"})
		if status != http.StatusOK {
			t.Fatalf("first patch status = %d, want 200", status)
		}
		if p.HostsViewDefault == nil || *p.HostsViewDefault != "table" {
			t.Fatalf("hosts_view_default = %v, want table", p.HostsViewDefault)
		}

		// Second PATCH sets a DIFFERENT key; the first MUST be retained (merge).
		status, p = patchPrefs(t, url, auth.RoleAdmin, map[string]any{"density": "compact"})
		if status != http.StatusOK {
			t.Fatalf("second patch status = %d, want 200", status)
		}
		if p.Density == nil || *p.Density != "compact" {
			t.Errorf("density = %v, want compact", p.Density)
		}
		if p.HostsViewDefault == nil || *p.HostsViewDefault != "table" {
			t.Errorf("hosts_view_default = %v after merge, want table retained (not overwritten)",
				p.HostsViewDefault)
		}

		// And a fresh GET reflects the merged state.
		_, got := getPrefs(t, url, auth.RoleAdmin)
		if got.HostsViewDefault == nil || *got.HostsViewDefault != "table" ||
			got.Density == nil || *got.Density != "compact" {
			t.Errorf("GET after merge = %+v, want table + compact", got)
		}
	})
}

// @ac AC-03
func TestUserPrefs_Patch_InvalidEnumRejected(t *testing.T) {
	t.Run("system-user-preferences/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Seed a valid value first.
		patchPrefs(t, url, auth.RoleAdmin, map[string]any{"hosts_view_default": "cards"})

		// An out-of-range enum is rejected 400 and must NOT persist.
		req := asRole(t, "PATCH", url+"/api/v1/users/me/preferences", auth.RoleAdmin,
			map[string]any{"hosts_view_default": "weird"})
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for invalid enum", resp.StatusCode)
		}

		_, got := getPrefs(t, url, auth.RoleAdmin)
		if got.HostsViewDefault == nil || *got.HostsViewDefault != "cards" {
			t.Errorf("after rejected patch hosts_view_default = %v, want cards (unchanged)",
				got.HostsViewDefault)
		}
	})
}

// @ac AC-04
func TestUserPrefs_AnonymousRejected(t *testing.T) {
	t.Run("system-user-preferences/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// role "" → no session cookie → anonymous.
		if status, _ := getPrefs(t, url, ""); status != http.StatusUnauthorized {
			t.Errorf("anonymous GET status = %d, want 401", status)
		}
		req := asRole(t, "PATCH", url+"/api/v1/users/me/preferences", "",
			map[string]any{"hosts_view_default": "table"})
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous PATCH status = %d, want 401", resp.StatusCode)
		}
	})
}
