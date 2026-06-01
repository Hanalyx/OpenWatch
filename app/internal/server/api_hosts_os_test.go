// @spec api-hosts
//
// AC traceability (this file):
//
//	AC-20  TestHosts_GetByID_OSFields_NullPreDiscovery
//	AC-21  TestHosts_GetByID_OSFields_PopulatedPostDiscovery
//	AC-22  TestHosts_List_OSFields_AndSingleSelect

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-20
// AC-20: Fresh host (no Discovery run) returns 200 with all 5 OS
// fields = null in the JSON envelope (keys present, values null).
func TestHosts_GetByID_OSFields_NullPreDiscovery(t *testing.T) {
	t.Run("api-hosts/AC-20", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createHostAPI(t, url, "fresh-host", "production")
		idStr := created["id"].(string)

		req := asRole(t, "GET", url+"/api/v1/hosts/"+idStr, auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d body=%s", resp.StatusCode, b)
		}

		// Decode as a flexible map. Per AC-20 each field is null OR
		// omitted entirely; both serialize to *string == nil after the
		// typed decode. So if the key IS present it MUST be null.
		var envelope map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&envelope)
		hostObj, ok := envelope["host"].(map[string]any)
		if !ok {
			t.Fatalf("response envelope missing 'host' object: %+v", envelope)
		}
		for _, field := range []string{"os_family", "os_version", "architecture", "platform_identifier", "os_discovered_at"} {
			if val, present := hostObj[field]; present && val != nil {
				t.Errorf("field %q = %v on fresh host, want null or absent", field, val)
			}
		}
	})
}

// @ac AC-21
// AC-21: After UPDATEing hosts.os_* columns directly (simulating a
// completed Discovery run), GET /hosts/{id} returns the values.
func TestHosts_GetByID_OSFields_PopulatedPostDiscovery(t *testing.T) {
	t.Run("api-hosts/AC-21", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "rhel-host", "production")
		idStr := created["id"].(string)

		discoveredAt := time.Now().UTC().Truncate(time.Second).Add(-1 * time.Minute)
		_, err := pool.Exec(context.Background(), `
			UPDATE hosts
			   SET os_family = $2,
			       os_version = $3,
			       architecture = $4,
			       platform_identifier = $5,
			       os_discovered_at = $6
			 WHERE id = $1`,
			idStr, "rhel", "9.4", "x86_64", "platform:el9", discoveredAt)
		if err != nil {
			t.Fatalf("update hosts os fields: %v", err)
		}

		req := asRole(t, "GET", url+"/api/v1/hosts/"+idStr, auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		var envelope struct {
			Host struct {
				OsFamily           *string    `json:"os_family"`
				OsVersion          *string    `json:"os_version"`
				Architecture       *string    `json:"architecture"`
				PlatformIdentifier *string    `json:"platform_identifier"`
				OsDiscoveredAt     *time.Time `json:"os_discovered_at"`
			} `json:"host"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&envelope)
		if envelope.Host.OsFamily == nil || *envelope.Host.OsFamily != "rhel" {
			t.Errorf("os_family=%v, want rhel", envelope.Host.OsFamily)
		}
		if envelope.Host.OsVersion == nil || *envelope.Host.OsVersion != "9.4" {
			t.Errorf("os_version=%v, want 9.4", envelope.Host.OsVersion)
		}
		if envelope.Host.Architecture == nil || *envelope.Host.Architecture != "x86_64" {
			t.Errorf("architecture=%v, want x86_64", envelope.Host.Architecture)
		}
		if envelope.Host.PlatformIdentifier == nil || *envelope.Host.PlatformIdentifier != "platform:el9" {
			t.Errorf("platform_identifier=%v, want platform:el9", envelope.Host.PlatformIdentifier)
		}
		if envelope.Host.OsDiscoveredAt == nil {
			t.Errorf("os_discovered_at is nil; want populated")
		}
	})
}

// @ac AC-22
// AC-22: GET /hosts items carry the same five fields; source-inspect
// the SELECT clause to enforce single-query semantics (no JOIN to
// host_system_info).
func TestHosts_List_OSFields_AndSingleSelect(t *testing.T) {
	t.Run("api-hosts/AC-22", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		_ = createHostAPI(t, url, "list-fresh", "production")
		populated := createHostAPI(t, url, "list-rhel", "production")
		populatedID := populated["id"].(string)
		_, err := pool.Exec(context.Background(),
			`UPDATE hosts SET os_family = 'rhel', os_version = '9.4' WHERE id = $1`,
			populatedID)
		if err != nil {
			t.Fatalf("seed populated os fields: %v", err)
		}

		req := asRole(t, "GET", url+"/api/v1/hosts", auth.RoleAdmin, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var page struct {
			Hosts []map[string]any `json:"hosts"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&page)
		if len(page.Hosts) < 2 {
			t.Fatalf("list returned %d hosts, want >= 2", len(page.Hosts))
		}
		// Pre-Discovery hosts may omit the OS fields (omitempty on
		// nullable nullable pointers). What matters is the populated
		// host carries them — asserted below.
		// Find the populated host and assert its values.
		var foundRHEL bool
		for _, h := range page.Hosts {
			if h["id"] == populatedID {
				foundRHEL = true
				if h["os_family"] != "rhel" {
					t.Errorf("populated host os_family=%v, want rhel", h["os_family"])
				}
				if h["os_version"] != "9.4" {
					t.Errorf("populated host os_version=%v, want 9.4", h["os_version"])
				}
			}
		}
		if !foundRHEL {
			t.Errorf("populated host not in list response")
		}

		// Source inspection (Spec C-11): the list query SELECT clause
		// includes the OS columns directly — no follow-up read, no JOIN
		// to host_system_info. The denormalized columns exist precisely
		// to make this single-SELECT.
		_, file, _, _ := runtime.Caller(0)
		src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "hosts_handlers.go"))
		if err != nil {
			t.Fatalf("read hosts_handlers.go: %v", err)
		}
		s := string(src)
		for _, col := range []string{"os_family", "os_version", "architecture", "platform_identifier", "os_discovered_at"} {
			if !strings.Contains(s, col) {
				t.Errorf("hosts_handlers.go does not reference %q in any SELECT — list handler must read OS columns directly", col)
			}
		}
		if strings.Contains(s, "JOIN host_system_info") {
			t.Errorf("hosts_handlers.go contains JOIN host_system_info — must use denormalized hosts.os_* columns instead (Spec C-11)")
		}
	})
}
