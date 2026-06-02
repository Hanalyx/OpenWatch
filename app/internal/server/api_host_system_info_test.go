// @spec api-host-system-info
//
// AC traceability (this file):
//
//   AC-01  TestAPI_HostSystemInfo_GET_ReturnsExistingRow
//   AC-02  TestAPI_HostSystemInfo_GET_NoRow_404
//   AC-03  TestAPI_HostSystemInfo_GET_UnknownHost_404
//   AC-04  TestAPI_HostSystemInfo_GET_Anonymous_Forbidden
//   AC-05  TestAPI_HostSystemInfo_Handler_UsesParameterizedSQL

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// seedSystemInfo inserts a host_system_info row directly. Returns
// the host id for downstream lookups. Uses TestAPI_helpers fixture
// state (freshAPIServer truncates host_system_info via cascading
// host wipe).
func seedSystemInfo(t *testing.T, pool any, hostID uuid.UUID, hostname, kernelRelease string, memTotalMB int) {
	t.Helper()
	// Reflect-free: use the pool's QueryRow path via the existing
	// test helpers' pgxpool.Pool. We're cheating slightly — the
	// pool comes from freshAPIServer via api_helpers_test.go's
	// concrete type. Cast here.
	type execer interface {
		Exec(ctx context.Context, sql string, args ...any) (pgconn, error)
	}
	_ = execer(nil) // unused; we use type assertion below
}

// AC-01: GET on a host that has a row returns 200 with the JSON.
func TestAPI_HostSystemInfo_GET_ReturnsExistingRow(t *testing.T) {
	t.Run("api-host-system-info/AC-01", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// Seed a host + system-info row.
		hid := uuid.Must(uuid.NewV7())
		_, err := pool.Exec(context.Background(),
			`INSERT INTO hosts (id, hostname, ip_address, environment, created_by)
			 VALUES ($1, $2, $3::inet, 'production',
			         (SELECT id FROM users LIMIT 1))`,
			hid, "ow-sysinfo-test", "192.0.2.1")
		if err != nil {
			t.Fatalf("seed host: %v", err)
		}
		_, err = pool.Exec(context.Background(),
			`INSERT INTO host_system_info (host_id, os_family, os_version, kernel_release,
			                               mem_total_mb, fqdn, collected_at)
			 VALUES ($1, 'rhel', '9.5', '5.14.0-test', 4096, 'ow-sysinfo-test.local', now())`,
			hid)
		if err != nil {
			t.Fatalf("seed system_info: %v", err)
		}

		req := asRole(t, "GET", url+"/api/v1/hosts/"+hid.String()+"/system-info", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["host_id"] != hid.String() {
			t.Errorf("host_id: want %s, got %v", hid, body["host_id"])
		}
		if body["os_family"] != "rhel" {
			t.Errorf("os_family: want rhel, got %v", body["os_family"])
		}
		if body["fqdn"] != "ow-sysinfo-test.local" {
			t.Errorf("fqdn: want ow-sysinfo-test.local, got %v", body["fqdn"])
		}
		// collected_at present as RFC3339-ish string.
		if _, ok := body["collected_at"].(string); !ok {
			t.Errorf("collected_at not a string: %T", body["collected_at"])
		}
	})
}

// AC-02: GET on a known host with NO system-info row returns 404.
func TestAPI_HostSystemInfo_GET_NoRow_404(t *testing.T) {
	t.Run("api-host-system-info/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hid := uuid.Must(uuid.NewV7())
		_, err := pool.Exec(context.Background(),
			`INSERT INTO hosts (id, hostname, ip_address, environment, created_by)
			 VALUES ($1, $2, $3::inet, 'production',
			         (SELECT id FROM users LIMIT 1))`,
			hid, "ow-no-sysinfo", "192.0.2.2")
		if err != nil {
			t.Fatalf("seed host: %v", err)
		}
		req := asRole(t, "GET", url+"/api/v1/hosts/"+hid.String()+"/system-info", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&env)
		if env.Error.Code != "hosts.not_found" {
			t.Errorf("want code=hosts.not_found, got %q", env.Error.Code)
		}
	})
}

// AC-03: GET on an unknown host id returns 404 with the SAME envelope.
func TestAPI_HostSystemInfo_GET_UnknownHost_404(t *testing.T) {
	t.Run("api-host-system-info/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		unknownID := uuid.Must(uuid.NewV7())
		req := asRole(t, "GET", url+"/api/v1/hosts/"+unknownID.String()+"/system-info", auth.RoleViewer, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&env)
		if env.Error.Code != "hosts.not_found" {
			t.Errorf("want code=hosts.not_found, got %q", env.Error.Code)
		}
	})
}

// AC-04: Anonymous caller is rejected before the row read.
func TestAPI_HostSystemInfo_GET_Anonymous_Forbidden(t *testing.T) {
	t.Run("api-host-system-info/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		hid := uuid.Must(uuid.NewV7())
		req, _ := http.NewRequest("GET",
			url+"/api/v1/hosts/"+hid.String()+"/system-info", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 anon, got %d", resp.StatusCode)
		}
	})
}

// AC-05: Source inspection — the handler MUST use a parameterized
// SELECT against host_system_info with $1 bound to host_id. No
// string-concat / fmt.Sprintf-built SQL.
func TestAPI_HostSystemInfo_Handler_UsesParameterizedSQL(t *testing.T) {
	t.Run("api-host-system-info/AC-05", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		path := filepath.Join(filepath.Dir(file), "host_system_info_handler.go")
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read handler: %v", err)
		}
		s := string(src)
		if !strings.Contains(s, "WHERE host_id = $1") {
			t.Error("handler missing parameterized WHERE host_id = $1 — SQL injection risk")
		}
		// No fmt.Sprintf into the query string.
		if strings.Contains(s, `fmt.Sprintf("SELECT`) || strings.Contains(s, `fmt.Sprintf("INSERT`) {
			t.Error("handler appears to use fmt.Sprintf to build SQL — SQL injection risk")
		}
		// No raw string-concat. The lazy way to detect this is to
		// look for a `" + ` pattern in the same paragraph as
		// `SELECT`. Heuristic but catches the obvious case.
		if strings.Contains(s, "SELECT") && strings.Contains(s, `" + `) {
			t.Error("handler appears to concatenate strings into the SQL — SQL injection risk")
		}
	})
}

// Placeholder type so the seedSystemInfo helper compiles cleanly even
// without using it. Real seeding happens inline in AC-01.
type pgconn struct{}
