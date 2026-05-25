// @spec api-hosts
//
// Host inventory CRUD HTTP integration tests. Skipped without
// OPENWATCH_TEST_DSN.

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/google/uuid"
)

// createHostAPI is the canonical happy-path POST /admin/hosts helper.
func createHostAPI(t *testing.T, srvURL, hostname, env string) map[string]any {
	t.Helper()
	body := map[string]any{
		"hostname":    hostname,
		"ip_address":  "192.0.2.10",
		"environment": env,
	}
	req := asRole(t, "POST", srvURL+"/api/v1/admin/hosts", auth.RoleAdmin, body)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("seed createHost %s: status=%d body=%s", hostname, resp.StatusCode, b)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	return got
}

// @ac AC-01
// AC-01: POST /admin/hosts with valid body → 201 + host JSON.
func TestHosts_Create_Success(t *testing.T) {
	t.Run("api-hosts/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"hostname":   "ac01-host",
			"ip_address": "192.0.2.10",
		}
		req := asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		var got map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got["hostname"] != "ac01-host" {
			t.Errorf("hostname = %v, want ac01-host", got["hostname"])
		}
		if got["ip_address"] != "192.0.2.10" {
			t.Errorf("ip_address = %v, want 192.0.2.10", got["ip_address"])
		}
		// Default port = 22, default environment = production.
		if p, _ := got["port"].(float64); int(p) != 22 {
			t.Errorf("port = %v, want 22 default", got["port"])
		}
		if got["environment"] != "production" {
			t.Errorf("environment = %v, want production default", got["environment"])
		}
	})
}

// @ac AC-02
// AC-02: caller without host:write → 403; no row inserted.
func TestHosts_Create_DeniedWithoutPermission(t *testing.T) {
	t.Run("api-hosts/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := map[string]any{
			"hostname": "denied", "ip_address": "192.0.2.50",
		}
		// viewer lacks host:write.
		req := asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleViewer, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM hosts WHERE hostname = $1`, "denied").Scan(&count)
		if count != 0 {
			t.Errorf("count = %d, want 0", count)
		}
	})
}

// @ac AC-03
// AC-03: empty hostname or malformed ip → 400 hosts.invalid_input.
func TestHosts_Create_InvalidInput(t *testing.T) {
	t.Run("api-hosts/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Empty hostname.
		body := map[string]any{
			"hostname": "", "ip_address": "192.0.2.10",
		}
		req := asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleAdmin, body)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("empty hostname status = %d, want 400", resp.StatusCode)
		}

		// Malformed ip.
		body = map[string]any{
			"hostname": "bad-ip", "ip_address": "not.an.ip.address",
		}
		req = asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleAdmin, body)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("bad-ip status = %d body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "hosts.invalid_input") {
			t.Errorf("body lacks hosts.invalid_input: %s", b)
		}
	})
}

// @ac AC-04
// AC-04: duplicate hostname + environment → 409 hosts.duplicate.
func TestHosts_Create_Duplicate(t *testing.T) {
	t.Run("api-hosts/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		_ = createHostAPI(t, url, "dup-host", "staging")

		body := map[string]any{
			"hostname":    "dup-host",
			"ip_address":  "192.0.2.99",
			"environment": "staging",
		}
		req := asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 409; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "hosts.duplicate") {
			t.Errorf("body lacks hosts.duplicate: %s", b)
		}
	})
}

// @ac AC-05
// AC-05: GET /admin/hosts returns active rows; soft-deleted excluded.
func TestHosts_List_ExcludesDeleted(t *testing.T) {
	t.Run("api-hosts/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		alive := createHostAPI(t, url, "alive-host", "production")
		dead := createHostAPI(t, url, "dead-host", "production")

		// Soft-delete dead.
		req := asRole(t, "DELETE",
			url+"/api/v1/admin/hosts/"+dead["id"].(string), auth.RoleAdmin, nil)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete status = %d", resp.StatusCode)
		}

		req = asRole(t, "GET", url+"/api/v1/admin/hosts", auth.RoleAdmin, nil)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list status = %d", resp.StatusCode)
		}
		var body struct {
			Hosts []map[string]any `json:"hosts"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		names := []string{}
		for _, h := range body.Hosts {
			names = append(names, h["hostname"].(string))
		}
		if !contains(names, alive["hostname"].(string)) {
			t.Errorf("alive-host missing from list: %v", names)
		}
		if contains(names, "dead-host") {
			t.Errorf("dead-host appears in list (should be soft-deleted): %v", names)
		}
	})
}

// @ac AC-06
// AC-06: ?environment=staging returns only matching hosts.
func TestHosts_List_FilterByEnvironment(t *testing.T) {
	t.Run("api-hosts/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		_ = createHostAPI(t, url, "stage-1", "staging")
		_ = createHostAPI(t, url, "stage-2", "staging")
		_ = createHostAPI(t, url, "prod-1", "production")

		req := asRole(t, "GET", url+"/api/v1/admin/hosts?environment=staging",
			auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		var body struct {
			Hosts []map[string]any `json:"hosts"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if len(body.Hosts) != 2 {
			t.Errorf("hosts len = %d, want 2 (staging only)", len(body.Hosts))
		}
		for _, h := range body.Hosts {
			if h["environment"] != "staging" {
				t.Errorf("non-staging host in result: %v", h)
			}
		}
	})
}

// @ac AC-07
// AC-07: ?tag=critical returns only hosts with that tag.
func TestHosts_List_FilterByTag(t *testing.T) {
	t.Run("api-hosts/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Two hosts with critical tag, one without.
		body := map[string]any{
			"hostname": "crit-1", "ip_address": "192.0.2.11",
			"tags": []string{"critical", "edge"},
		}
		req := asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleAdmin, body)
		_ = doReq(t, req).Body.Close()

		body = map[string]any{
			"hostname": "crit-2", "ip_address": "192.0.2.12",
			"tags": []string{"critical"},
		}
		req = asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleAdmin, body)
		_ = doReq(t, req).Body.Close()

		body = map[string]any{
			"hostname": "non-crit", "ip_address": "192.0.2.13",
			"tags": []string{"edge"},
		}
		req = asRole(t, "POST", url+"/api/v1/admin/hosts", auth.RoleAdmin, body)
		_ = doReq(t, req).Body.Close()

		req = asRole(t, "GET", url+"/api/v1/admin/hosts?tag=critical",
			auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		var out struct {
			Hosts []map[string]any `json:"hosts"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if len(out.Hosts) != 2 {
			t.Errorf("hosts len = %d, want 2 (critical only)", len(out.Hosts))
		}
		for _, h := range out.Hosts {
			tags, _ := h["tags"].([]any)
			found := false
			for _, t := range tags {
				if t == "critical" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("host missing critical tag: %v", h)
			}
		}
	})
}

// @ac AC-08
// AC-08: GET /admin/hosts/{id} → 200 / 404.
func TestHosts_GetByID(t *testing.T) {
	t.Run("api-hosts/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createHostAPI(t, url, "by-id", "production")
		id := created["id"].(string)

		req := asRole(t, "GET", url+"/api/v1/admin/hosts/"+id, auth.RoleAdmin, nil)
		resp := doReq(t, req)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get status = %d body=%s", resp.StatusCode, b)
		}
		var got map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&got)
		resp.Body.Close()
		if got["hostname"] != "by-id" {
			t.Errorf("hostname = %v, want by-id", got["hostname"])
		}

		// Unknown id → 404.
		req = asRole(t, "GET", url+"/api/v1/admin/hosts/"+uuid.New().String(),
			auth.RoleAdmin, nil)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unknown status = %d, want 404", resp.StatusCode)
		}
	})
}

// @ac AC-09
// AC-09: PATCH applies update; immutable fields preserved; updated_at advances.
func TestHosts_Patch_Update(t *testing.T) {
	t.Run("api-hosts/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createHostAPI(t, url, "patch-host", "production")
		id := created["id"].(string)
		origHostname := created["hostname"].(string)
		origCreatedBy := created["created_by"].(string)
		origCreatedAt := created["created_at"].(string)
		origUpdatedAt := created["updated_at"].(string)

		body := map[string]any{
			"display_name": "New Display",
			"description":  "Updated description",
			"port":         2222,
			"tags":         []string{"linux", "frontend"},
		}
		req := asRole(t, "PATCH", url+"/api/v1/admin/hosts/"+id, auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("patch status = %d body=%s", resp.StatusCode, b)
		}
		var got map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&got)
		if got["display_name"] != "New Display" {
			t.Errorf("display_name = %v, want New Display", got["display_name"])
		}
		if p, _ := got["port"].(float64); int(p) != 2222 {
			t.Errorf("port = %v, want 2222", got["port"])
		}
		// Immutable fields preserved.
		if got["hostname"] != origHostname {
			t.Errorf("hostname mutated: %v vs %v", got["hostname"], origHostname)
		}
		if got["created_by"] != origCreatedBy {
			t.Errorf("created_by mutated: %v vs %v", got["created_by"], origCreatedBy)
		}
		if got["created_at"] != origCreatedAt {
			t.Errorf("created_at mutated: %v vs %v", got["created_at"], origCreatedAt)
		}
		// updated_at advances.
		if got["updated_at"] == origUpdatedAt {
			t.Errorf("updated_at did not advance: %v", got["updated_at"])
		}
	})
}

// @ac AC-10
// AC-10: PATCH with malformed ip → 400; no fields mutated.
func TestHosts_Patch_InvalidIP(t *testing.T) {
	t.Run("api-hosts/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createHostAPI(t, url, "patch-bad-ip", "production")
		id := created["id"].(string)
		origIP := created["ip_address"].(string)

		body := map[string]any{
			"ip_address": "not.a.real.ip",
		}
		req := asRole(t, "PATCH", url+"/api/v1/admin/hosts/"+id, auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "hosts.invalid_input") {
			t.Errorf("body lacks hosts.invalid_input: %s", b)
		}

		// Confirm IP wasn't mutated by re-reading.
		req = asRole(t, "GET", url+"/api/v1/admin/hosts/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		var got map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&got)
		resp.Body.Close()
		if got["ip_address"] != origIP {
			t.Errorf("ip_address mutated despite 400: %v vs %v", got["ip_address"], origIP)
		}
	})
}

// @ac AC-11
// AC-11: DELETE → 204; subsequent GET → 404; row still in DB with deleted_at set.
func TestHosts_Delete_SoftDelete(t *testing.T) {
	t.Run("api-hosts/AC-11", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "to-delete", "production")
		id := created["id"].(string)

		req := asRole(t, "DELETE", url+"/api/v1/admin/hosts/"+id, auth.RoleAdmin, nil)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete status = %d, want 204", resp.StatusCode)
		}

		req = asRole(t, "GET", url+"/api/v1/admin/hosts/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("post-delete get status = %d, want 404", resp.StatusCode)
		}

		// Underlying row still exists with deleted_at set.
		var deletedAt *string
		err := pool.QueryRow(context.Background(),
			`SELECT deleted_at::text FROM hosts WHERE id = $1`, id).Scan(&deletedAt)
		if err != nil {
			t.Fatalf("row missing entirely: %v", err)
		}
		if deletedAt == nil {
			t.Errorf("deleted_at is NULL despite 204; expected soft-delete")
		}
	})
}

// @ac AC-12
// AC-12: DELETE without host:delete → 403; row NOT soft-deleted.
func TestHosts_Delete_DeniedWithoutPermission(t *testing.T) {
	t.Run("api-hosts/AC-12", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "keep-me", "production")
		id := created["id"].(string)

		// ops_lead has host:read+write but NOT host:delete.
		req := asRole(t, "DELETE", url+"/api/v1/admin/hosts/"+id, auth.RoleOpsLead, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}

		// Row still has deleted_at = NULL.
		var deletedAt *string
		err := pool.QueryRow(context.Background(),
			`SELECT deleted_at::text FROM hosts WHERE id = $1`, id).Scan(&deletedAt)
		if err != nil {
			t.Fatalf("row missing: %v", err)
		}
		if deletedAt != nil {
			t.Errorf("deleted_at is %v after 403; expected NULL", *deletedAt)
		}
	})
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
