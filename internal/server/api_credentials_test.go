// @spec api-credentials
//
// Credential CRUD + host resolver HTTP integration tests. Skipped
// without OPENWATCH_TEST_DSN.

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// weakRSAPEM returns a 1024-bit RSA key — below the NIST minimum
// (2048). ValidateAuthKey rejects it; AC-05 uses this to verify the
// handler rejects the create with 400. The key is never stored or
// used to dial; it only exercises the strength-rejection path.
//
//nolint:gosec // 1024-bit RSA is intentional for the rejection test.
func weakRSAPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
}

// seedAPIHost inserts a host row directly and returns its id. The
// admin POST /hosts route lives in spec 9; tests here need a
// concrete host id without coupling to it, so we go straight to SQL.
// Uses the freshAPIServer fixture's stub admin user as created_by.
func seedAPIHost(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	hid, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		hid, "ac-host-"+hid.String()[:8], "192.0.2.20", roleUserIDs[auth.RoleAdmin])
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return hid
}

// @ac AC-01
// AC-01: POST /credentials returns 201 + metadata; body lacks any
// secret-bearing keys.
func TestCredentials_Create_Success(t *testing.T) {
	t.Run("api-credentials/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"scope":       "system",
			"name":        "ac01-cred",
			"username":    "admin",
			"auth_method": "password",
			"password":    "supersecret-pw-12345",
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		raw, _ := io.ReadAll(resp.Body)
		// Body must NEVER carry a secret-bearing key. Match the JSON
		// key + colon pattern (".X":) so we don't false-positive on the
		// auth_method value "password".
		for _, leaky := range []string{
			`"password":`, `"private_key":`, `"private_key_passphrase":`,
			`"encrypted_password":`, `"encrypted_private_key":`,
		} {
			if strings.Contains(string(raw), leaky) {
				t.Errorf("response leaks %s: %s", leaky, raw)
			}
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["name"] != "ac01-cred" || got["username"] != "admin" {
			t.Errorf("unexpected body: %s", raw)
		}
		if got["auth_method"] != "password" || got["scope"] != "system" {
			t.Errorf("metadata mismatch: %s", raw)
		}
	})
}

// @ac AC-02
// AC-02: caller without credential:write → 403; no row inserted.
func TestCredentials_Create_DeniedWithoutPermission(t *testing.T) {
	t.Run("api-credentials/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := map[string]any{
			"scope": "system", "name": "denied", "username": "u",
			"auth_method": "password", "password": "x",
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleViewer, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM credentials WHERE name = $1`, "denied").Scan(&count)
		if count != 0 {
			t.Errorf("count = %d, want 0", count)
		}
	})
}

// @ac AC-03
// AC-03: scope=host but scope_id omitted → 400 credentials.invalid_scope.
func TestCredentials_Create_HostScopeMissingScopeID(t *testing.T) {
	t.Run("api-credentials/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"scope": "host", "name": "bad", "username": "u",
			"auth_method": "password", "password": "x",
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "credentials.invalid_scope") {
			t.Errorf("body lacks credentials.invalid_scope: %s", b)
		}
	})
}

// @ac AC-04
// AC-04: scope=host with non-existent scope_id → 400 credentials.host_not_found.
func TestCredentials_Create_HostNotFound(t *testing.T) {
	t.Run("api-credentials/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"scope": "host", "scope_id": uuid.New().String(),
			"name": "ghost", "username": "u",
			"auth_method": "password", "password": "x",
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "credentials.host_not_found") {
			t.Errorf("body lacks credentials.host_not_found: %s", b)
		}
	})
}

// @ac AC-05
// AC-05: auth_method=ssh_key with an unparseable / weak key → 400.
func TestCredentials_Create_InvalidKeyRejected(t *testing.T) {
	t.Run("api-credentials/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Unparseable key.
		body := map[string]any{
			"scope": "system", "name": "bad-key", "username": "u",
			"auth_method": "ssh_key",
			"private_key": "not a pem block",
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unparseable status = %d body=%s", resp.StatusCode, b)
		}
		if !strings.Contains(string(b), "credentials.invalid_key") {
			t.Errorf("unparseable body lacks credentials.invalid_key: %s", b)
		}

		// Below-minimum RSA (1024 bits — below NIST 2048 floor).
		body["name"] = "weak-rsa"
		body["private_key"] = weakRSAPEM(t)
		req = asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp = doReq(t, req)
		b, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("weak-rsa status = %d body=%s", resp.StatusCode, b)
		}
	})
}

// @ac AC-06
// AC-06: second is_default=true system credential → 409.
func TestCredentials_Create_MultipleSystemDefaults(t *testing.T) {
	t.Run("api-credentials/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"scope": "system", "name": "first-default", "username": "u",
			"auth_method": "password", "password": "x", "is_default": true,
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("first default status = %d, want 201", resp.StatusCode)
		}

		body["name"] = "second-default"
		req = asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("second default status = %d body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "credentials.multiple_system_defaults") {
			t.Errorf("body lacks credentials.multiple_system_defaults: %s", b)
		}
	})
}

// @ac AC-07
// AC-07: GET /credentials returns metadata-only list — no secrets.
func TestCredentials_List_NoSecrets(t *testing.T) {
	t.Run("api-credentials/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Seed one of each.
		for _, name := range []string{"a", "b"} {
			body := map[string]any{
				"scope": "system", "name": "list-" + name, "username": "u",
				"auth_method": "password", "password": "topsecret-" + name,
			}
			req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
			resp := doReq(t, req)
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("seed %s status = %d", name, resp.StatusCode)
			}
		}

		req := asRole(t, "GET", url+"/api/v1/credentials", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d body=%s", resp.StatusCode, raw)
		}
		// No secret-bearing key may appear anywhere in the body.
		// Substrings: plaintext we passed in, plus the JSON-key form
		// `"X":` for the secret fields (".X":).
		for _, leaky := range []string{
			"topsecret-a", "topsecret-b",
			`"password":`, `"private_key":`, `"encrypted_password":`,
		} {
			if strings.Contains(string(raw), leaky) {
				t.Errorf("list leaks %s: %s", leaky, raw)
			}
		}
		var body struct {
			Credentials []map[string]any `json:"credentials"`
		}
		_ = json.Unmarshal(raw, &body)
		if len(body.Credentials) != 2 {
			t.Errorf("credentials len = %d, want 2", len(body.Credentials))
		}

		// Caller without credential:read → 403.
		req = asRole(t, "GET", url+"/api/v1/credentials", auth.RoleViewer, nil)
		resp2 := doReq(t, req)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusForbidden {
			t.Errorf("viewer status = %d, want 403", resp2.StatusCode)
		}
	})
}

// @ac AC-08
// AC-08: GET /credentials/{id} returns metadata; unknown id → 404.
func TestCredentials_GetByID(t *testing.T) {
	t.Run("api-credentials/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"scope": "system", "name": "by-id", "username": "u",
			"auth_method": "password", "password": "x",
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		var created map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()
		id := created["id"].(string)

		req = asRole(t, "GET", url+"/api/v1/credentials/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("get status = %d body=%s", resp.StatusCode, raw)
		}
		if strings.Contains(string(raw), `"password":`) ||
			strings.Contains(string(raw), `"private_key":`) {
			t.Errorf("get leaks secret keys: %s", raw)
		}

		// Unknown id → 404.
		req = asRole(t, "GET", url+"/api/v1/credentials/"+uuid.New().String(), auth.RoleAdmin, nil)
		resp = doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unknown status = %d, want 404", resp.StatusCode)
		}
	})
}

// @ac AC-09
// AC-09: DELETE → 204; subsequent GET → 404; row NOT removed.
func TestCredentials_Delete_SoftDelete(t *testing.T) {
	t.Run("api-credentials/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		body := map[string]any{
			"scope": "system", "name": "to-delete", "username": "u",
			"auth_method": "password", "password": "x",
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		var created map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()
		id := created["id"].(string)

		req = asRole(t, "DELETE", url+"/api/v1/credentials/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete status = %d, want 204", resp.StatusCode)
		}

		// Get returns 404.
		req = asRole(t, "GET", url+"/api/v1/credentials/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("post-delete get status = %d, want 404", resp.StatusCode)
		}

		// Row is still in DB (is_active=false), confirming soft delete.
		var active bool
		err := pool.QueryRow(context.Background(),
			`SELECT is_active FROM credentials WHERE id = $1`, id).Scan(&active)
		if err != nil {
			t.Fatalf("row missing: %v", err)
		}
		if active {
			t.Errorf("is_active = true after soft delete; expected false")
		}
	})
}

// @ac AC-10
// AC-10: POST /hosts/{host_id}/credentials:resolve returns the
// host-scope credential when one exists.
func TestCredentials_Resolve_HostScopeWins(t *testing.T) {
	t.Run("api-credentials/AC-10", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		// Seed a creator user and a host directly to avoid coupling to
		// the host admin API (spec 9).
		hostID := seedAPIHost(t, pool)

		// System default.
		body := map[string]any{
			"scope": "system", "name": "sys-default", "username": "sysuser",
			"auth_method": "password", "password": "x", "is_default": true,
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("seed sys: %d", resp.StatusCode)
		}

		// Host-scope override.
		body = map[string]any{
			"scope": "host", "scope_id": hostID.String(),
			"name": "host-override", "username": "hostuser",
			"auth_method": "password", "password": "x",
		}
		req = asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("seed host: %d", resp.StatusCode)
		}

		req = asRole(t, "POST",
			url+"/api/v1/hosts/"+hostID.String()+"/credentials:resolve",
			auth.RoleAdmin, nil)
		resp = doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("resolve status = %d body=%s", resp.StatusCode, raw)
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["username"] != "hostuser" || got["scope"] != "host" {
			t.Errorf("resolve picked %v, want host/hostuser", got)
		}
	})
}

// @ac AC-11
// AC-11: Resolve returns the system default when no host-scope row exists.
func TestCredentials_Resolve_FallsBackToSystem(t *testing.T) {
	t.Run("api-credentials/AC-11", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedAPIHost(t, pool)

		body := map[string]any{
			"scope": "system", "name": "only-system", "username": "sysuser",
			"auth_method": "password", "password": "x", "is_default": true,
		}
		req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("seed sys: %d", resp.StatusCode)
		}

		req = asRole(t, "POST",
			url+"/api/v1/hosts/"+hostID.String()+"/credentials:resolve",
			auth.RoleAdmin, nil)
		resp = doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("resolve status = %d body=%s", resp.StatusCode, raw)
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["scope"] != "system" || got["username"] != "sysuser" {
			t.Errorf("resolve picked %v, want system/sysuser", got)
		}
	})
}

// @ac AC-13
// AC-13: Clone a system credential into a host scope; new row inherits
// the source's auth_method + key metadata + username but lives at the
// new (scope=host, scope_id) coordinates.
func TestCredentials_Clone_SystemToHost(t *testing.T) {
	t.Run("api-credentials/AC-13", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// Source: system credential.
		srcReq := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, map[string]any{
			"scope":       "system",
			"name":        "ac13-src",
			"username":    "operator",
			"auth_method": "password",
			"password":    "src-pw-from-template",
		})
		srcResp := doReq(t, srcReq)
		if srcResp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(srcResp.Body)
			srcResp.Body.Close()
			t.Fatalf("seed source: status=%d body=%s", srcResp.StatusCode, b)
		}
		var src map[string]any
		_ = json.NewDecoder(srcResp.Body).Decode(&src)
		srcResp.Body.Close()
		srcID, _ := src["id"].(string)

		// Target host for the clone.
		hostID := seedAPIHost(t, pool)

		cloneReq := asRole(t, "POST",
			url+"/api/v1/credentials/"+srcID+":clone", auth.RoleAdmin, map[string]any{
				"scope":    "host",
				"scope_id": hostID.String(),
				"name":     "ac13-clone",
			})
		cloneResp := doReq(t, cloneReq)
		defer cloneResp.Body.Close()
		if cloneResp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(cloneResp.Body)
			t.Fatalf("clone status=%d body=%s", cloneResp.StatusCode, b)
		}
		raw, _ := io.ReadAll(cloneResp.Body)
		// Response must NEVER leak secret material.
		for _, leaky := range []string{
			`"password":`, `"private_key":`, `"private_key_passphrase":`,
			`"encrypted_password":`, `"encrypted_private_key":`,
		} {
			if strings.Contains(string(raw), leaky) {
				t.Errorf("clone response leaks %s: %s", leaky, raw)
			}
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["scope"] != "host" {
			t.Errorf("scope = %v, want host", got["scope"])
		}
		if got["scope_id"] != hostID.String() {
			t.Errorf("scope_id = %v, want %s", got["scope_id"], hostID.String())
		}
		// Source identity inherited: username + auth_method match.
		if got["username"] != "operator" {
			t.Errorf("username = %v, want operator (inherited from source)", got["username"])
		}
		if got["auth_method"] != "password" {
			t.Errorf("auth_method = %v, want password", got["auth_method"])
		}
		if got["id"] == srcID {
			t.Errorf("clone reused source id %s; expected fresh id", srcID)
		}
		if got["name"] != "ac13-clone" {
			t.Errorf("name = %v, want ac13-clone", got["name"])
		}
	})
}

// @ac AC-14
// AC-14: Clone with unknown source id returns 404 credentials.not_found.
func TestCredentials_Clone_UnknownSource(t *testing.T) {
	t.Run("api-credentials/AC-14", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedAPIHost(t, pool)
		bogus, _ := uuid.NewV7()

		req := asRole(t, "POST",
			url+"/api/v1/credentials/"+bogus.String()+":clone", auth.RoleAdmin, map[string]any{
				"scope":    "host",
				"scope_id": hostID.String(),
			})
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "credentials.not_found") {
			t.Errorf("body lacks credentials.not_found: %s", b)
		}
	})
}

// @ac AC-15
// AC-15: Clone with scope=host but a non-existent scope_id returns
// 400 credentials.host_not_found.
func TestCredentials_Clone_HostNotFound(t *testing.T) {
	t.Run("api-credentials/AC-15", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Real source.
		srcReq := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, map[string]any{
			"scope":       "system",
			"name":        "ac15-src",
			"username":    "operator",
			"auth_method": "password",
			"password":    "src-pw",
		})
		srcResp := doReq(t, srcReq)
		if srcResp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(srcResp.Body)
			srcResp.Body.Close()
			t.Fatalf("seed source: status=%d body=%s", srcResp.StatusCode, b)
		}
		var src map[string]any
		_ = json.NewDecoder(srcResp.Body).Decode(&src)
		srcResp.Body.Close()
		srcID, _ := src["id"].(string)

		ghost, _ := uuid.NewV7()
		req := asRole(t, "POST",
			url+"/api/v1/credentials/"+srcID+":clone", auth.RoleAdmin, map[string]any{
				"scope":    "host",
				"scope_id": ghost.String(),
			})
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "credentials.host_not_found") {
			t.Errorf("body lacks credentials.host_not_found: %s", b)
		}
	})
}

// @ac AC-12
// AC-12: Resolve returns 404 credentials.none_available when neither
// host-scope nor system-default is present.
func TestCredentials_Resolve_NoneAvailable(t *testing.T) {
	t.Run("api-credentials/AC-12", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedAPIHost(t, pool)

		req := asRole(t, "POST",
			url+"/api/v1/hosts/"+hostID.String()+"/credentials:resolve",
			auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "credentials.none_available") {
			t.Errorf("body lacks credentials.none_available: %s", b)
		}
	})
}

// seedAPICredential creates a credential via the admin POST route and
// returns its id. Used by the PATCH tests to get a concrete row to
// update without reaching into SQL.
func seedAPICredential(t *testing.T, url string, body map[string]any) string {
	t.Helper()
	req := asRole(t, "POST", url+"/api/v1/credentials", auth.RoleAdmin, body)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("seed credential: status=%d body=%s", resp.StatusCode, b)
	}
	var created map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&created)
	return created["id"].(string)
}

// encPassword reads the raw encrypted_password ciphertext for a
// credential id. The PATCH tests use it to prove the stored secret is
// untouched when only metadata changes (and after a rejected update).
func encPassword(t *testing.T, pool *pgxpool.Pool, id string) []byte {
	t.Helper()
	var enc []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT encrypted_password FROM credentials WHERE id = $1`, id).Scan(&enc); err != nil {
		t.Fatalf("read encrypted_password: %v", err)
	}
	return enc
}

// @ac AC-16
// AC-16: PATCH changing only metadata returns 200 with updated
// metadata; no secret leaks; the stored ciphertext is untouched.
func TestCredentials_Patch_MetadataOnly(t *testing.T) {
	t.Run("api-credentials/AC-16", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		id := seedAPICredential(t, url, map[string]any{
			"scope": "system", "name": "ac16-before", "username": "u-before",
			"auth_method": "password", "password": "keep-this-secret-12345",
		})
		encBefore := encPassword(t, pool, id)

		req := asRole(t, "PATCH", url+"/api/v1/credentials/"+id, auth.RoleAdmin,
			map[string]any{"name": "ac16-after", "description": "edited", "username": "u-after"})
		resp := doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d body=%s", resp.StatusCode, raw)
		}
		for _, leaky := range []string{
			`"password":`, `"private_key":`, `"private_key_passphrase":`,
			`"encrypted_password":`, `"encrypted_private_key":`,
		} {
			if strings.Contains(string(raw), leaky) {
				t.Errorf("response leaks %s: %s", leaky, raw)
			}
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["name"] != "ac16-after" || got["username"] != "u-after" {
			t.Errorf("metadata not updated: %s", raw)
		}
		// Ciphertext must be byte-identical: no re-entry, no re-encrypt.
		encAfter := encPassword(t, pool, id)
		if !bytes.Equal(encBefore, encAfter) {
			t.Errorf("stored ciphertext changed on a metadata-only PATCH")
		}
	})
}

// @ac AC-17
// AC-17: PATCH without credential:write → 403; credential unchanged.
func TestCredentials_Patch_DeniedWithoutPermission(t *testing.T) {
	t.Run("api-credentials/AC-17", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		id := seedAPICredential(t, url, map[string]any{
			"scope": "system", "name": "ac17-keep", "username": "u",
			"auth_method": "password", "password": "x",
		})

		req := asRole(t, "PATCH", url+"/api/v1/credentials/"+id, auth.RoleViewer,
			map[string]any{"name": "ac17-hacked"})
		resp := doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}

		req = asRole(t, "GET", url+"/api/v1/credentials/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["name"] != "ac17-keep" {
			t.Errorf("name = %v after denied PATCH, want unchanged", got["name"])
		}
	})
}

// @ac AC-18
// AC-18: PATCH on an unknown id → 404; PATCH on a soft-deleted
// credential → 404 (no revive).
func TestCredentials_Patch_NotFound(t *testing.T) {
	t.Run("api-credentials/AC-18", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Unknown id.
		req := asRole(t, "PATCH", url+"/api/v1/credentials/"+uuid.Must(uuid.NewV7()).String(),
			auth.RoleAdmin, map[string]any{"name": "nope"})
		resp := doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown id status = %d body=%s, want 404", resp.StatusCode, raw)
		}
		if !strings.Contains(string(raw), "credentials.not_found") {
			t.Errorf("body lacks credentials.not_found: %s", raw)
		}

		// Soft-deleted credential cannot be revived through PATCH.
		id := seedAPICredential(t, url, map[string]any{
			"scope": "system", "name": "ac18-del", "username": "u",
			"auth_method": "password", "password": "x",
		})
		req = asRole(t, "DELETE", url+"/api/v1/credentials/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		resp.Body.Close()
		req = asRole(t, "PATCH", url+"/api/v1/credentials/"+id, auth.RoleAdmin,
			map[string]any{"name": "ac18-revived"})
		resp = doReq(t, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("soft-deleted PATCH status = %d, want 404", resp.StatusCode)
		}
	})
}

// @ac AC-19
// AC-19: PATCH that leaves the effective auth_method without its
// required secret → 400 credentials.missing_secret; unchanged.
func TestCredentials_Patch_MissingSecret(t *testing.T) {
	t.Run("api-credentials/AC-19", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Password-only credential; switching to ssh_key with no key
		// stored and none supplied leaves the method secret-less.
		id := seedAPICredential(t, url, map[string]any{
			"scope": "system", "name": "ac19", "username": "u",
			"auth_method": "password", "password": "x",
		})

		req := asRole(t, "PATCH", url+"/api/v1/credentials/"+id, auth.RoleAdmin,
			map[string]any{"auth_method": "ssh_key"})
		resp := doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d body=%s, want 400", resp.StatusCode, raw)
		}
		if !strings.Contains(string(raw), "credentials.missing_secret") {
			t.Errorf("body lacks credentials.missing_secret: %s", raw)
		}

		// auth_method unchanged.
		req = asRole(t, "GET", url+"/api/v1/credentials/"+id, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		raw, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["auth_method"] != "password" {
			t.Errorf("auth_method = %v after rejected PATCH, want password", got["auth_method"])
		}
	})
}

// @ac AC-20
// AC-20: PATCH is_default=true on a system credential atomically
// demotes the prior system default.
func TestCredentials_Patch_DefaultAutoDemote(t *testing.T) {
	t.Run("api-credentials/AC-20", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		oldDefault := seedAPICredential(t, url, map[string]any{
			"scope": "system", "name": "ac20-old-default", "username": "u",
			"auth_method": "password", "password": "x", "is_default": true,
		})
		// A second system credential, not default (allowed — the unique
		// index only constrains is_default=true rows).
		newDefault := seedAPICredential(t, url, map[string]any{
			"scope": "system", "name": "ac20-new-default", "username": "u",
			"auth_method": "password", "password": "x",
		})

		req := asRole(t, "PATCH", url+"/api/v1/credentials/"+newDefault, auth.RoleAdmin,
			map[string]any{"is_default": true})
		resp := doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, raw)
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["is_default"] != true {
			t.Errorf("patched credential is_default = %v, want true", got["is_default"])
		}

		// The prior default was demoted.
		req = asRole(t, "GET", url+"/api/v1/credentials/"+oldDefault, auth.RoleAdmin, nil)
		resp = doReq(t, req)
		raw, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		var old map[string]any
		_ = json.Unmarshal(raw, &old)
		if old["is_default"] != false {
			t.Errorf("prior default is_default = %v, want false (auto-demoted)", old["is_default"])
		}
	})
}

// @ac AC-21
// AC-21: PATCH supplying an unparseable/weak private_key → 400
// credentials.invalid_key; stored ciphertext untouched.
func TestCredentials_Patch_InvalidKeyRejected(t *testing.T) {
	t.Run("api-credentials/AC-21", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		id := seedAPICredential(t, url, map[string]any{
			"scope": "system", "name": "ac21", "username": "u",
			"auth_method": "password", "password": "keep-me-67890",
		})
		encBefore := encPassword(t, pool, id)

		req := asRole(t, "PATCH", url+"/api/v1/credentials/"+id, auth.RoleAdmin,
			map[string]any{"auth_method": "both", "private_key": weakRSAPEM(t)})
		resp := doReq(t, req)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d body=%s, want 400", resp.StatusCode, raw)
		}
		if !strings.Contains(string(raw), "credentials.invalid_key") {
			t.Errorf("body lacks credentials.invalid_key: %s", raw)
		}
		encAfter := encPassword(t, pool, id)
		if !bytes.Equal(encBefore, encAfter) {
			t.Errorf("stored ciphertext changed despite a rejected PATCH")
		}
	})
}
