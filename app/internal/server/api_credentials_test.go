// @spec api-credentials
//
// Credential CRUD + host resolver HTTP integration tests. Skipped
// without OPENWATCH_TEST_DSN.

package server

import (
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
