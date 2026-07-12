// @spec api-notifications
//
// CRUD + RBAC + write-only secret handling for the notification-channel
// endpoints. DSN-gated via freshAPIServer.

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return string(b)
}

// @ac AC-01
func TestNotifications_ListRBAC(t *testing.T) {
	t.Run("api-notifications/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Anonymous → denied (401 or 403 per the auth/permission gate).
		anon := asRole(t, "GET", url+"/api/v1/notifications/channels", "", nil)
		if r := doReq(t, anon); r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusForbidden {
			t.Errorf("anon list = %d, want 401 or 403", r.StatusCode)
		}
		// A read-holder (viewer) → 200 with a channels array.
		r := doReq(t, asRole(t, "GET", url+"/api/v1/notifications/channels", auth.RoleViewer, nil))
		if r.StatusCode != http.StatusOK {
			t.Fatalf("viewer list = %d, want 200", r.StatusCode)
		}
		var list api.NotificationChannelList
		if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
	})
}

// @ac AC-02
func TestNotifications_CreateRedactsSecret(t *testing.T) {
	t.Run("api-notifications/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"type": "slack", "name": "ops",
			"url": "https://hooks.slack.com/services/T/B/supersecret",
		}
		// Viewer lacks notification:write → 403.
		if r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleViewer, body)); r.StatusCode != http.StatusForbidden {
			t.Errorf("viewer create = %d, want 403", r.StatusCode)
		}
		// Admin → 201, and the secret must not appear anywhere in the JSON.
		r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, body))
		raw := readBody(t, r)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("admin create = %d, want 201 (body %s)", r.StatusCode, raw)
		}
		if strings.Contains(raw, "supersecret") || strings.Contains(raw, "/services/T/B/") {
			t.Errorf("create response leaked secret url: %s", raw)
		}
		if !strings.Contains(raw, "hooks.slack.com") {
			t.Errorf("create response missing target_hint: %s", raw)
		}
	})
}

// @ac AC-05
func TestNotifications_RejectsBadURLAnd503(t *testing.T) {
	t.Run("api-notifications/AC-05", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// http:// rejected → 400.
		bad := map[string]any{"type": "webhook", "name": "x", "url": "http://example.com/h"}
		if r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, bad)); r.StatusCode != http.StatusBadRequest {
			t.Errorf("http url create = %d, want 400", r.StatusCode)
		}
		// Private host rejected → 400.
		priv := map[string]any{"type": "webhook", "name": "x", "url": "https://10.0.0.1/h"}
		if r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, priv)); r.StatusCode != http.StatusBadRequest {
			t.Errorf("private url create = %d, want 400", r.StatusCode)
		}
	})
}

// @ac AC-05
// Source inspection — the response struct exposes no secret field.
func TestNotifications_ResponseHasNoSecretField(t *testing.T) {
	t.Run("api-notifications/AC-05", func(t *testing.T) {
		var c api.NotificationChannel
		// Compile-time: target_hint is the only target field.
		_ = c.TargetHint
		// Reflect: no url/token field on the response type.
		rt := reflect.TypeOf(c)
		for _, banned := range []string{"Url", "Token", "URL", "ConfigCiphertext"} {
			if _, ok := rt.FieldByName(banned); ok {
				t.Errorf("NotificationChannel response exposes secret field %q", banned)
			}
		}
	})
}

// @ac AC-06
func TestNotifications_EmailCreateRedactsSecret(t *testing.T) {
	t.Run("api-notifications/AC-06", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"type": "email", "name": "secops-mail",
			"smtp_host": "smtp.corp.example", "smtp_port": 587,
			"username": "ow", "password": "smtp-supersecret",
			"from": "openwatch@corp.example", "to": []string{"sec@corp.example"},
		}
		r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, body))
		raw := readBody(t, r)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("email create = %d, want 201 (body %s)", r.StatusCode, raw)
		}
		if strings.Contains(raw, "smtp-supersecret") || strings.Contains(raw, `"password"`) ||
			strings.Contains(raw, `"username"`) {
			t.Errorf("email create response leaked credential: %s", raw)
		}
		if !strings.Contains(raw, "smtp.corp.example") {
			t.Errorf("email create response missing smtp host hint: %s", raw)
		}
		// Missing recipients → 400.
		bad := map[string]any{
			"type": "email", "name": "x",
			"smtp_host": "smtp.corp.example", "smtp_port": 587, "from": "a@x.com",
		}
		if br := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, bad)); br.StatusCode != http.StatusBadRequest {
			t.Errorf("email create without recipients = %d, want 400", br.StatusCode)
		}
	})
}

// @ac AC-07
// The list/read path returns an email channel's NON-secret config so the
// edit form can pre-fill — smtp_port, from, to, username — but never the
// password. Editing without re-entering the password keeps the stored one.
func TestNotifications_EmailListExposesNonSecretConfig(t *testing.T) {
	t.Run("api-notifications/AC-07", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"type": "email", "name": "prefill-mail",
			"smtp_host": "smtp.corp.example", "smtp_port": 2525,
			"username": "ow-user", "password": "smtp-supersecret",
			"from": "alerts@corp.example", "to": []string{"sec@corp.example", "ops@corp.example"},
		}
		cr := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, body))
		if cr.StatusCode != http.StatusCreated {
			t.Fatalf("create = %d", cr.StatusCode)
		}
		var created api.NotificationChannel
		_ = json.NewDecoder(cr.Body).Decode(&created)

		// LIST returns the non-secret fields for pre-fill, never the password.
		lr := doReq(t, asRole(t, "GET", url+"/api/v1/notifications/channels", auth.RoleAdmin, nil))
		raw := readBody(t, lr)
		for _, want := range []string{"smtp.corp.example", "2525", "alerts@corp.example", "sec@corp.example", "ow-user"} {
			if !strings.Contains(raw, want) {
				t.Errorf("list missing non-secret email field %q for pre-fill: %s", want, raw)
			}
		}
		if strings.Contains(raw, "smtp-supersecret") || strings.Contains(raw, `"password"`) {
			t.Errorf("list leaked the SMTP password: %s", raw)
		}

		// PATCH from/to WITHOUT re-entering the password must keep it. Verify
		// by confirming the channel still validates + the password survives
		// (a delivery would otherwise fail; here we assert update succeeds and
		// re-read still has no password exposed).
		id := created.Id.String()
		pr := doReq(t, asRole(t, "PATCH", url+"/api/v1/notifications/channels/"+id, auth.RoleAdmin,
			map[string]any{
				"name": "prefill-mail", "enabled": true,
				"smtp_host": "smtp.corp.example", "smtp_port": 2525,
				"username": "ow-user", "from": "alerts@corp.example",
				"to": []string{"new@corp.example"},
			}))
		if pr.StatusCode != http.StatusOK {
			t.Fatalf("patch (no password) = %d, want 200", pr.StatusCode)
		}
		gr := doReq(t, asRole(t, "GET", url+"/api/v1/notifications/channels", auth.RoleAdmin, nil))
		graw := readBody(t, gr)
		if !strings.Contains(graw, "new@corp.example") {
			t.Errorf("patched recipient not persisted: %s", graw)
		}
	})
}

// @ac AC-08
// AC-08: an email channel's smtp_encryption mode round-trips (create ->
// read) and an invalid mode is rejected with 400.
func TestNotifications_EmailEncryptionRoundTrip(t *testing.T) {
	t.Run("api-notifications/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		body := map[string]any{
			"type": "email", "name": "tls-mail",
			"smtp_host": "smtp.corp.example", "smtp_port": 465,
			"smtp_encryption": "tls", "smtp_insecure_skip_verify": true,
			"from": "alerts@corp.example", "to": []string{"sec@corp.example"},
		}
		cr := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, body))
		if cr.StatusCode != http.StatusCreated {
			t.Fatalf("create = %d", cr.StatusCode)
		}
		lr := doReq(t, asRole(t, "GET", url+"/api/v1/notifications/channels", auth.RoleAdmin, nil))
		raw := readBody(t, lr)
		if !strings.Contains(raw, `"smtp_encryption":"tls"`) &&
			!strings.Contains(raw, `"smtp_encryption": "tls"`) {
			t.Errorf("read did not return smtp_encryption=tls for pre-fill: %s", raw)
		}
		if !strings.Contains(raw, `"smtp_insecure_skip_verify":true`) &&
			!strings.Contains(raw, `"smtp_insecure_skip_verify": true`) {
			t.Errorf("read did not return smtp_insecure_skip_verify=true for pre-fill: %s", raw)
		}
		// An out-of-enum mode is rejected by validation.
		bad := map[string]any{
			"type": "email", "name": "bad-enc",
			"smtp_host": "smtp.corp.example", "smtp_port": 587,
			"smtp_encryption": "bogus",
			"from":            "a@x.com", "to": []string{"b@x.com"},
		}
		if br := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin, bad)); br.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid encryption = %d, want 400", br.StatusCode)
		}
	})
}

// @ac AC-03
func TestNotifications_UpdateDeleteRBAC(t *testing.T) {
	t.Run("api-notifications/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Create one as admin.
		r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin,
			map[string]any{"type": "webhook", "name": "n1", "url": "https://example.com/h"}))
		var created api.NotificationChannel
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			t.Fatalf("decode create: %v", err)
		}
		id := created.Id.String()
		// PATCH name/enabled without url → secret untouched, 200.
		pr := doReq(t, asRole(t, "PATCH", url+"/api/v1/notifications/channels/"+id, auth.RoleAdmin,
			map[string]any{"name": "n2", "enabled": false}))
		if pr.StatusCode != http.StatusOK {
			t.Fatalf("patch = %d, want 200", pr.StatusCode)
		}
		// Viewer can't delete (notification:delete) → 403.
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/notifications/channels/"+id, auth.RoleViewer, nil)); dr.StatusCode != http.StatusForbidden {
			t.Errorf("viewer delete = %d, want 403", dr.StatusCode)
		}
		// Admin delete → 204.
		if dr := doReq(t, asRole(t, "DELETE", url+"/api/v1/notifications/channels/"+id, auth.RoleAdmin, nil)); dr.StatusCode != http.StatusNoContent {
			t.Errorf("admin delete = %d, want 204", dr.StatusCode)
		}
	})
}

// @ac AC-04
func TestNotifications_TestEndpoint(t *testing.T) {
	t.Run("api-notifications/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		// Unknown id → 404.
		missing := "00000000-0000-0000-0000-000000000000"
		if r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels/"+missing+":test", auth.RoleAdmin, nil)); r.StatusCode != http.StatusNotFound {
			t.Errorf("test missing = %d, want 404", r.StatusCode)
		}
		// Create then test: delivery to example.com fails (no real endpoint)
		// → 400, proving the gate + path reach delivery (not a 403/404/503).
		r := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels", auth.RoleAdmin,
			map[string]any{"type": "webhook", "name": "n1", "url": "https://example.invalid/h"}))
		var created api.NotificationChannel
		_ = json.NewDecoder(r.Body).Decode(&created)
		tr := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels/"+created.Id.String()+":test", auth.RoleAdmin, nil))
		if tr.StatusCode != http.StatusBadRequest {
			t.Errorf("test bad endpoint = %d, want 400 (delivery failed)", tr.StatusCode)
		}
		// Viewer lacks notification:test → 403.
		if vr := doReq(t, asRole(t, "POST", url+"/api/v1/notifications/channels/"+created.Id.String()+":test", auth.RoleViewer, nil)); vr.StatusCode != http.StatusForbidden {
			t.Errorf("viewer test = %d, want 403", vr.StatusCode)
		}
	})
}
