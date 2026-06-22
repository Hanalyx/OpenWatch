// @spec api-reports
//
//	AC-16  TestAPI_ReportSigningAndKeyEndpoint — generate a signed report,
//	       fetch the signing public key, verify the signature offline, and
//	       confirm the wire exposes content_sha256 + signature + key id.

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/report"
)

// @ac AC-16
func TestAPI_ReportSigningAndKeyEndpoint(t *testing.T) {
	t.Run("api-reports/AC-16", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// Generate a report (host:write) — the harness signer signs it.
		genReq := asRole(t, "POST", url+"/api/v1/reports:generate", auth.RoleOpsLead, nil)
		gr := doReq(t, genReq)
		defer gr.Body.Close()
		if gr.StatusCode != http.StatusCreated {
			t.Fatalf("generate status = %d, want 201", gr.StatusCode)
		}
		var rep struct {
			ID            string `json:"id"`
			ContentSha256 string `json:"content_sha256"`
			Signature     string `json:"signature"`
			SigningKeyID  string `json:"signing_key_id"`
		}
		if err := json.NewDecoder(gr.Body).Decode(&rep); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		if rep.ContentSha256 == "" || rep.Signature == "" || rep.SigningKeyID == "" {
			t.Fatalf("report missing signing fields: %+v", rep)
		}

		// Fetch the signing public key (host:read).
		keyReq := asRole(t, "GET", url+"/api/v1/reports/signing-key", auth.RoleViewer, nil)
		kr := doReq(t, keyReq)
		defer kr.Body.Close()
		if kr.StatusCode != http.StatusOK {
			t.Fatalf("signing-key status = %d, want 200", kr.StatusCode)
		}
		var key struct {
			KeyID     string `json:"key_id"`
			Algorithm string `json:"algorithm"`
			PublicKey string `json:"public_key"`
			Ephemeral bool   `json:"ephemeral"`
		}
		if err := json.NewDecoder(kr.Body).Decode(&key); err != nil {
			t.Fatalf("decode signing key: %v", err)
		}
		if key.Algorithm != "ed25519" || key.KeyID != rep.SigningKeyID || !key.Ephemeral {
			t.Errorf("signing key = %+v (want ed25519, key id %s, ephemeral)", key, rep.SigningKeyID)
		}

		// Offline verification: the report's signature verifies over its
		// content address with the published public key.
		pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("bad public key: err=%v len=%d", err, len(pub))
		}
		sig, err := base64.StdEncoding.DecodeString(rep.Signature)
		if err != nil {
			t.Fatalf("bad signature b64: %v", err)
		}
		if !report.VerifySignature(ed25519.PublicKey(pub), rep.ContentSha256, sig) {
			t.Errorf("report signature did not verify with the published public key")
		}

		// Anonymous is rejected on the signing-key endpoint.
		anon, _ := http.NewRequest("GET", url+"/api/v1/reports/signing-key", nil)
		ar, _ := http.DefaultClient.Do(anon)
		ar.Body.Close()
		if ar.StatusCode != http.StatusUnauthorized && ar.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous signing-key status = %d, want 401/403", ar.StatusCode)
		}
	})
}

// @ac AC-18
// GET /api/v1/reports/frameworks (host:read) returns the fleet framework
// catalog as a {frameworks:[{framework,rule_count}]} shape; anonymous is
// rejected.
func TestAPI_ReportFrameworks(t *testing.T) {
	t.Run("api-reports/AC-18", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		req := asRole(t, "GET", url+"/api/v1/reports/frameworks", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("frameworks status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Frameworks []struct {
				Framework string `json:"framework"`
				RuleCount int    `json:"rule_count"`
			} `json:"frameworks"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode frameworks: %v", err)
		}
		if body.Frameworks == nil {
			t.Errorf("frameworks is null, want an array (possibly empty)")
		}

		anon, _ := http.NewRequest("GET", url+"/api/v1/reports/frameworks", nil)
		ar, _ := http.DefaultClient.Do(anon)
		ar.Body.Close()
		if ar.StatusCode != http.StatusUnauthorized && ar.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous frameworks status = %d, want 401/403", ar.StatusCode)
		}
	})
}
