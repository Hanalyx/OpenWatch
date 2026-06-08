// @spec api-version

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// @ac AC-01
// api-version/AC-01: GET /api/v1/version with no auth returns 200 + JSON.
func TestAPI_Version_Returns200JSON(t *testing.T) {
	t.Run("api-version/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/version")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})
}

// versionBody mirrors the api.VersionResponse JSON for decoding in tests.
type versionBody struct {
	Openwatch string `json:"openwatch"`
	Kensa     string `json:"kensa"`
	Go        string `json:"go"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// @ac AC-02
// api-version/AC-02: body has non-empty openwatch, kensa, and go.
func TestAPI_Version_CoreFieldsNonEmpty(t *testing.T) {
	t.Run("api-version/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/version")
		defer resp.Body.Close()
		var got versionBody
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Kensa resolves to "unknown" in the test binary (it does not link the
		// kensa module); the contract is only that the field is non-empty.
		if got.Openwatch == "" {
			t.Error("openwatch is empty")
		}
		if got.Kensa == "" {
			t.Error("kensa is empty")
		}
		if got.Go == "" {
			t.Error("go is empty")
		}
		if !strings.HasPrefix(got.Go, "go") {
			t.Errorf("go = %q, want a 'go'-prefixed toolchain version", got.Go)
		}
	})
}

// @ac AC-03
// api-version/AC-03: body includes commit and build_time fields.
func TestAPI_Version_HasBuildFields(t *testing.T) {
	t.Run("api-version/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/version")
		defer resp.Body.Close()
		// Decode into a map to assert the keys are present in the wire JSON,
		// regardless of their (build-dependent) values.
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, k := range []string{"commit", "build_time"} {
			if _, ok := raw[k]; !ok {
				t.Errorf("response missing %q field", k)
			}
		}
	})
}

// @ac AC-04
// api-version/AC-04: response carries an X-Correlation-Id header.
func TestAPI_Version_CorrelationIdHeader(t *testing.T) {
	t.Run("api-version/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		resp := doGet(t, url+"/api/v1/version")
		defer resp.Body.Close()
		if cid := resp.Header.Get("X-Correlation-Id"); cid == "" {
			t.Error("X-Correlation-Id header missing")
		} else if !strings.HasPrefix(cid, "req-") {
			t.Errorf("X-Correlation-Id = %q, want req- prefix", cid)
		}
	})
}
