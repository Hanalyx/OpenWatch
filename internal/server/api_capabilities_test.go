// @spec api-capabilities
//
//	AC-01  TestCapabilities_MirrorsTheRegistry
//	AC-02  TestCapabilities_AvailabilityFollowsEntitlement
//	AC-03  TestCapabilities_DisclosesNoIdentityOrKeyMaterial
//	AC-04  TestCapabilities_StableOrder
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"testing"

	"github.com/Hanalyx/openwatch/internal/license"
)

type capsBody struct {
	Tier         string `json:"tier"`
	Status       string `json:"status"`
	Capabilities []struct {
		ID          string `json:"id"`
		Tier        string `json:"tier"`
		Available   bool   `json:"available"`
		Description string `json:"description"`
	} `json:"capabilities"`
}

func getCaps(t *testing.T, url string) (capsBody, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/api/v1/capabilities", nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var raw map[string]any
	var typed capsBody
	b, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		t.Fatalf("read body: %v", rerr)
	}
	if err := json.Unmarshal(b, &typed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	_ = json.Unmarshal(b, &raw)
	return typed, raw
}

// @ac AC-01
// AC-01: the response mirrors the registry exactly. A capability cannot be
// reported without being registered, and none may be silently omitted.
func TestCapabilities_MirrorsTheRegistry(t *testing.T) {
	t.Run("api-capabilities/AC-01", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		got, _ := getCaps(t, url)
		if len(got.Capabilities) != len(license.FeatureRegistry) {
			t.Fatalf("returned %d capabilities, registry has %d",
				len(got.Capabilities), len(license.FeatureRegistry))
		}
		seen := map[string]bool{}
		for _, c := range got.Capabilities {
			seen[c.ID] = true
			if c.Description == "" {
				t.Errorf("%s has no description; the UI has nothing to show", c.ID)
			}
		}
		for id := range license.FeatureRegistry {
			if !seen[string(id)] {
				t.Errorf("registry capability %q missing from the response", id)
			}
		}
	})
}

// @ac AC-02
// AC-02: availability is the runtime entitlement, not a static label.
func TestCapabilities_AvailabilityFollowsEntitlement(t *testing.T) {
	t.Run("api-capabilities/AC-02", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		got, _ := getCaps(t, url)
		for _, c := range got.Capabilities {
			want := c.Tier == "free"
			if c.Available != want {
				t.Errorf("unlicensed: %s (tier %s) available=%v, want %v",
					c.ID, c.Tier, c.Available, want)
			}
		}

		// Granting one paid capability flips exactly that one.
		restore := license.EnableFeatureForTesting(license.ComplianceAttestation)
		defer restore()
		got2, _ := getCaps(t, url)
		for _, c := range got2.Capabilities {
			want := c.Tier == "free" || c.ID == string(license.ComplianceAttestation)
			if c.Available != want {
				t.Errorf("licensed: %s available=%v, want %v", c.ID, c.Available, want)
			}
		}
	})
}

// @ac AC-03
// AC-03 (NEGATIVE PATH): the endpoint is anonymous, so it must disclose
// nothing about WHO holds the license. Assert on the raw JSON rather than the
// typed struct: a typed decode would silently ignore an extra field, which is
// exactly the leak this guards against.
func TestCapabilities_DisclosesNoIdentityOrKeyMaterial(t *testing.T) {
	t.Run("api-capabilities/AC-03", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		_, raw := getCaps(t, url)

		for _, forbidden := range []string{
			"customer_id", "customerId", "fingerprint",
			"expires_at", "issued_at", "issuer", "audience",
			"license_jwt", "public_key", "signature",
		} {
			if _, present := raw[forbidden]; present {
				t.Errorf("anonymous capabilities response leaks %q", forbidden)
			}
		}
		caps, _ := raw["capabilities"].([]any)
		for _, c := range caps {
			m, _ := c.(map[string]any)
			for k := range m {
				switch k {
				case "id", "tier", "available", "description":
				default:
					t.Errorf("unexpected per-capability field %q; keep this response minimal", k)
				}
			}
		}
	})
}

// @ac AC-04
// AC-04: stable order, so a client diffing the response does not churn on Go
// map iteration order.
func TestCapabilities_StableOrder(t *testing.T) {
	t.Run("api-capabilities/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		got, _ := getCaps(t, url)
		ids := make([]string, len(got.Capabilities))
		for i, c := range got.Capabilities {
			ids[i] = c.ID
		}
		if !sort.StringsAreSorted(ids) {
			t.Errorf("capabilities are not in stable id order: %v", ids)
		}
	})
}
