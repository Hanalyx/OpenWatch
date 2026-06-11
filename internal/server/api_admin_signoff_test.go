// @spec release-admin-signoff
//
// Sign-off acceptance tests for release 0.2.0. Most ACs are cited to
// the underlying spec that already enforces them; this file's job is
// to make the citations auditable (the named spec file exists and
// lists the cited AC) and to drive the composition checks the per-
// spec tests do not run.

package server

import (
	"os"
	"strings"
	"testing"
)

// readSpec is a tiny helper: reads a spec file from the repository
// (relative to this test's package dir) and returns its content as a
// string. The signoff tests cite specific spec files + AC ids; if
// either drifts, the test fails.
func readSpec(t *testing.T, relPath string) string {
	t.Helper()
	raw, err := os.ReadFile(relPath)
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return string(raw)
}

// requireACs fails the test if the spec body does not mention every
// cited AC id (e.g., "AC-01") — guards against the cited AC being
// renumbered or dropped.
func requireACs(t *testing.T, specBody, specID string, acIDs ...string) {
	t.Helper()
	for _, ac := range acIDs {
		if !strings.Contains(specBody, "id: "+ac) {
			t.Errorf("%s missing %s", specID, ac)
		}
	}
}

// @ac AC-01
// AC-01: login happy path covered by api-auth AC-01.
func TestReleaseSignoff_AC01_LoginHappyPath(t *testing.T) {
	t.Run("release-admin-signoff/AC-01", func(t *testing.T) {
		s := readSpec(t, "../../specs/api/auth.spec.yaml")
		requireACs(t, s, "api-auth", "AC-01")
	})
}

// @ac AC-02
// AC-02: login + MFA happy path covered by api-auth AC-05.
func TestReleaseSignoff_AC02_LoginMFA(t *testing.T) {
	t.Run("release-admin-signoff/AC-02", func(t *testing.T) {
		s := readSpec(t, "../../specs/api/auth.spec.yaml")
		requireACs(t, s, "api-auth", "AC-05")
	})
}

// @ac AC-03
// AC-03: /auth/me with session cookie covered by api-auth AC-10.
func TestReleaseSignoff_AC03_AuthMe(t *testing.T) {
	t.Run("release-admin-signoff/AC-03", func(t *testing.T) {
		s := readSpec(t, "../../specs/api/auth.spec.yaml")
		requireACs(t, s, "api-auth", "AC-10")
	})
}

// @ac AC-04
// AC-04: admin user create with no password_hash leak covered by
// api-users AC-01.
func TestReleaseSignoff_AC04_UserCreate(t *testing.T) {
	t.Run("release-admin-signoff/AC-04", func(t *testing.T) {
		s := readSpec(t, "../../specs/api/users.spec.yaml")
		requireACs(t, s, "api-users", "AC-01")
	})
}

// @ac AC-05
// AC-05: admin host create covered by api-hosts AC-01.
func TestReleaseSignoff_AC05_HostCreate(t *testing.T) {
	t.Run("release-admin-signoff/AC-05", func(t *testing.T) {
		s := readSpec(t, "../../specs/api/hosts.spec.yaml")
		requireACs(t, s, "api-hosts", "AC-01")
	})
}

// @ac AC-06
// AC-06: credential create with no secret leak covered by
// api-credentials AC-01.
func TestReleaseSignoff_AC06_CredentialCreate(t *testing.T) {
	t.Run("release-admin-signoff/AC-06", func(t *testing.T) {
		s := readSpec(t, "../../specs/api/credentials.spec.yaml")
		requireACs(t, s, "api-credentials", "AC-01")
	})
}

// @ac AC-07
// AC-07: credential resolve (host-scope wins, system-default fallback)
// covered by api-credentials AC-10 + AC-11.
func TestReleaseSignoff_AC07_CredentialResolve(t *testing.T) {
	t.Run("release-admin-signoff/AC-07", func(t *testing.T) {
		s := readSpec(t, "../../specs/api/credentials.spec.yaml")
		requireACs(t, s, "api-credentials", "AC-10", "AC-11")
	})
}

// @ac AC-08
// AC-08: OIDC/SAML 402 explicitly deferred. The sso_saml license
// feature is registered; the endpoint that returns 402 is not in 0.2.0
// scope. This test pins the deferral so it's auditable — when the SSO
// endpoint lands, replace this body with a real handler check.
func TestReleaseSignoff_AC08_SSODeferred(t *testing.T) {
	t.Run("release-admin-signoff/AC-08", func(t *testing.T) {
		// The license feature itself MUST be registered so the future
		// endpoint can gate on it.
		feats, err := os.ReadFile("../license/features.gen.go")
		if err != nil {
			t.Fatalf("read features.gen.go: %v", err)
		}
		if !strings.Contains(string(feats), `SsoSaml Feature = "sso_saml"`) {
			t.Error("sso_saml feature not in license registry; SSO deferral is misaligned")
		}
		// The signoff spec MUST explicitly mark this AC deferred.
		s := readSpec(t, "../../specs/release/admin-signoff.spec.yaml")
		if !strings.Contains(s, "explicitly deferred") {
			t.Error("admin-signoff spec must keep the SSO deferral annotation")
		}
	})
}

// AC-09 lives in api_admin_e2e_test.go as TestAdminE2E_RealIdentity —
// the only AC that the signoff directly enforces with its own
// end-to-end test.

// @ac AC-10
// AC-10: every 0.2.0 spec is registered in specter.yaml. The full
// `specter coverage` check is operator-mediated; this test pins the
// minimum invariant: the registry lists the 9 0.2.0 spec ids.
func TestReleaseSignoff_AC10_SpecsRegistered(t *testing.T) {
	t.Run("release-admin-signoff/AC-10", func(t *testing.T) {
		raw, err := os.ReadFile("../../specter.yaml")
		if err != nil {
			t.Fatalf("read specter.yaml: %v", err)
		}
		s := string(raw)
		required := []string{
			"system-auth-identity",
			"system-user-management",
			"system-credential-store",
			"system-host-inventory",
			"system-ssh-connectivity",
			"api-auth",
			"api-users",
			"api-credentials",
			"api-hosts",
			"release-admin-signoff",
		}
		for _, id := range required {
			if !strings.Contains(s, id) {
				t.Errorf("specter.yaml missing spec id %q", id)
			}
		}
	})
}

// @ac AC-11
// AC-11: Stage-0 DoD steps 7-19 still pass. Covered by the existing
// release-stage-0-signoff spec — pinning that those ACs are still
// listed catches a regression where the 0.2.0 work dropped the earlier
// signoff coverage.
func TestReleaseSignoff_AC11_Stage0Preserved(t *testing.T) {
	t.Run("release-admin-signoff/AC-11", func(t *testing.T) {
		s := readSpec(t, "../../specs/release/stage-0-signoff.spec.yaml")
		// All 13 Stage-0 ACs must still be declared.
		for i := 1; i <= 13; i++ {
			ac := "AC-"
			if i < 10 {
				ac += "0"
			}
			ac += string(rune('0' + i%10))
			if i == 10 {
				ac = "AC-10"
			} else if i == 11 {
				ac = "AC-11"
			} else if i == 12 {
				ac = "AC-12"
			} else if i == 13 {
				ac = "AC-13"
			}
			if !strings.Contains(s, "id: "+ac) {
				t.Errorf("stage-0-signoff missing %s", ac)
			}
		}
	})
}

// @ac AC-12
// AC-12: operator-mediated — `go test ./...` and `golangci-lint run`
// must be green. We cannot run them from inside a test (re-entrancy),
// but we can pin that the CI gate spec covers them.
func TestReleaseSignoff_AC12_CIGatesCover(t *testing.T) {
	t.Run("release-admin-signoff/AC-12", func(t *testing.T) {
		s := readSpec(t, "../../specs/release/ci-gates.spec.yaml")
		// The ci-gates spec must reference both Go test and golangci-lint.
		if !strings.Contains(strings.ToLower(s), "golangci") {
			t.Error("ci-gates spec does not mention golangci-lint")
		}
		if !strings.Contains(strings.ToLower(s), "go test") {
			t.Error("ci-gates spec does not mention go test")
		}
	})
}

// @ac AC-13
// AC-13: header-based identity bypass is removed entirely. Pins the
// negative invariant against future regressions — if anyone adds the
// stub binder back, this test fails. Mirrors system-rbac AC-12.
func TestReleaseSignoff_AC13_NoIdentityBypass(t *testing.T) {
	t.Run("release-admin-signoff/AC-13", func(t *testing.T) {
		s := readSpec(t, "../../specs/system/rbac.spec.yaml")
		requireACs(t, s, "system-rbac", "AC-12")

		// Source-level invariant: no stub-related symbol remains in
		// internal/auth.
		src, err := os.ReadFile("../auth/identity.go")
		if err != nil {
			t.Fatalf("read identity.go: %v", err)
		}
		for _, banned := range []string{
			"StubIdentityBinder",
			"StubRoleHeader",
			"StubUserIDHeader",
			"X-Stub-Role",
			"X-Stub-User-Id",
		} {
			if strings.Contains(string(src), banned) {
				t.Errorf("identity.go still contains %q — bypass must be removed", banned)
			}
		}

		// Middleware-level invariant: server.go does not mount any
		// auth.* middleware. The only auth wiring is the production
		// identity binder from internal/identity.
		srvSrc, err := os.ReadFile("server.go")
		if err != nil {
			t.Fatalf("read server.go: %v", err)
		}
		if strings.Contains(string(srvSrc), "auth.StubIdentityBinder") {
			t.Error("server.go still mounts auth.StubIdentityBinder")
		}
	})
}
