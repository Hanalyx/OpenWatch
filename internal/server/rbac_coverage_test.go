// @spec system-rbac
//
// Per-route RBAC enforcement coverage (v0.7 exit criterion 1).
//
//	AC-18  TestRBACCoverage_EveryDeclaredPermissionIsEnforced
//
// WHY THIS EXISTS: authorization was enforced only by a hand-written
// auth.EnforcePermission call inside each handler. Every privileged mutation
// did call it, verified by hand in the 2026-06-29 review, but nothing failed
// the build if a future handler forgot, and the OpenAPI x-required-permission
// declarations were decorative: no CI step linked the contract to the code.
//
// This test makes the link structural. A route that declares a permission in
// api/openapi.yaml and whose handler does not enforce that exact permission
// constant fails the build.
package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// permConstByValue reads the generated permission registry and returns a map
// from the permission string ("host:read") to its Go constant name
// ("HostRead"). Derived from the generated source rather than re-implementing
// the generator's naming convention, so the two cannot drift.
func permConstByValue(t *testing.T) map[string]string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "auth", "permissions.gen.go"))
	if err != nil {
		t.Fatalf("read permissions.gen.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*([A-Z][A-Za-z0-9]*)\s+Permission\s*=\s*"([^"]+)"`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out[m[2]] = m[1]
	}
	if len(out) == 0 {
		t.Fatal("no permission constants parsed from permissions.gen.go")
	}
	return out
}

// serverSource concatenates the non-test Go sources in this package, and also
// records which file each handler came from for readable failures.
func serverSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		b.Write(src)
		b.WriteString("\n")
	}
	return b.String()
}

// declaredPermissions parses the OpenAPI contract for every operation that
// declares x-required-permission, returning operationId -> permission.
func declaredPermissions(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
			Permission  string `yaml:"x-required-permission"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	out := map[string]string{}
	for _, item := range doc.Paths {
		for method, op := range item {
			switch method {
			case "get", "post", "put", "patch", "delete":
			default:
				continue
			}
			if op.Permission != "" && op.OperationID != "" {
				out[op.OperationID] = op.Permission
			}
		}
	}
	return out
}

// handlerBody returns the source of the handler method implementing
// operationId, or "" when no such method exists. oapi-codegen names the method
// after the operationId with the first letter upper-cased.
func handlerBody(src, operationID string) string {
	name := strings.ToUpper(operationID[:1]) + operationID[1:]
	marker := "func (h *handlers) " + name + "("
	i := strings.Index(src, marker)
	if i < 0 {
		return ""
	}
	rest := src[i+len(marker):]
	// Body ends at the next top-level func declaration.
	if j := strings.Index(rest, "\nfunc "); j >= 0 {
		return rest[:j]
	}
	return rest
}

// enforces reports whether body enforces constName, following delegation to a
// same-receiver helper up to maxDelegationDepth levels.
//
// Several handlers are thin wrappers: ApproveRemediation and RejectRemediation
// both delegate to h.reviewRemediation, which is where EnforcePermission
// actually lives. A checker that only looked at the handler body would report
// those as unenforced, and the natural "fix" for a false positive like that is
// to weaken the check, which is how a real gap gets let through later.
const maxDelegationDepth = 2

func enforces(src, body, constName string, depth int) bool {
	if strings.Contains(body, "auth."+constName) {
		return true
	}
	if depth >= maxDelegationDepth {
		return false
	}
	// Follow calls to same-receiver helpers, e.g. "h.reviewRemediation(".
	re := regexp.MustCompile(`h\.([a-z][A-Za-z0-9]*)\(`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		marker := "func (h *handlers) " + m[1] + "("
		i := strings.Index(src, marker)
		if i < 0 {
			continue
		}
		rest := src[i+len(marker):]
		if j := strings.Index(rest, "\nfunc "); j >= 0 {
			rest = rest[:j]
		}
		if enforces(src, rest, constName, depth+1) {
			return true
		}
	}
	return false
}

// @ac AC-18
// AC-18: every route declaring x-required-permission has a handler that
// enforces that exact permission constant. A route that forgets fails the
// build.
func TestRBACCoverage_EveryDeclaredPermissionIsEnforced(t *testing.T) {
	t.Run("system-rbac/AC-18", func(t *testing.T) {
		declared := declaredPermissions(t)
		if len(declared) == 0 {
			t.Fatal("no x-required-permission declarations found; the contract or this parser is broken")
		}
		constOf := permConstByValue(t)
		src := serverSource(t)

		var missingHandler, unknownPerm, notEnforced []string

		for opID, perm := range declared {
			constName, ok := constOf[perm]
			if !ok {
				// The contract names a permission the registry does not have.
				unknownPerm = append(unknownPerm, opID+" declares "+perm)
				continue
			}
			body := handlerBody(src, opID)
			if body == "" {
				missingHandler = append(missingHandler, opID)
				continue
			}
			// The handler must reference the generated constant, not a raw
			// string. forbidigo separately bans raw permission literals.
			if enforces(src, body, constName, 0) {
				continue
			}
			notEnforced = append(notEnforced, opID+" must enforce auth."+constName+" ("+perm+")")
		}

		for _, m := range unknownPerm {
			t.Errorf("openapi declares a permission missing from the registry: %s", m)
		}
		for _, m := range missingHandler {
			t.Errorf("no handler found for operationId %q; if it was renamed, the contract is stale", m)
		}
		for _, m := range notEnforced {
			t.Errorf("route does not enforce its declared permission: %s", m)
		}

		if len(notEnforced) == 0 && len(unknownPerm) == 0 && len(missingHandler) == 0 {
			t.Logf("%d routes declare a permission; all enforce it", len(declared))
		}
	})
}
