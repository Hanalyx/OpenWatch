// @spec system-license-features
//
// Per-route license enforcement coverage (v0.7 exit criterion 2, epic A2).
//
//	AC-14  TestLicenseCoverage_EveryDeclaredFeatureIsRegisteredAndEnforced
//
// WHY THIS EXISTS: the licensing machinery is complete and was wired to
// exactly one demo route. Seven of the paid capabilities have no code yet, so
// today this check passes almost trivially. That is the point. It is not here
// to find current gaps; it is here so that when bulk remediation lands and
// someone forgets the gate, the build fails instead of the capability shipping
// free. The RBAC equivalent (system-rbac AC-18) exists for the same reason and
// found a real contract bug on its first run.
package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// featureConstByValue maps a feature id ("audit_export") to its generated Go
// constant name ("AuditExport"), read out of the generated registry rather
// than by reimplementing the generator's naming rule.
func featureConstByValue(t *testing.T) map[string]string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "license", "features.gen.go"))
	if err != nil {
		t.Fatalf("read features.gen.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*([A-Z][A-Za-z0-9]*)\s+Feature\s*=\s*"([^"]+)"`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out[m[2]] = m[1]
	}
	if len(out) == 0 {
		t.Fatal("no Feature constants parsed from features.gen.go")
	}
	return out
}

// declaredFeatures returns operationId -> (feature, conditional).
//
// Two annotations, deliberately distinct:
//
//	x-required-feature     the WHOLE route is paid
//	x-conditional-feature  the route is paid for SOME requests, decided from
//	                       the body. Reports are the live case: only the
//	                       `attestation` kind is entitled, so declaring the
//	                       route paid outright would be a false claim in the
//	                       public contract.
//
// Collapsing the two would force a choice between lying about a free route and
// leaving a real gate undeclared. The second is what happened when the
// attestation gate shipped: enforced in the handler, invisible in the contract.
func declaredFeatures(t *testing.T) map[string]struct {
	Feature     string
	Conditional bool
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
			Required    string `yaml:"x-required-feature"`
			Conditional string `yaml:"x-conditional-feature"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	out := map[string]struct {
		Feature     string
		Conditional bool
	}{}
	for _, item := range doc.Paths {
		for method, op := range item {
			switch method {
			case "get", "post", "put", "patch", "delete":
			default:
				continue
			}
			if op.OperationID == "" {
				continue
			}
			switch {
			case op.Required != "":
				out[op.OperationID] = struct {
					Feature     string
					Conditional bool
				}{op.Required, false}
			case op.Conditional != "":
				out[op.OperationID] = struct {
					Feature     string
					Conditional bool
				}{op.Conditional, true}
			}
		}
	}
	return out
}

// @ac AC-14
// AC-14: a route that declares a license feature names a registered one and
// actually enforces it. A paid route cannot ship ungated.
func TestLicenseCoverage_EveryDeclaredFeatureIsRegisteredAndEnforced(t *testing.T) {
	t.Run("system-license-features/AC-14", func(t *testing.T) {
		declared := declaredFeatures(t)
		constOf := featureConstByValue(t)
		src := serverSource(t)
		// The conditional gates live outside this package.
		extra := ""
		for _, rel := range []string{
			filepath.Join("..", "reportschedule", "dispatcher.go"),
		} {
			if b, err := os.ReadFile(rel); err == nil {
				extra = extra + "\n" + string(b)
			}
		}
		all := src + extra

		if len(declared) == 0 {
			t.Fatal("no feature declarations found; the contract or this parser is broken")
		}

		for opID, d := range declared {
			constName, ok := constOf[d.Feature]
			if !ok {
				t.Errorf("%s declares feature %q which is not in licensing/features.yaml", opID, d.Feature)
				continue
			}
			body := handlerBody(src, opID)
			if body == "" {
				t.Errorf("no handler found for operationId %q; the contract is stale", opID)
				continue
			}
			// A conditional gate is usually delegated to a named helper, so
			// look at the whole package for the constant when the handler body
			// does not carry it directly.
			if strings.Contains(body, "license."+constName) {
				continue
			}
			// Follow the route's own call graph. Deliberately NOT a
			// package-wide search for the constant: the first cut of this
			// check did that, and it passed a route whose gate had been
			// swapped to a different feature, because the right constant still
			// appeared elsewhere in the package. A loose match in a security
			// check is worse than none, because it reads as coverage.
			if enforces(all, body, "license."+constName, 0) {
				continue
			}
			t.Errorf("route %s declares feature %q but does not enforce license.%s",
				opID, d.Feature, constName)
		}

		// The reverse direction: a paid feature enforced somewhere in the
		// server package must be declared by at least one route, or the public
		// contract hides a paywall. This is the gap the attestation gate left.
		for value, constName := range constOf {
			if !strings.Contains(src, "license."+constName) {
				continue
			}
			found := false
			for _, d := range declared {
				if d.Feature == value {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("license.%s is enforced in the server package but no route declares %q; "+
					"add x-required-feature (whole route) or x-conditional-feature (body-dependent)",
					constName, value)
			}
		}
	})
}
