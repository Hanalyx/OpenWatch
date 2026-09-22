// @spec system-rbac
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"gopkg.in/yaml.v3"
)

// Spec: specs/system/rbac.spec.yaml
//
//	AC-29  TestRBACClasses_EveryOperationDeclaresOneClassAndTheHandlerAgrees
//	AC-30  TestRBACClasses_AnonymousRegistryExposesNothingDynamic

const anonymousReadsKey = "x-anonymous-reads"

// contractOperation is one operation as the classification test reads it.
type contractOperation struct {
	Route      string
	Method     string
	Permission string
	Identity   bool
	Security   *[]any // nil when the operation inherits; a pointer to an empty list when it declares security: []
}

// allOperations reads every operation in api/openapi.yaml, every method,
// with the three fields the classification depends on.
func allOperations(t *testing.T) map[string]contractOperation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
			Permission  string `yaml:"x-required-permission"`
			Identity    bool   `yaml:"x-requires-identity"`
			Security    *[]any `yaml:"security"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	out := map[string]contractOperation{}
	for path, item := range doc.Paths {
		for method, op := range item {
			switch method {
			case "get", "post", "put", "patch", "delete":
			default:
				continue
			}
			if op.OperationID == "" {
				t.Errorf("%s %s has no operationId", strings.ToUpper(method), path)
				continue
			}
			out[op.OperationID] = contractOperation{
				Route: strings.ToUpper(method) + " " + path, Method: method,
				Permission: strings.TrimSpace(op.Permission), Identity: op.Identity, Security: op.Security,
			}
		}
	}
	return out
}

// namedAllowlist reads one of the two top-level allowlists.
func namedAllowlist(t *testing.T, key string) []allowlistEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	node, ok := doc[key]
	if !ok {
		return nil
	}
	var out []allowlistEntry
	if err := node.Decode(&out); err != nil {
		t.Fatalf("parse %s: %v", key, err)
	}
	return out
}

// enforcePermissionCall matches a route gate on a typed constant. It is
// narrower than authQualifiedRef on purpose: GetLicense reads
// HasPermission(auth.SystemRead) to decide which fields to write and lets
// an anonymous caller through, which is a field gate, not a route gate.
var enforcePermissionCall = regexp.MustCompile(`EnforcePermission\(\s*w\s*,\s*r\s*,\s*(auth\.[A-Z][A-Za-z0-9]*|[a-z][A-Za-z0-9]*)\s*\)`)

// @ac AC-29
// AC-29: every operation, GET included, declares exactly one authorization
// class in the contract, and the handler source agrees with the class.
func TestRBACClasses_EveryOperationDeclaresOneClassAndTheHandlerAgrees(t *testing.T) {
	t.Run("system-rbac/AC-29", func(t *testing.T) {
		ops := allOperations(t)
		if len(ops) == 0 {
			t.Fatal("no operations parsed; the contract or this parser is broken")
		}
		src := serverSource(t)
		constOf := permConstByValue(t)
		permConstNames := map[string]bool{}
		for _, name := range constOf {
			permConstNames[name] = true
		}

		// Both allowlists: every entry justified, live, and unique across
		// the two lists together.
		anon := map[string]string{}
		for _, key := range []string{anonymousAllowlistKey, anonymousReadsKey} {
			for _, e := range namedAllowlist(t, key) {
				id := strings.TrimSpace(e.OperationID)
				if id == "" {
					t.Errorf("%s has an entry with no operationId", key)
					continue
				}
				if strings.TrimSpace(e.Reason) == "" {
					t.Errorf("%s entry %q carries no reason", key, id)
				}
				op, live := ops[id]
				if !live {
					t.Errorf("%s names %q, which is not an operation in the contract", key, id)
					continue
				}
				if key == anonymousAllowlistKey && op.Method == "get" {
					t.Errorf("%s names %q, a GET; reads belong on %s", key, id, anonymousReadsKey)
				}
				if key == anonymousReadsKey && op.Method != "get" {
					t.Errorf("%s names %q, a %s; mutations belong on %s", key, id, strings.ToUpper(op.Method), anonymousAllowlistKey)
				}
				if prev, dup := anon[id]; dup {
					t.Errorf("%q appears on both %s and %s", id, prev, key)
				}
				anon[id] = key
			}
		}

		// A route gate on a typed permission constant, following delegation
		// the way AC-18 does. Reports the constant it found so an
		// allowlisted route that later gained a gate is named precisely.
		routeGate := func(body string) bool {
			for _, m := range enforcePermissionCall.FindAllStringSubmatch(body, -1) {
				if strings.HasPrefix(m[1], "auth.") && permConstNames[strings.TrimPrefix(m[1], "auth.")] {
					return true
				}
				if !strings.HasPrefix(m[1], "auth.") {
					// A permission passed in as a parameter (reviewException,
					// lifecycle). The caller's body names the constant, and
					// AC-18 pins which one; here it is enough that a gate runs.
					return true
				}
			}
			return false
		}
		// An identity gate reads the bound identity and refuses when there
		// is none. 401 is the canonical refusal; api-activity C-01 mandates
		// 403 for its route, which is why both are accepted here.
		identityGate := func(body string) bool {
			reads := strings.Contains(body, "IsAnonymous") || strings.Contains(body, "callerUUID(")
			refuses := strings.Contains(body, "http.StatusUnauthorized") || strings.Contains(body, "http.StatusForbidden")
			return reads && refuses
		}

		var problems []string
		perm, ident, anonCount := 0, 0, 0
		for opID, op := range ops {
			classes := []string{}
			if op.Permission != "" {
				classes = append(classes, "x-required-permission")
			}
			if op.Identity {
				classes = append(classes, "x-requires-identity")
			}
			_, listed := anon[opID]
			securityEmpty := op.Security != nil && len(*op.Security) == 0
			if listed || securityEmpty {
				classes = append(classes, "anonymous")
			}
			if len(classes) != 1 {
				problems = append(problems, op.Route+" ("+opID+") declares "+strings.Join(classes, "+")+"; exactly one class is required")
				continue
			}
			body := handlerBody(src, opID)
			if body == "" {
				problems = append(problems, op.Route+" ("+opID+") has no handler; its class cannot be checked")
				continue
			}
			switch classes[0] {
			case "x-required-permission":
				perm++ // AC-18 checks the constant matches the declaration
			case "x-requires-identity":
				ident++
				if !enforcesFunc(src, body, identityGate, 0) {
					problems = append(problems, op.Route+" ("+opID+") declares x-requires-identity but its handler does not read the identity and refuse an anonymous caller")
				}
				if enforcesFunc(src, body, routeGate, 0) {
					problems = append(problems, op.Route+" ("+opID+") declares x-requires-identity but its handler enforces a permission; declare x-required-permission instead")
				}
			case "anonymous":
				anonCount++
				if enforcesFunc(src, body, routeGate, 0) {
					problems = append(problems, op.Route+" ("+opID+") is allowlisted as anonymous but its handler enforces a permission; delete the allowlist entry and declare the permission")
				}
			}
		}
		sort.Strings(problems)
		for _, p := range problems {
			t.Error(p)
		}
		if perm+ident+anonCount != len(ops) {
			t.Errorf("accounting does not close: %d operations, but %d permission + %d identity + %d anonymous = %d",
				len(ops), perm, ident, anonCount, perm+ident+anonCount)
		}
		if len(problems) == 0 {
			t.Logf("%d operations: %d declare a permission, %d require an identity, %d anonymous (%d on %s, %d on %s, rest security: [])",
				len(ops), perm, ident, anonCount, countKey(anon, anonymousAllowlistKey), anonymousAllowlistKey,
				countKey(anon, anonymousReadsKey), anonymousReadsKey)
		}
	})
}

func countKey(m map[string]string, key string) int {
	n := 0
	for _, v := range m {
		if v == key {
			n++
		}
	}
	return n
}

// @ac AC-30
// AC-30: the anonymous registry exposes nothing dynamic: no user, no
// assignment, no custom role, no configuration value. Checked at runtime
// as an anonymous caller and in the handler's source.
func TestRBACClasses_AnonymousRegistryExposesNothingDynamic(t *testing.T) {
	t.Run("system-rbac/AC-30", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, err := http.NewRequest("GET", url+"/api/v1/auth/permissions:registry", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := doReq(t, req) // no cookie, no bearer: anonymous
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("anonymous registry status = %d, want 200", resp.StatusCode)
		}
		raw, _ := io.ReadAll(resp.Body)
		var top map[string]json.RawMessage
		if err := json.Unmarshal(raw, &top); err != nil {
			t.Fatalf("decode: %v", err)
		}
		keys := make([]string, 0, len(top))
		for k := range top {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "categories,permissions,roles" {
			t.Errorf("registry keys = %v, want exactly categories, permissions, roles", keys)
		}
		var roles []struct {
			ID        string `json:"id"`
			IsBuiltIn bool   `json:"is_built_in"`
		}
		if err := json.Unmarshal(top["roles"], &roles); err != nil {
			t.Fatalf("decode roles: %v", err)
		}
		got := map[string]bool{}
		for _, r := range roles {
			if !r.IsBuiltIn {
				t.Errorf("registry role %q is not built in; custom roles must not reach the anonymous registry", r.ID)
			}
			got[r.ID] = true
		}
		for id := range auth.BuiltInRoles {
			if !got[string(id)] {
				t.Errorf("built-in role %q missing from the registry", id)
			}
		}
		if len(got) != len(auth.BuiltInRoles) {
			t.Errorf("registry has %d roles, want the %d built-in roles only", len(got), len(auth.BuiltInRoles))
		}
		body := strings.ToLower(string(raw))
		for _, forbidden := range []string{"email", "username", "password", "user_id", "assigned", "dsn", "secret"} {
			if strings.Contains(body, `"`+forbidden+`"`) {
				t.Errorf("registry body carries a %q key; the anonymous registry must be static", forbidden)
			}
		}

		// Source half: the handler reads only the generated registry.
		src := serverSource(t)
		hb := handlerBody(src, "getAuthPermissionsRegistry")
		if hb == "" {
			t.Fatal("GetAuthPermissionsRegistry handler not found")
		}
		for _, reach := range []string{"h.pool", "h.users", "h.roles", "pgx", "Query(", "QueryRow("} {
			if strings.Contains(hb, reach) {
				t.Errorf("GetAuthPermissionsRegistry touches %s; the anonymous registry must come from the generated registry only", reach)
			}
		}
	})
}
