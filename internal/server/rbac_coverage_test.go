// @spec system-rbac
//
// Per-route RBAC enforcement coverage (v0.7 exit criterion 1).
//
//	AC-18  TestRBACCoverage_EveryDeclaredPermissionIsEnforced
//	AC-22  TestRBACCoverage_EveryFeatureGateAlsoDeclaresAPermission
//	AC-24  TestRBACCoverage_EchoRequiresSystemRead
//	AC-25  TestRBACCoverage_EvaluateAlertRequiresPolicyRead
//	AC-26  TestRBACCoverage_NoMutatingRouteIsAnonymouslyOpen
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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/auth"
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

// opGates is what one operation declares about the two gates it expects:
// x-required-permission for RBAC and x-required-feature for entitlement.
// Either may be empty, and AC-22 is the rule about which combinations are
// allowed.
type opGates struct {
	Permission string
	Feature    string
}

// operationGates parses the OpenAPI contract and returns operationId -> the
// gates it declares. Operations declaring neither gate are omitted.
func operationGates(t *testing.T) map[string]opGates {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
			Permission  string `yaml:"x-required-permission"`
			Feature     string `yaml:"x-required-feature"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	out := map[string]opGates{}
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
			if op.Permission == "" && op.Feature == "" {
				continue
			}
			out[op.OperationID] = opGates{Permission: op.Permission, Feature: op.Feature}
		}
	}
	return out
}

// declaredPermissions returns operationId -> permission for every operation
// that declares x-required-permission.
func declaredPermissions(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for opID, gates := range operationGates(t) {
		if gates.Permission != "" {
			out[opID] = gates.Permission
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

// qualified is the package-qualified constant the caller is looking for, e.g.
// "auth.HostRead" or "license.ComplianceAttestation". It is a parameter rather
// than a hardcoded "auth." prefix because the license coverage check reuses
// this walker; the first cut hardcoded auth. and silently reported every
// license gate as missing.
func enforces(src, body, qualified string, depth int) bool {
	if strings.Contains(body, qualified) {
		return true
	}
	if depth >= maxDelegationDepth {
		return false
	}
	// Follow calls to same-receiver helpers, e.g. "h.reviewRemediation(", and
	// to package-level helpers, e.g. "enforceAttestationLicense(". Both are
	// real patterns here: RBAC delegates to a method, the license gate to a
	// package function. Following only one of them silently under-checks the
	// other.
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`h\.([a-z][A-Za-z0-9]*)\(`).FindAllStringSubmatch(body, -1) {
		seen["func (h *handlers) "+m[1]+"("] = true
	}
	for _, m := range regexp.MustCompile(`(?:^|[^.\w])([a-z][A-Za-z0-9]*)\(`).FindAllStringSubmatch(body, -1) {
		seen["func "+m[1]+"("] = true
	}
	for marker := range seen {
		i := strings.Index(src, marker)
		if i < 0 {
			continue
		}
		rest := src[i+len(marker):]
		if j := strings.Index(rest, "\nfunc "); j >= 0 {
			rest = rest[:j]
		}
		if enforces(src, rest, qualified, depth+1) {
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
			if enforces(src, body, "auth."+constName, 0) {
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

// @ac AC-22
// AC-22: a license feature check is never the only gate on a route. Every
// operation declaring x-required-feature also declares x-required-permission,
// and AC-18 above then holds its handler to the matching typed constant.
//
// Verified by inspecting the contract, so a new paid route that ships with an
// entitlement gate and no permission fails the build rather than review.
// POST /diagnostics:premium-echo was the instance: it called
// license.EnforceFeature and nothing else, so on any instance licensed for
// premium_diagnostics an anonymous caller reached the handler. Its sibling
// POST /diagnostics:require-remediation-execute already declared both and was
// unaffected.
func TestRBACCoverage_EveryFeatureGateAlsoDeclaresAPermission(t *testing.T) {
	t.Run("system-rbac/AC-22", func(t *testing.T) {
		gates := operationGates(t)
		if len(gates) == 0 {
			t.Fatal("no gate declarations found; the contract or this parser is broken")
		}

		featureGated := 0
		for opID, g := range gates {
			if g.Feature == "" {
				continue
			}
			featureGated++
			if g.Permission == "" {
				t.Errorf("%s declares x-required-feature %q and no x-required-permission. "+
					"Entitlement is not authorization: license state is process-global, so a "+
					"feature check alone tells the server what the deployment bought, never who "+
					"is asking.", opID, g.Feature)
			}
		}
		if featureGated == 0 {
			t.Fatal("no operation declares x-required-feature; this check would pass vacuously")
		}
		t.Logf("%d routes declare a feature gate; all also declare a permission", featureGated)
	})
}

// anonymousAllowlistKey is the top-level extension in api/openapi.yaml that
// names the mutating operations allowed to run without a caller. It is a
// constant so the contract and this walker cannot disagree by a typo, and so
// renaming the key is a one-line change here.
const anonymousAllowlistKey = "x-anonymous-mutations"

// allowlistEntry is one row of that list. Both fields are required: AC-26
// rejects an entry with no reason, because an allowlist whose entries carry no
// justification is a list somebody maintains rather than a rule.
type allowlistEntry struct {
	OperationID string `yaml:"operationId"`
	Reason      string `yaml:"reason"`
}

// mutatingOperations returns every POST, PUT, PATCH and DELETE in the contract
// as operationId -> "METHOD /path".
//
// This deliberately does not reuse operationGates. That parser drops any
// operation declaring neither gate, and an operation that declares nothing is
// exactly what AC-26 exists to catch.
func mutatingOperations(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	out := map[string]string{}
	for path, item := range doc.Paths {
		for method, op := range item {
			switch method {
			case "post", "put", "patch", "delete":
			default:
				continue
			}
			if op.OperationID == "" {
				t.Errorf("%s %s has no operationId; AC-26 cannot resolve it to a handler", strings.ToUpper(method), path)
				continue
			}
			out[op.OperationID] = strings.ToUpper(method) + " " + path
		}
	}
	return out
}

// anonymousAllowlist reads the named allowlist from api/openapi.yaml. A
// missing key returns an empty list, which is the correct reading: no
// operation is excused.
func anonymousAllowlist(t *testing.T) []allowlistEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	node, ok := doc[anonymousAllowlistKey]
	if !ok {
		return nil
	}
	var out []allowlistEntry
	if err := node.Decode(&out); err != nil {
		t.Fatalf("parse %s: %v", anonymousAllowlistKey, err)
	}
	return out
}

// enforcesFunc reports whether body satisfies match, following delegation to a
// same-receiver method or a package-level helper the way AC-18's enforces
// does. It is the same walk with a predicate instead of a fixed string,
// because AC-26 accepts two classes of check rather than one named constant.
func enforcesFunc(src, body string, match func(string) bool, depth int) bool {
	if match(body) {
		return true
	}
	if depth >= maxDelegationDepth {
		return false
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`h\.([a-z][A-Za-z0-9]*)\(`).FindAllStringSubmatch(body, -1) {
		seen["func (h *handlers) "+m[1]+"("] = true
	}
	for _, m := range regexp.MustCompile(`(?:^|[^.\w])([a-z][A-Za-z0-9]*)\(`).FindAllStringSubmatch(body, -1) {
		seen["func "+m[1]+"("] = true
	}
	for marker := range seen {
		i := strings.Index(src, marker)
		if i < 0 {
			continue
		}
		rest := src[i+len(marker):]
		if j := strings.Index(rest, "\nfunc "); j >= 0 {
			rest = rest[:j]
		}
		if enforcesFunc(src, rest, match, depth+1) {
			return true
		}
	}
	return false
}

// authQualifiedRef matches a reference to an exported identifier in the auth
// package, e.g. "auth.SystemRead". The match is narrowed afterwards to names
// the generated permission registry actually defines, so auth.FromContext is
// not mistaken for a permission.
var authQualifiedRef = regexp.MustCompile(`\bauth\.([A-Z][A-Za-z0-9]*)\b`)

// @ac AC-26
// AC-26: no mutating operation is anonymously open by accident. Every POST,
// PUT, PATCH and DELETE in api/openapi.yaml must resolve to a gate. Either its
// handler provably enforces the caller, or its operationId appears on the
// named anonymous allowlist the contract carries.
//
// Enforcement is read from the HANDLER SOURCE, not from the annotation. That
// is what keeps this check honest. The annotation is documentation that a CI
// gate gives teeth; the handler check is the only thing that stops a request.
// Reading the contract instead would report a missing x-required-permission on
// a route that does enforce as if it were open, and would miss a route that
// declares a permission it never checks.
//
// Two classes of check are accepted: an RBAC check on a typed constant from
// internal/auth/permissions.gen.go, or an authentication check for a route
// that needs no specific permission. The walk follows delegation to a
// same-receiver helper, since many handlers are thin wrappers.
//
// Both defects this AC closes, POST :echo and POST :evaluate-alert, survived
// review because a silent contract reads exactly like a safe one.
func TestRBACCoverage_NoMutatingRouteIsAnonymouslyOpen(t *testing.T) {
	t.Run("system-rbac/AC-26", func(t *testing.T) {
		ops := mutatingOperations(t)
		if len(ops) == 0 {
			t.Fatal("no mutating operations found; the contract or this parser is broken")
		}
		constOf := permConstByValue(t)
		permConstNames := map[string]bool{}
		for _, name := range constOf {
			permConstNames[name] = true
		}
		src := serverSource(t)

		// An RBAC gate is a reference to a generated permission constant.
		rbacGate := func(body string) bool {
			for _, m := range authQualifiedRef.FindAllStringSubmatch(body, -1) {
				if permConstNames[m[1]] {
					return true
				}
			}
			return false
		}
		// An authentication gate reads the bound identity and refuses when
		// there is none. This package spells that two ways, and both are
		// named here rather than matched by a loose pattern. Identity.
		// IsAnonymous is the direct read. callerUUID wraps auth.FromContext
		// and returns nil when the identity carries no user id, which the
		// self-scoped routes test instead.
		//
		// The refusal has to be in the same body. Reading IsAnonymous is not
		// by itself a gate: report_schedule_handlers.go reads it to attribute
		// a row to its creator and lets the request through either way.
		// Requiring the 401 alongside is what separates a check from a use.
		authGate := func(body string) bool {
			reads := strings.Contains(body, "IsAnonymous") || strings.Contains(body, "callerUUID(")
			return reads && strings.Contains(body, "http.StatusUnauthorized")
		}

		// The allowlist's whole value is that a reviewer can read the anonymous
		// surface off one page. Every check below defends that: an entry that
		// is hidden, unjustified, dead, or lying makes the page untrue, and an
		// untrue inventory is worse than none because it is believed.
		gates := operationGates(t)
		allowed := map[string]bool{}
		for _, e := range anonymousAllowlist(t) {
			if strings.TrimSpace(e.OperationID) == "" {
				t.Errorf("%s has an entry with no operationId", anonymousAllowlistKey)
				continue
			}
			if strings.TrimSpace(e.Reason) == "" {
				t.Errorf("%s entry %q carries no reason; an entry nobody justified is not an allowlist entry",
					anonymousAllowlistKey, e.OperationID)
			}
			if _, exists := ops[e.OperationID]; !exists {
				t.Errorf("%s names %q, which is not a mutating operation in the contract; "+
					"a renamed or deleted route must fail here rather than leave a dead entry that quietly widens the rule",
					anonymousAllowlistKey, e.OperationID)
			}
			// A duplicate hides one of the two entries from anyone reading the
			// list, and a merge is exactly where a second copy appears.
			if allowed[e.OperationID] {
				t.Errorf("%s names %q twice; a duplicate hides one entry from review",
					anonymousAllowlistKey, e.OperationID)
			}
			// Allowlisted and gated are opposite claims. The failure this
			// catches is not someone writing both today, it is a route being
			// gated later while its old entry survives. Then the page still
			// advertises an anonymous surface that no longer exists, and the
			// walk below passes either way because the entry short-circuits it.
			if g, ok := gates[e.OperationID]; ok && strings.TrimSpace(g.Permission) != "" {
				t.Errorf("%s names %q, which also declares x-required-permission %q. "+
					"An operation cannot be both anonymous and gated: if the route was gated after it was "+
					"allowlisted, delete the entry rather than leaving the list claiming it is open",
					anonymousAllowlistKey, e.OperationID, g.Permission)
			}
			allowed[e.OperationID] = true
		}

		var ungated, missingHandler []string
		gated := 0
		for opID, route := range ops {
			if allowed[opID] {
				continue
			}
			body := handlerBody(src, opID)
			if body == "" {
				missingHandler = append(missingHandler, route+" ("+opID+")")
				continue
			}
			if enforcesFunc(src, body, rbacGate, 0) || enforcesFunc(src, body, authGate, 0) {
				gated++
				continue
			}
			ungated = append(ungated, route+" ("+opID+")")
		}
		sort.Strings(ungated)
		sort.Strings(missingHandler)

		for _, m := range missingHandler {
			t.Errorf("no handler found for mutating operation %s; AC-26 cannot show it is gated", m)
		}
		for _, m := range ungated {
			t.Errorf("mutating operation is anonymously open: %s. Its handler enforces no permission "+
				"and does not check the caller is authenticated, and it is not on %s.",
				m, anonymousAllowlistKey)
		}

		// The arithmetic has to close. A walker that resolved 80 of 83 and
		// reported no failures would look identical to one that resolved all
		// 83, and the three it dropped are exactly where a defect would sit.
		// The per-operation errors above already catch that, but only if the
		// operation reached the loop at all: a parser that silently skipped an
		// operation, or an allowlist entry naming a route that is not mutating,
		// would leave no error and no trace. This makes the count itself an
		// assertion rather than a log line.
		if gated+len(allowed) != len(ops) {
			t.Errorf("accounting does not close: %d mutating operations, but %d gated + %d allowlisted = %d. "+
				"Every mutating operation must resolve to exactly one of the two states",
				len(ops), gated, len(allowed), gated+len(allowed))
		}
		if len(ungated) == 0 && len(missingHandler) == 0 {
			t.Logf("%d mutating operations: %d gated in the handler, %d on %s",
				len(ops), gated, len(allowed), anonymousAllowlistKey)
		}
	})
}

// @ac AC-24
// AC-24: POST /diagnostics:echo requires system:read, the same permission its
// sibling :premium-echo already requires.
//
// The route was open to anyone who could reach the port, and every call wrote
// one audit event carrying up to 1024 characters of the caller's own text plus
// one idempotency row holding the same text.
//
// The gate changes WHAT anonymous traffic writes, not HOW MUCH. It does not
// stop the audit write: auth.EnforcePermission denies through denyPermission,
// which emits authz.permission.denied on every denial including an anonymous
// one, exactly as AC-09 already requires. What changes is the content. The row
// is now a fixed shape carrying required_permission, instead of an event
// carrying text a compliance reviewer later reads as evidence. The row COUNT
// is still unbounded and nothing rate-limits the route, since
// internal/server/server.go throttles login and MFA only. That half is open,
// and this test does not pretend otherwise.
//
// WHAT THIS TEST DELIBERATELY DOES NOT ASSERT. An anonymous replay of a
// previously used Idempotency-Key returns the cached 200, not 401. That is
// measured and filed, not overlooked: see the comment at the end of this test
// and bugs/OW-012.
func TestRBACCoverage_EchoRequiresSystemRead(t *testing.T) {
	t.Run("system-rbac/AC-24", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		post := func(key, corr, message string, withCookie bool) (int, string) {
			t.Helper()
			req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:echo",
				strings.NewReader(`{"message":"`+message+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
			req.Header.Set("X-Correlation-Id", corr)
			if withCookie {
				req.AddCookie(roleCookies[auth.RoleViewer])
			}
			resp := doReq(t, req)
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}

		// 1. Anonymous, fresh key: 401 auth.required.
		code, body := post("ac24-anon-key", "ac24-anon", "ac24-anon-message", false)
		if code != http.StatusUnauthorized {
			t.Errorf("anonymous :echo status = %d, want 401; body=%s", code, body)
		}
		if !strings.Contains(body, "auth.required") {
			t.Errorf("anonymous :echo body lacks auth.required: %s", body)
		}

		// 2. It stored none of the caller's text. The audit writer is
		// asynchronous, so give it the same settle window the rest of this
		// suite uses before asserting an absence.
		//
		// What AC-24 rules out is the echo's own event, action
		// integration.plugin.executed, whose detail copies req.Message
		// verbatim (internal/server/handlers.go:263). That is the
		// attacker-controlled write. The denial row is server-authored and
		// fixed in shape, and C-04 with AC-09 REQUIRE it, so a run that wrote
		// literally nothing would break a different rule.
		time.Sleep(300 * time.Millisecond)
		var echoRows int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM audit_events
			   WHERE correlation_id = 'ac24-anon'
			     AND action = 'integration.plugin.executed'`,
		).Scan(&echoRows); err != nil {
			t.Fatalf("count echo audit_events: %v", err)
		}
		if echoRows != 0 {
			t.Errorf("anonymous :echo wrote %d echo audit rows, want 0", echoRows)
		}
		// Nothing anywhere in the audit table carries the anonymous caller's
		// text, whatever action a future author files it under.
		var textRows int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE detail::text LIKE '%ac24-anon-message%'`,
		).Scan(&textRows); err != nil {
			t.Fatalf("search audit_events detail: %v", err)
		}
		if textRows != 0 {
			t.Errorf("anonymous :echo copied the caller's text into %d audit rows, want 0", textRows)
		}
		// The denial itself IS recorded, per C-04, and its detail names the
		// permission rather than anything the caller sent. Asserted here so
		// the absence checks above can never be satisfied by an audit pipeline
		// that stopped writing altogether.
		var denialRows int64
		var denialDetail string
		if err := pool.QueryRow(ctx,
			`SELECT count(*), COALESCE(max(detail::text), '') FROM audit_events
			   WHERE correlation_id = 'ac24-anon' AND action = 'authz.permission.denied'`,
		).Scan(&denialRows, &denialDetail); err != nil {
			t.Fatalf("count denial audit_events: %v", err)
		}
		if denialRows != 1 {
			t.Errorf("anonymous :echo wrote %d authz.permission.denied rows, want 1", denialRows)
		}
		if !strings.Contains(denialDetail, `"system:read"`) {
			t.Errorf("denial detail does not name the required permission: %s", denialDetail)
		}
		var idemRows int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM idempotency_keys WHERE key = 'ac24-anon-key'`,
		).Scan(&idemRows); err != nil {
			t.Fatalf("count idempotency_keys: %v", err)
		}
		if idemRows != 0 {
			t.Errorf("anonymous :echo wrote %d idempotency_keys rows, want 0", idemRows)
		}

		// 3. A denial is never cached, so it is never replayable. The
		// middleware stores a 2xx and nothing else
		// (internal/idempotency/middleware.go:106). Sending the SAME key again
		// with no credentials therefore has to reach the handler and be denied
		// a second time rather than replay anything, and two attempts still
		// leave no idempotency row.
		code, body = post("ac24-anon-key", "ac24-anon-retry", "ac24-anon-message", false)
		if code != http.StatusUnauthorized {
			t.Errorf("anonymous retry with the same key: status = %d, want 401 again; body=%s", code, body)
		}
		if !strings.Contains(body, "auth.required") {
			t.Errorf("anonymous retry body lacks auth.required: %s", body)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM idempotency_keys WHERE key = 'ac24-anon-key'`,
		).Scan(&idemRows); err != nil {
			t.Fatalf("re-count idempotency_keys: %v", err)
		}
		if idemRows != 0 {
			t.Errorf("two anonymous :echo calls wrote %d idempotency_keys rows, want 0", idemRows)
		}

		// 4. A caller holding system:read succeeds, so the 401 above is the
		// permission and not a broken route.
		code, body = post("ac24-ok-key", "ac24-ok", "authorized", true)
		if code != http.StatusOK {
			t.Fatalf("viewer :echo status = %d, want 200; body=%s", code, body)
		}

		// 5. The anonymous replay. This assertion was withdrawn when AC-24 was
		// written, because it could not hold: internal/idempotency answered a
		// cache hit before the handler ran, so the auth.EnforcePermission above
		// never executed and the stored 200 was served to anyone holding the
		// key. That was bugs/OW-012, and it is now fixed.
		//
		// The middleware no longer runs at all for an anonymous caller, so the
		// key cached at step 4 is not even looked up. The request reaches the
		// handler and the permission check answers it.
		//
		// Re-enabling this here rather than only in the idempotency package is
		// deliberate. system-idempotency AC-10 pins the middleware behavior;
		// this pins the property an operator actually cares about, that a
		// cached success is never handed to a caller who was never authorized,
		// through the route where it was first measured.
		// The key and body MUST match step 4 exactly. A different key is not a
		// replay at all, it is a fresh anonymous call, and this assertion then
		// passes against a completely broken cache. That is not hypothetical:
		// the first version of this step reused a stale key name and survived
		// three separate mutations of the guard it was supposed to be pinning.
		code, body = post("ac24-ok-key", "ac24-replay", "authorized", false)
		if code != http.StatusUnauthorized {
			t.Errorf("anonymous replay of a used Idempotency-Key: status = %d, want 401. "+
				"A stored success must not be handed to a caller who was never authorized; body=%s", code, body)
		}
		if !strings.Contains(body, "auth.required") {
			t.Errorf("anonymous replay body lacks auth.required: %s", body)
		}
	})
}

// @ac AC-25
// AC-25: POST /diagnostics:evaluate-alert requires policy:read.
//
// It had no check of any kind, not even authentication. It decodes a score,
// evaluates the alert_thresholds policy, and returns the outcome with the
// policy type and version. An anonymous caller could walk scores 0 to 100,
// watch where the verdict changes, and read back the deployment's alert
// thresholds along with which policy version is loaded.
//
// All five built-in roles hold policy:read, so the fixture sessions cannot
// produce the 403 case. It uses the technique from api-license AC-16: an
// auth.Identity on the request context with IsAnonymous false and a RoleID
// that auth.BuiltInRoles does not resolve. That identity is authenticated and
// grants nothing, which is exactly the 403 case.
func TestRBACCoverage_EvaluateAlertRequiresPolicyRead(t *testing.T) {
	t.Run("system-rbac/AC-25", func(t *testing.T) {
		url, pool := freshAPIServer(t)

		// Anonymous over the real chain: 401 auth.required.
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:evaluate-alert",
			strings.NewReader(`{"score":65}`))
		req.Header.Set("Content-Type", "application/json")
		resp := doReq(t, req)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous :evaluate-alert status = %d, want 401; body=%s", resp.StatusCode, b)
		}
		if !strings.Contains(string(b), "auth.required") {
			t.Errorf("anonymous :evaluate-alert body lacks auth.required: %s", b)
		}
		// The response must not carry the policy the route exists to disclose.
		if strings.Contains(string(b), "policy_version") || strings.Contains(string(b), "outcome") {
			t.Errorf("anonymous denial leaked policy content: %s", b)
		}

		// Authenticated, but the role grants nothing: 403. The handler is
		// called directly because this identity cannot be minted through the
		// session binder.
		h := &handlers{pool: pool}
		unknownRole := auth.RoleID("role-that-grants-nothing")
		if _, resolves := auth.BuiltInRoles[unknownRole]; resolves {
			t.Fatalf("fixture role %q resolves in BuiltInRoles; pick one that does not", unknownRole)
		}
		direct := httptest.NewRequest("POST", "/api/v1/diagnostics:evaluate-alert",
			strings.NewReader(`{"score":65}`))
		direct.Header.Set("Content-Type", "application/json")
		direct = direct.WithContext(auth.SetIdentity(direct.Context(), auth.Identity{
			ID:          "authenticated-but-unprivileged",
			RoleID:      unknownRole,
			IsAnonymous: false,
		}))
		rec := httptest.NewRecorder()
		h.PostDiagnosticsEvaluateAlert(rec, direct)
		if rec.Code != http.StatusForbidden {
			t.Errorf("authenticated caller without policy:read: status = %d, want 403; body=%s",
				rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "authz.permission_denied") {
			t.Errorf("403 body lacks authz.permission_denied: %s", rec.Body.String())
		}

		// The contract declares what the handler enforces, which is what puts
		// the route in scope for the AC-18 gate.
		if got := declaredPermissions(t)["postDiagnosticsEvaluateAlert"]; got != "policy:read" {
			t.Errorf("openapi x-required-permission = %q, want policy:read", got)
		}
	})
}
