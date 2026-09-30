// Doc API query parameters. A documented request whose query parameter the API
// does not declare fails silently: the server ignores the unknown name and
// answers with its default. REPORT_VERIFICATION.md told readers to fetch
// /api/v1/reports/{id}/export?face=json; the parameter is `format`, its default
// is pdf, and every genuine signed report then failed the hash check (CP
// bugs/OW-091). This test reads every /api/v1/...?name= example in tracked
// Markdown and shell files and fails when the contract does not declare that
// query parameter for that path.
package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// docQueryRE captures a documented API path and its query string. The query
// ends at a quote, space, backtick, bracket or backslash.
var docQueryRE = regexp.MustCompile("(/api/v1/[A-Za-z0-9_\\-./{}$<>:]+)\\?([^\"'\\s`)\\]\\\\]+)")

// declaredQueryParams returns, for each contract path, the query parameter
// names declared on the path item or on any of its operations.
func declaredQueryParams(t *testing.T, contract []byte) map[string]map[string]bool {
	t.Helper()
	var doc struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Parameters map[string]map[string]any `yaml:"parameters"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(contract, &doc); err != nil {
		t.Fatalf("parse api/openapi.yaml: %v", err)
	}
	resolve := func(p any) map[string]any {
		m, _ := p.(map[string]any)
		if ref, ok := m["$ref"].(string); ok {
			return doc.Components.Parameters[ref[strings.LastIndex(ref, "/")+1:]]
		}
		return m
	}
	collect := func(into map[string]bool, params any) {
		list, _ := params.([]any)
		for _, p := range list {
			m := resolve(p)
			if m["in"] == "query" {
				if name, ok := m["name"].(string); ok {
					into[name] = true
				}
			}
		}
	}
	out := map[string]map[string]bool{}
	for path, item := range doc.Paths {
		names := map[string]bool{}
		collect(names, item["parameters"])
		for _, op := range item {
			if m, ok := op.(map[string]any); ok {
				collect(names, m["parameters"])
			}
		}
		out[path] = names
	}
	return out
}

// isPlaceholder reports whether a documented path segment stands for a value
// (`$ID`, `{id}`, `<id>`) rather than a literal.
func isPlaceholder(seg string) bool {
	return strings.ContainsAny(seg, "${<")
}

// matchContractPath returns the contract path a documented path refers to.
// A contract segment in braces matches any documented segment; among several
// matches the one with the most literal segments wins, so
// /reports/signing-key is not read as /reports/{id}.
func matchContractPath(documented string, contract map[string]map[string]bool) (string, bool) {
	dseg := strings.Split(strings.TrimSuffix(documented, "/"), "/")
	best, bestLiterals := "", -1
	for path := range contract {
		cseg := strings.Split(path, "/")
		if len(cseg) != len(dseg) {
			continue
		}
		literals, ok := 0, true
		for i := range cseg {
			switch {
			case cseg[i] == dseg[i]:
				literals++
			case strings.HasPrefix(cseg[i], "{") && dseg[i] != "":
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && literals > bestLiterals {
			best, bestLiterals = path, literals
		}
	}
	return best, bestLiterals >= 0
}

type docQuery struct {
	file, line, path, param string
}

// scanDocQueries extracts every documented /api/v1 query parameter from text.
func scanDocQueries(file, text string) []docQuery {
	var out []docQuery
	for n, line := range strings.Split(text, "\n") {
		for _, m := range docQueryRE.FindAllStringSubmatch(line, -1) {
			for _, kv := range strings.Split(m[2], "&") {
				name := kv
				if i := strings.Index(kv, "="); i >= 0 {
					name = kv[:i]
				}
				if name == "" || isPlaceholder(name) {
					continue
				}
				out = append(out, docQuery{file, file + ":" + strconv.Itoa(n+1), m[1], name})
			}
		}
	}
	return out
}

// undeclared returns the documented queries whose parameter the contract does
// not declare for the documented path, and the paths it cannot match.
func undeclared(queries []docQuery, contract map[string]map[string]bool) []string {
	var bad []string
	for _, q := range queries {
		path, ok := matchContractPath(q.path, contract)
		if !ok {
			bad = append(bad, q.line+": "+q.path+" is not a path in api/openapi.yaml")
			continue
		}
		if !contract[path][q.param] {
			var declared []string
			for n := range contract[path] {
				declared = append(declared, n)
			}
			sort.Strings(declared)
			bad = append(bad, q.line+": "+path+" declares no query parameter "+q.param+
				" (declared: "+strings.Join(declared, ", ")+")")
		}
	}
	return bad
}

func TestDocs_APIQueryParametersAreDeclared(t *testing.T) {
	root := repoRootForLinks(t)
	contractBytes, err := os.ReadFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read api/openapi.yaml: %v", err)
	}
	contract := declaredQueryParams(t, contractBytes)
	if len(contract) == 0 {
		t.Fatal("api/openapi.yaml parsed to no paths; the check would prove nothing")
	}

	t.Run("the contract declares format on the report export", func(t *testing.T) {
		got := contract["/api/v1/reports/{id}/export"]
		if !got["format"] || got["face"] {
			t.Fatalf("report export query parameters = %v, want format and not face", got)
		}
	})

	t.Run("the parser rejects the defect this test exists for", func(t *testing.T) {
		q := scanDocQueries("fixture.md", "curl \"https://h/api/v1/reports/$ID/export?face=json\" -o r.json")
		if len(q) != 1 || q[0].param != "face" || q[0].path != "/api/v1/reports/$ID/export" {
			t.Fatalf("scan of the OW-091 line = %+v, want one query for face on the export path", q)
		}
		if bad := undeclared(q, contract); len(bad) != 1 {
			t.Fatalf("undeclared(face=json) = %v, want exactly one finding", bad)
		}
	})

	t.Run("tracked docs name only declared query parameters", func(t *testing.T) {
		out, err := exec.Command("git", "-C", root, "ls-files", "*.md", "*.sh").Output()
		if err != nil {
			t.Skipf("git ls-files unavailable (%v); skipping", err)
		}
		var queries []docQuery
		for _, rel := range strings.Fields(string(out)) {
			if strings.Contains(rel, "node_modules/") || strings.HasPrefix(rel, "docs/_history/") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			queries = append(queries, scanDocQueries(rel, string(b))...)
		}
		sawReportExport := false
		for _, q := range queries {
			if q.file == "docs/runbooks/REPORT_VERIFICATION.md" && strings.Contains(q.path, "/export") {
				sawReportExport = true
			}
		}
		if !sawReportExport {
			t.Fatal("found no report export query in REPORT_VERIFICATION.md; the scan cannot see the case it guards")
		}
		if bad := undeclared(queries, contract); len(bad) > 0 {
			t.Fatalf("%d documented query parameter(s) the contract does not declare:\n  %s",
				len(bad), strings.Join(bad, "\n  "))
		}
	})
}
