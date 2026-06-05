// @spec system-os-intelligence
//
// AC traceability (this file):
//
//	AC-01  TestCodes_AtLeast20CrossCategoryAndDottedHierarchy
//	AC-02  TestCodes_AllCoveredByAuditEventsYAML

package collector

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// @ac AC-01
// AC-01: taxonomy.Codes() returns at least 20 entries; every code matches
// the closed three-segment dotted regex; at least one entry from each
// category (account, security, system) appears.
func TestCodes_AtLeast20CrossCategoryAndDottedHierarchy(t *testing.T) {
	t.Run("system-os-intelligence/AC-01", func(t *testing.T) {
		codes := Codes()
		if len(codes) < 20 {
			t.Errorf("Codes() = %d entries, want >= 20", len(codes))
		}
		re := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2}$`)
		seen := map[string]int{}
		for _, c := range codes {
			s := string(c)
			if !re.MatchString(s) {
				t.Errorf("code %q does not match three-segment dotted regex", s)
			}
			cat := s[:strings.IndexByte(s, '.')]
			seen[cat]++
		}
		for _, want := range []string{"account", "security", "system"} {
			if seen[want] == 0 {
				t.Errorf("taxonomy has no entries in category %q", want)
			}
		}
	})
}

// @ac AC-02
// AC-02: every code in Codes() has a matching entry in
// app/audit/events.yaml. Source inspection: parse events.yaml and
// assert the union covers Codes().
func TestCodes_AllCoveredByAuditEventsYAML(t *testing.T) {
	t.Run("system-os-intelligence/AC-02", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		// Walk up to the app/ root.
		dir := filepath.Dir(file)
		var yamlPath string
		for i := 0; i < 8; i++ {
			cand := filepath.Join(dir, "audit", "events.yaml")
			if _, err := os.Stat(cand); err == nil {
				yamlPath = cand
				break
			}
			dir = filepath.Dir(dir)
		}
		if yamlPath == "" {
			t.Fatalf("could not locate app/audit/events.yaml from %s", file)
		}
		raw, err := os.ReadFile(yamlPath)
		if err != nil {
			t.Fatalf("read events.yaml: %v", err)
		}
		var doc struct {
			Events []struct {
				Code string `yaml:"code"`
			} `yaml:"events"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("yaml unmarshal: %v", err)
		}
		yamlCodes := map[string]bool{}
		for _, e := range doc.Events {
			yamlCodes[e.Code] = true
		}
		for _, c := range Codes() {
			if !yamlCodes[string(c)] {
				t.Errorf("taxonomy code %q has no entry in app/audit/events.yaml", c)
			}
		}
	})
}
