// @spec api-fleet-observability
//
// AC traceability (this file):
//   AC-13  TestFleetHandlers_NoSQL_NoPoolAccess

package server

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func fleetHandlerSources(t *testing.T) []string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	return []string{
		filepath.Join(dir, "fleet_handlers.go"),
		filepath.Join(dir, "fleet_helpers.go"),
	}
}

// @ac AC-13
// AC-13: fleet handler files contain no SQL statements (SELECT/INSERT/
// UPDATE/DELETE) and no direct h.pool.Query / h.pool.Exec calls. All
// data access goes through h.fleet.* methods on fleetrollup.Service.
func TestFleetHandlers_NoSQL_NoPoolAccess(t *testing.T) {
	t.Run("api-fleet-observability/AC-13", func(t *testing.T) {
		sqlPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bSELECT\s`),
			regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`),
			regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b`),
			regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
		}
		poolPattern := regexp.MustCompile(`h\.pool\.(Query|QueryRow|Exec|Begin)\b`)

		for _, f := range fleetHandlerSources(t) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			src := string(b)
			for _, p := range sqlPatterns {
				if p.MatchString(src) {
					t.Errorf("%s contains SQL matching %q — fleet handlers must delegate to fleetrollup.Service (AC-13)",
						filepath.Base(f), p.String())
				}
			}
			if poolPattern.MatchString(src) {
				t.Errorf("%s contains direct h.pool access — must go through h.fleet (AC-13)",
					filepath.Base(f))
			}
			// Must reference h.fleet to confirm delegation actually happens.
			if !strings.Contains(src, "h.fleet.") && filepath.Base(f) == "fleet_handlers.go" {
				t.Errorf("%s never references h.fleet — handlers do not delegate to fleetrollup.Service (AC-13)",
					filepath.Base(f))
			}
		}
	})
}
