// @spec system-intelligence-scheduler
//
// AC traceability (this file):
//
//	AC-01  TestMigration0019_AddsNextIntelligenceAt
//	AC-07  TestListIntelTargets_SingleSQLQuery
//	AC-12  TestDispatchHost_AdvisoryLockBeforeRunCycle
//	AC-15  TestSchedulerPackage_NoServerImports

package scheduler

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// @ac AC-01
// AC-01: Migration 0019 adds next_intelligence_at to
// host_intelligence_state + an index on (next_intelligence_at NULLS
// FIRST). A partial WHERE was tried but Postgres rejects
// now()-based predicates (SQLSTATE 42P17 — predicate functions must
// be IMMUTABLE).
func TestMigration0019_AddsNextIntelligenceAt(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-01", func(t *testing.T) {
		path := findMigration(t, "0019_intel_scheduler.sql")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		s := string(raw)
		if !strings.Contains(s, "ADD COLUMN next_intelligence_at TIMESTAMPTZ") {
			t.Errorf("migration 0019 missing ADD COLUMN next_intelligence_at TIMESTAMPTZ")
		}
		if !strings.Contains(s, "CREATE INDEX idx_intel_state_due") {
			t.Errorf("migration 0019 missing idx_intel_state_due index")
		}
		// B-tree on (next_intelligence_at NULLS FIRST) — the scheduler
		// query walks the leftmost slice.
		if !strings.Contains(s, "next_intelligence_at NULLS FIRST") {
			t.Errorf("migration 0019 idx_intel_state_due missing 'next_intelligence_at NULLS FIRST' ordering")
		}
	})
}

// @ac AC-07
// AC-07: listIntelTargets MUST issue exactly one pool.Query call.
// Source inspection on service.go.
func TestListIntelTargets_SingleSQLQuery(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-07", func(t *testing.T) {
		src := readSchedulerSrc(t, "service.go")
		body := extractFuncBody(t, src, "listIntelTargets")
		count := strings.Count(body, ".Query(")
		if count != 1 {
			t.Errorf("listIntelTargets contains %d .Query(...) calls, want exactly 1", count)
		}
	})
}

// @ac AC-12
// AC-12: dispatchHost acquires the per-host advisory lock BEFORE the
// real RunCycle call. Source inspection: pool.BeginTx →
// pg_(try_)advisory_xact_lock → s.runner.RunCycle ordering. Spec C-03
// describes the lock as pg_advisory_xact_lock; the production code
// uses the try variant (no-op on contention instead of blocking) per
// the spec's "one runs, the other no-ops" wording.
func TestDispatchHost_AdvisoryLockBeforeRunCycle(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-12", func(t *testing.T) {
		src := readSchedulerSrc(t, "service.go")
		body := extractFuncBody(t, src, "dispatchHost")
		beginIdx := strings.Index(body, "BeginTx")
		lockIdx := strings.Index(body, "advisory_xact_lock")
		// Find the production RunCycle call site (captures runErr),
		// not the pool-less early-return at the top of the function.
		runIdx := strings.Index(body, "_, runErr := s.runner.RunCycle")
		if beginIdx < 0 || lockIdx < 0 || runIdx < 0 {
			t.Fatalf("dispatchHost missing one of {BeginTx=%d, advisory_xact_lock=%d, RunCycle=%d}",
				beginIdx, lockIdx, runIdx)
		}
		if !(beginIdx < lockIdx && lockIdx < runIdx) {
			t.Errorf("dispatchHost ordering wrong — got BeginTx@%d, advisory@%d, RunCycle@%d (want strictly increasing)",
				beginIdx, lockIdx, runIdx)
		}
	})
}

// @ac AC-15
// AC-15: scheduler package source MUST NOT import internal/server or
// any http-shaped package.
func TestSchedulerPackage_NoServerImports(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-15", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			astFile, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", e.Name(), err)
			}
			for _, imp := range astFile.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(p, "internal/server") {
					t.Errorf("%s imports %q — scheduler MUST stay credential-and-DB only (no HTTP)", e.Name(), p)
				}
				if p == "net/http" {
					t.Errorf("%s imports net/http — scheduler is HTTP-free", e.Name())
				}
			}
		}
	})
}

// findMigration walks up from the test file to the migrations dir.
func findMigration(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "db", "migrations", name)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate migration %q", name)
	return ""
}

// readSchedulerSrc reads a .go file from the scheduler package dir.
func readSchedulerSrc(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

// extractFuncBody returns the body of the named top-level func. Scans
// for a declaration line — either "func name(" or "func (x *T) name("
// — then returns the substring through the next "\nfunc " start (or
// EOF). The decl-only match avoids matching call-sites like
// "s.dispatchHost(...)" inside other functions.
func extractFuncBody(t *testing.T, src, name string) string {
	t.Helper()
	// Plain top-level: "func name("
	idx := strings.Index(src, "func "+name+"(")
	if idx < 0 {
		// Method receiver: "func (...) name("
		// Walk the source looking for "func (" then a matching ") name(".
		pos := 0
		for {
			off := strings.Index(src[pos:], "func (")
			if off < 0 {
				break
			}
			start := pos + off
			// Find the close of the receiver group then check the next token.
			closeParen := strings.Index(src[start:], ") ")
			if closeParen < 0 {
				break
			}
			afterRecv := start + closeParen + 2
			if strings.HasPrefix(src[afterRecv:], name+"(") {
				idx = start
				break
			}
			pos = afterRecv
		}
	}
	if idx < 0 {
		t.Fatalf("function %q not found in source", name)
	}
	body := src[idx:]
	nextFn := strings.Index(body[1:], "\nfunc ")
	if nextFn > 0 {
		body = body[:nextFn]
	}
	return body
}
