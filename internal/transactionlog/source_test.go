// @spec system-transaction-log-writer
//
// AC traceability (this file):
//   AC-12  TestNoScanBaselinesReferenceInRepo
//   AC-13  TestNoRawSQLConcat_InPackage

package transactionlog

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

func appDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(packageDir(t), "..", "..")
}

func goSourceFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

// @ac AC-12
// AC-12: the entire codebase contains no references to the
// scan_baselines table — neither in migrations, queries, models, nor
// code. The Python implementation used scan_baselines; this Go side
// explicitly drops it (the prior transactions row IS the baseline).
//
// Walks every .go and .sql file under app/ looking for the literal
// string "scan_baselines" or the camel-case "ScanBaseline".
func TestNoScanBaselinesReferenceInRepo(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-12", func(t *testing.T) {
		root := appDir(t)

		forbidden := []string{
			"scan_baselines",
			"ScanBaseline",
		}
		var offenders []string

		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Skip vendor/build directories.
				name := d.Name()
				if name == "dist" || name == "node_modules" || name == ".specter-results.json" {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".go" && ext != ".sql" {
				return nil
			}
			// Don't scan our own AC-12 test (it contains the forbidden
			// string by design as part of the test's literal pattern).
			if strings.HasSuffix(path, "source_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil // best-effort scan
			}
			src := string(b)
			for _, bad := range forbidden {
				if strings.Contains(src, bad) {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders, rel+" contains "+bad)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		if len(offenders) > 0 {
			t.Errorf("AC-12: codebase contains scan_baselines references — the Python-era table is explicitly dropped (transactions IS the baseline). Offenders:\n  %s", strings.Join(offenders, "\n  "))
		}
	})
}

// @ac AC-13
// AC-13: internal/transactionlog source files contain no calls to
// db.Exec / db.Query / text() with string-concatenated SQL. All DB
// access uses parameterized queries via pgxpool.Pool's typed Exec/Query
// methods. AST-walks every import + scans for forbidden patterns.
//
// What's allowed:
//   - pool.Exec(ctx, `<const SQL>`, args...)  — parameterized
//   - pool.QueryRow(ctx, `<const SQL>`, args...) — parameterized
//   - tx.Exec / tx.QueryRow / tx.Query — parameterized
//   - fmt.Sprintf for ERROR MESSAGES (not for SQL)
//
// What's forbidden:
//   - fmt.Sprintf followed by pool.Exec/Query
//   - Any SQL fragment built via string concatenation (`"SELECT " + col + ...`)
//   - Use of database/sql.Tx instead of pgx.Tx (would indicate raw driver use)
func TestNoRawSQLConcat_InPackage(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-13", func(t *testing.T) {
		files := goSourceFiles(t, packageDir(t))
		if len(files) == 0 {
			t.Skip("no source files yet")
		}

		// Pattern: pool.Exec or tx.Exec or pool.Query with a
		// non-backticked, non-string-literal first SQL argument that
		// uses string concatenation. We detect this by looking for
		// the literal `+ string` operator inside a call to .Exec(,
		// or .Query(, or .QueryRow(,.
		//
		// This is intentionally conservative — if someone reaches
		// for fmt.Sprintf to build an SQL string, the call shape
		// `<dbHandle>.<method>(ctx, fmt.Sprintf(...)` is forbidden.
		concatPattern := regexp.MustCompile(`\.(?:Exec|Query|QueryRow)\(\s*\w+\s*,\s*fmt\.Sprintf`)
		stringPlusPattern := regexp.MustCompile(`\.(?:Exec|Query|QueryRow)\([^)]*"\s*\+\s*\w`)

		// Imports: database/sql import would suggest raw driver use.
		fset := token.NewFileSet()
		for _, f := range files {
			astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, imp := range astFile.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "database/sql" {
					t.Errorf("%s imports database/sql — internal/transactionlog uses pgx directly; database/sql suggests raw driver use forbidden by AC-13", f)
				}
			}

			// Source-level pattern check.
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			s := string(src)
			if concatPattern.MatchString(s) {
				t.Errorf("%s contains a .Exec/.Query/.QueryRow call whose SQL arg is built via fmt.Sprintf — AC-13 forbids string-built SQL", f)
			}
			if stringPlusPattern.MatchString(s) {
				t.Errorf("%s contains a .Exec/.Query/.QueryRow call whose SQL arg uses string-concatenation — AC-13 forbids", f)
			}
		}
	})
}
