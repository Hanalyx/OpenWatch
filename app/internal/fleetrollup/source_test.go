// @spec system-fleet-rollup
//
// AC traceability (this file):
//   AC-11  TestNoMutationSQL_InPackage
//   AC-12  TestNoRawSQLConcat_InPackage
//   AC-13  TestServiceMethodsReturnTypedStructs

package fleetrollup

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
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

func goNonTestFiles(t *testing.T) []string {
	t.Helper()
	dir := packageDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

// @ac AC-11
// AC-11: internal/fleetrollup contains no INSERT, UPDATE, or DELETE
// SQL statements (case-insensitive). Enforces the read-only invariant.
func TestNoMutationSQL_InPackage(t *testing.T) {
	t.Run("system-fleet-rollup/AC-11", func(t *testing.T) {
		// Case-insensitive whole-word patterns. Avoid false positives
		// on identifiers that contain the word (e.g. "InsertSomething"
		// in a Go func name would be caught by the strings approach,
		// but we use \b to keep this tight).
		mutationPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`),
			regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b`),
			regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
			regexp.MustCompile(`(?i)\bTRUNCATE\s+TABLE\b`),
		}
		for _, f := range goNonTestFiles(t) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			src := string(b)
			for _, p := range mutationPatterns {
				if p.MatchString(src) {
					t.Errorf("%s contains mutation SQL matching %q — fleetrollup is read-only (AC-11)",
						f, p.String())
				}
			}
		}
	})
}

// @ac AC-12
// AC-12: internal/fleetrollup contains no fmt.Sprintf-into-SQL nor
// string-concatenated SQL. All SQL is parameterized via $1, $2, ...
func TestNoRawSQLConcat_InPackage(t *testing.T) {
	t.Run("system-fleet-rollup/AC-12", func(t *testing.T) {
		concatPattern := regexp.MustCompile(`\.(?:Exec|Query|QueryRow)\(\s*\w+\s*,\s*fmt\.Sprintf`)
		stringPlusPattern := regexp.MustCompile(`\.(?:Exec|Query|QueryRow)\([^)]*"\s*\+\s*\w`)

		// Imports: database/sql import would suggest raw driver use,
		// which contradicts our pgxpool-only stance.
		fset := token.NewFileSet()
		for _, f := range goNonTestFiles(t) {
			astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, imp := range astFile.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "database/sql" {
					t.Errorf("%s imports database/sql — fleetrollup uses pgxpool directly (AC-12)", f)
				}
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			s := string(src)
			if concatPattern.MatchString(s) {
				t.Errorf("%s builds SQL via fmt.Sprintf — parameterize instead (AC-12)", f)
			}
			if stringPlusPattern.MatchString(s) {
				t.Errorf("%s builds SQL via string concatenation — parameterize instead (AC-12)", f)
			}
		}
	})
}

// @ac AC-13
// AC-13: every exported method on *Service returns a concrete struct
// type (not map[string]any). Reflection walks Service's method set.
func TestServiceMethodsReturnTypedStructs(t *testing.T) {
	t.Run("system-fleet-rollup/AC-13", func(t *testing.T) {
		st := reflect.TypeOf((*Service)(nil))
		// AnyType is the forbidden return type at any position.
		anyType := reflect.TypeOf((*any)(nil)).Elem()

		for i := 0; i < st.NumMethod(); i++ {
			m := st.Method(i)
			// Skip non-exported (defensive — Go reflection on a pointer
			// type already filters to exported, but explicit is better).
			if !m.IsExported() {
				continue
			}
			ft := m.Type
			// Return positions: the first non-error result must be a
			// concrete struct (or a slice of one). Walk all results.
			for j := 0; j < ft.NumOut(); j++ {
				rt := ft.Out(j)
				// Allow error.
				errIface := reflect.TypeOf((*error)(nil)).Elem()
				if rt.Implements(errIface) {
					continue
				}
				// Allow slice — unwrap.
				if rt.Kind() == reflect.Slice {
					rt = rt.Elem()
				}
				// Reject map[string]any.
				if rt.Kind() == reflect.Map {
					if rt.Key().Kind() == reflect.String && rt.Elem() == anyType {
						t.Errorf("Service.%s returns map[string]any — must return typed structs (AC-13)", m.Name)
					}
					continue
				}
				// At this point rt should be a struct (concrete value type).
				if rt.Kind() != reflect.Struct {
					t.Errorf("Service.%s returns %s (kind %s) — expected concrete struct (AC-13)",
						m.Name, rt, rt.Kind())
				}
			}
		}
	})
}
