// @spec system-alerts
//
// AC traceability (this file):
//
//	AC-15  TestAlertsPackage_NoHTTPImports

package alerts

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// @ac AC-15
// AC-15: internal/alerts MUST NOT import internal/server or net/http.
func TestAlertsPackage_NoHTTPImports(t *testing.T) {
	t.Run("system-alerts/AC-15", func(t *testing.T) {
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
					t.Errorf("%s imports %q — alerts MUST stay HTTP-free", e.Name(), p)
				}
				if p == "net/http" {
					t.Errorf("%s imports net/http — alerts is HTTP-free", e.Name())
				}
			}
		}
	})
}
