// @spec system-discovery-scheduler

package scheduler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const queueImportPath = "github.com/Hanalyx/openwatch/internal/queue"

// queueInsertFuncs are the internal/queue functions that create a job row.
var queueInsertFuncs = map[string]bool{
	"Enqueue": true, "EnqueueAfter": true, "EnqueueIfAbsent": true, "Claim": true,
}

// discoveryEnqueueSites returns "file:line" for every call to a queue insert
// function whose arguments reference JobKindHostDiscovery, in every non-test
// Go file under root. It resolves the queue import's local name per file, so
// an aliased import is still seen.
func discoveryEnqueueSites(t *testing.T, root string) []string {
	t.Helper()
	var sites []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "frontend", "vendor", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		queueName := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == queueImportPath {
				queueName = "queue"
				if imp.Name != nil {
					queueName = imp.Name.Name
				}
			}
		}
		inQueuePkg := f.Name.Name == "queue"
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn := ""
			switch x := call.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && queueName != "" && id.Name == queueName {
					fn = x.Sel.Name
				}
			case *ast.Ident:
				if inQueuePkg {
					fn = x.Name
				}
			}
			if !queueInsertFuncs[fn] {
				return true
			}
			refs := false
			for _, a := range call.Args {
				ast.Inspect(a, func(m ast.Node) bool {
					switch y := m.(type) {
					case *ast.Ident:
						if y.Name == "JobKindHostDiscovery" {
							refs = true
						}
					case *ast.BasicLit:
						if y.Value == `"host.discovery"` {
							refs = true
						}
					}
					return true
				})
			}
			if refs {
				rel, _ := filepath.Rel(root, path)
				sites = append(sites, rel+":"+strconv.Itoa(fset.Position(call.Pos()).Line))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return sites
}

// @ac AC-17
// AC-17: only discovery's own enqueue and claim create discovery jobs.
func TestDiscoveryJobs_OnlyDiscoveryEnqueues(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-17", func(t *testing.T) {
		root := filepath.Join(packageDir(t), "..", "..", "..", "..")
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
			t.Fatalf("repository root not found at %s: %v", root, err)
		}
		const allowed = "internal/intelligence/discovery/lease.go"
		sites := discoveryEnqueueSites(t, root)
		found := 0
		for _, s := range sites {
			if strings.HasPrefix(s, allowed+":") {
				found++
				continue
			}
			t.Errorf("%s creates a host.discovery job outside discovery.Enqueue and discovery.ClaimRun", s)
		}
		// The allowed file must itself be seen, or the scan is blind.
		if found != 2 {
			t.Errorf("found %d discovery job inserts in %s, want 2 (Enqueue and ClaimRun)", found, allowed)
		}
	})
}
