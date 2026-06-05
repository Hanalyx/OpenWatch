// @spec system-discovery-scheduler
//
// AC traceability (this file):
//
//	AC-06  TestListDiscoveryTargets_SingleSQLQuery
//	AC-07  TestEnqueueDispatch_UsesQueueEnqueue
//	AC-11  TestSchedulerPackage_NoServerImports

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

// @ac AC-06
// AC-06: listDiscoveryTargets MUST issue exactly one pool.Query call.
// Source inspection on service.go.
func TestListDiscoveryTargets_SingleSQLQuery(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-06", func(t *testing.T) {
		src := readSchedulerSrc(t, "service.go")
		body := extractFuncBody(t, src, "listDiscoveryTargets")
		count := strings.Count(body, ".Query(")
		if count != 1 {
			t.Errorf("listDiscoveryTargets contains %d .Query(...) calls, want exactly 1", count)
		}
	})
}

// @ac AC-07
// AC-07: enqueueing goes through internal/queue.Enqueue with the
// JobKindHostDiscovery constant + HostDiscoveryJobPayload type. The
// scheduler does NOT call discovery.Service.Discover or any SSH path
// inline. Source inspection of service.go's enqueuer adapter.
func TestEnqueueDispatch_UsesQueueEnqueue(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-07", func(t *testing.T) {
		src := readSchedulerSrc(t, "service.go")
		// PoolEnqueuer.Enqueue MUST call queue.Enqueue with the
		// discovery job-kind constant + payload type.
		body := extractFuncBody(t, src, "Enqueue")
		if !strings.Contains(body, "queue.Enqueue(") {
			t.Errorf("PoolEnqueuer.Enqueue does not call queue.Enqueue")
		}
		if !strings.Contains(body, "discovery.JobKindHostDiscovery") {
			t.Errorf("PoolEnqueuer.Enqueue does not reference discovery.JobKindHostDiscovery")
		}
		if !strings.Contains(body, "discovery.HostDiscoveryJobPayload") {
			t.Errorf("PoolEnqueuer.Enqueue does not reference discovery.HostDiscoveryJobPayload")
		}
		// Negative: no inline SSH or Discover calls.
		if strings.Contains(src, ".Discover(") {
			t.Errorf("service.go contains a .Discover(...) call — the scheduler must enqueue, not run")
		}
		if strings.Contains(src, "ssh.Dial") || strings.Contains(src, "owssh.") {
			t.Errorf("service.go references SSH primitives — the scheduler must not open sessions")
		}
	})
}

// @ac AC-11
// AC-11: scheduler package source MUST NOT import internal/server or
// any http-shaped package. Walks every .go file under
// internal/intelligence/discovery/scheduler/.
func TestSchedulerPackage_NoServerImports(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-11", func(t *testing.T) {
		dir := packageDir(t)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		fset := token.NewFileSet()
		forbidden := []string{
			"github.com/Hanalyx/openwatch/internal/server",
			"net/http",
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				t.Errorf("parse %s: %v", path, err)
				continue
			}
			for _, imp := range f.Imports {
				v := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbidden {
					if v == bad {
						t.Errorf("%s imports %q — scheduler must stay HTTP-free", path, v)
					}
				}
			}
		}
	})
}

// readSchedulerSrc reads a file from this package's source directory.
func readSchedulerSrc(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(packageDir(t), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

// packageDir returns the absolute path to this package's source dir.
func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

// extractFuncBody returns the source between the first `{` and matching
// `}` after the named function's declaration. Simplistic but adequate
// for the small bodies under test.
func extractFuncBody(t *testing.T, src, fnName string) string {
	t.Helper()
	// Look for "func [(receiver)] name(" — accept any receiver shape.
	patterns := []string{
		"func (s *Service) " + fnName + "(",
		"func (s Service) " + fnName + "(",
		"func (p PoolEnqueuer) " + fnName + "(",
		"func " + fnName + "(",
	}
	var start int = -1
	for _, p := range patterns {
		if i := strings.Index(src, p); i >= 0 {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("function %s not found in source", fnName)
	}
	brace := strings.Index(src[start:], "{")
	if brace < 0 {
		t.Fatalf("opening brace for %s not found", fnName)
	}
	depth := 1
	pos := start + brace + 1
	for ; pos < len(src) && depth > 0; pos++ {
		switch src[pos] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return src[start+brace : pos]
}
