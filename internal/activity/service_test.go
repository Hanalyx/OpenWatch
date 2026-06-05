// @spec system-activity
//
// AC traceability (this file):
//
//	AC-09  TestList_LimitOutOfRange
//	AC-10  TestList_InvalidSourceOrSeverity
//	AC-11  TestList_SourceInspection_OneQueryAndUnionAll
//	AC-12  TestPackage_NoHTTPImports

package activity

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// @ac AC-09
// AC-09: limit=0 and limit=300 -> ErrInvalidLimit; valid range passes
// the gate (we don't need the DB to assert the rejection).
func TestList_LimitOutOfRange(t *testing.T) {
	t.Run("system-activity/AC-09", func(t *testing.T) {
		svc := NewService(nil)
		_, _, _, err := svc.List(context.Background(), Filter{Limit: 0}, Caller{})
		if !errors.Is(err, ErrInvalidLimit) {
			t.Errorf("limit=0 err=%v, want ErrInvalidLimit", err)
		}
		_, _, _, err = svc.List(context.Background(), Filter{Limit: 300}, Caller{})
		if !errors.Is(err, ErrInvalidLimit) {
			t.Errorf("limit=300 err=%v, want ErrInvalidLimit", err)
		}
	})
}

// @ac AC-10
// AC-10: unknown source / severity return their typed errors and
// don't touch the DB (svc.pool is nil — would panic if reached).
func TestList_InvalidSourceOrSeverity(t *testing.T) {
	t.Run("system-activity/AC-10", func(t *testing.T) {
		svc := NewService(nil)
		_, _, _, err := svc.List(context.Background(),
			Filter{Limit: 50, Source: "not-a-source"}, Caller{})
		if !errors.Is(err, ErrInvalidSource) {
			t.Errorf("err=%v, want ErrInvalidSource", err)
		}
		_, _, _, err = svc.List(context.Background(),
			Filter{Limit: 50, Severity: "not-a-sev"}, Caller{})
		if !errors.Is(err, ErrInvalidSeverity) {
			t.Errorf("err=%v, want ErrInvalidSeverity", err)
		}
	})
}

// @ac AC-11
// AC-11: source inspection — queryUnion's body executes exactly one
// pool.Query, and the assembled SQL contains UNION ALL literally.
func TestList_SourceInspection_OneQueryAndUnionAll(t *testing.T) {
	t.Run("system-activity/AC-11", func(t *testing.T) {
		src := readSrc(t, "service.go")
		body := extractFuncBody(t, src, "queryUnion")
		if c := strings.Count(body, ".Query("); c != 1 {
			t.Errorf("queryUnion contains %d .Query(...) calls, want 1", c)
		}
		if !strings.Contains(body, `"UNION ALL`) && !strings.Contains(body, "UNION ALL") {
			t.Errorf("queryUnion does not assemble a UNION ALL")
		}
	})
}

// @ac AC-12
// AC-12: activity package source MUST NOT import internal/server or net/http.
func TestPackage_NoHTTPImports(t *testing.T) {
	t.Run("system-activity/AC-12", func(t *testing.T) {
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
					t.Errorf("%s imports %q — activity MUST stay HTTP-free", e.Name(), p)
				}
				if p == "net/http" {
					t.Errorf("%s imports net/http — activity is HTTP-free", e.Name())
				}
			}
		}
	})
}

func readSrc(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

func extractFuncBody(t *testing.T, src, name string) string {
	t.Helper()
	// Plain top-level: "func name("
	idx := strings.Index(src, "func "+name+"(")
	if idx < 0 {
		// Method receiver: "func (x *T) name("
		pos := 0
		for {
			off := strings.Index(src[pos:], "func (")
			if off < 0 {
				break
			}
			start := pos + off
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
		t.Fatalf("function %q not found", name)
	}
	body := src[idx:]
	nextFn := strings.Index(body[1:], "\nfunc ")
	if nextFn > 0 {
		body = body[:nextFn]
	}
	return body
}
