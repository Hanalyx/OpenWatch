// @spec system-liveness-loop
//
// AC traceability (this file):
//   AC-14  TestNoCredentialImports

package liveness

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// @ac AC-14
// AC-14: internal/liveness source files must NOT import
// internal/credential and must NOT reference ssh.ParsePrivateKey or
// the credential-decryption code path. The probe is credential-free
// (spec C-07).
func TestNoCredentialImports(t *testing.T) {
	t.Run("system-liveness-loop/AC-14", func(t *testing.T) {
		dir := packageDir(t)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}

		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f := filepath.Join(dir, e.Name())
			astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, imp := range astFile.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(path, "internal/credential") {
					t.Errorf("%s imports %q — liveness MUST be credential-free (AC-14)", f, path)
				}
				if strings.Contains(path, "golang.org/x/crypto/ssh") {
					// The crypto/ssh package contains ParsePrivateKey
					// and other credential-handling primitives. The
					// probe should use net.DialTimeout + raw banner
					// read, not the SSH library.
					t.Errorf("%s imports %q — liveness uses raw TCP, not the SSH library (AC-14)", f, path)
				}
			}

			// Belt-and-suspenders: scan source text for
			// ssh.ParsePrivateKey calls (a future contributor reaching
			// for crypto/ssh via a renamed import would be caught here).
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			if strings.Contains(string(src), "ParsePrivateKey") {
				t.Errorf("%s references ParsePrivateKey — credential parsing forbidden (AC-14)", f)
			}
		}
	})
}
