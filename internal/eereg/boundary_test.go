package eereg

import (
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const eeModulePath = "github.com/Hanalyx/openwatch/ee"

// TestCoreDoesNotImportEE statically enforces the one-way licensing boundary:
// no package under internal/ or cmd/ that is part of the CE build may import
// the ee module tree. Files carrying the "ee" build tag (the wiring file that
// blank-imports ee) are excluded, since that is the single sanctioned bridge.
//
// This is the Go-test counterpart of scripts/check-ee-boundary.sh; the shell
// guard runs in `make check` without building, this runs under `go test` so the
// invariant carries spec coverage.
//
// @spec system-ee-capability-seam
// @ac AC-04
func TestCoreDoesNotImportEE(t *testing.T) {
	t.Run("system-ee-capability-seam/AC-04", func(t *testing.T) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(wd, "..", "..") // repo root from internal/eereg
		ctx := build.Default                  // default context: the "ee" tag is NOT set (CE build)

		for _, dir := range []string{"internal", "cmd"} {
			base := filepath.Join(root, dir)
			walkErr := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					switch d.Name() {
					case "spa", "node_modules", "testdata":
						return filepath.SkipDir
					}
					return nil
				}
				if !strings.HasSuffix(path, ".go") {
					return nil
				}
				// Only files included in the CE build matter. MatchFile evaluates
				// //go:build constraints against the default context, so the
				// ee-tagged wiring file is excluded here.
				included, mErr := ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
				if mErr != nil || !included {
					return nil
				}
				f, pErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
				if pErr != nil {
					return nil
				}
				for _, imp := range f.Imports {
					p := strings.Trim(imp.Path.Value, `"`)
					if p == eeModulePath || strings.HasPrefix(p, eeModulePath+"/") {
						rel, _ := filepath.Rel(root, path)
						t.Errorf("core file %s imports the ee tree (%s); the core must reach EE capabilities only via internal/eereg", rel, p)
					}
				}
				return nil
			})
			if walkErr != nil {
				t.Fatalf("walk %s: %v", base, walkErr)
			}
		}
	})
}
