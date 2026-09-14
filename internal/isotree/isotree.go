// Package isotree gives a test a private copy of part of the repository.
//
// Several guard tests prove their detector can see a planted fixture. Planting
// it in the shared checkout is the obvious way and it is wrong: any other test
// that walks the tree at the same moment can list the fixture and then fail to
// open it once it is removed. That is not a theoretical race. Under
// `go test -p 4 ./...` the retention sweeper guard failed a documentation-only
// pull request on exactly that interleaving (CP bugs/OW-036).
//
// The fix is isolation, not tolerance. A detector that can be pointed at a
// root runs its clean scan against the real repository, as it must, and its
// planted scan against a copy that only this test can see. The copy lives
// under t.TempDir(), outside the checkout, so a repository-rooted walk never
// encounters it and nothing is left behind if the test dies.
//
// This is test support. It has no production callers and adds no behavior to
// the product.
package isotree

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Copy copies go.mod, go.sum and each of the named repository-relative
// directories from repoRoot into a fresh temporary directory, preserving the
// relative layout, and returns that directory. It is enough for a source walk
// and for `go list -deps` run from inside the copy, which resolves external
// modules from the module cache and internal ones from the copied tree.
//
// Symlinks are not followed and directories named .git, node_modules and
// vendor are skipped: none of them is source the guards read, and node_modules
// alone would make the copy slow enough to matter.
func Copy(t testing.TB, repoRoot string, dirs ...string) string {
	t.Helper()
	dst := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum"} {
		src := filepath.Join(repoRoot, name)
		if _, err := os.Stat(src); err != nil {
			continue // a scope that is not a Go module is still copyable
		}
		copyFile(t, src, filepath.Join(dst, name))
	}
	for _, d := range dirs {
		copyDir(t, filepath.Join(repoRoot, d), filepath.Join(dst, d))
	}
	return dst
}

func copyDir(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor":
				if path != src {
					return filepath.SkipDir
				}
			}
			return os.MkdirAll(target, 0o755)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		copyFile(t, path, target)
		return nil
	})
	if err != nil {
		t.Fatalf("isotree: copy %s: %v", src, err)
	}
}

func copyFile(t testing.TB, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("isotree: open %s: %v", src, err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("isotree: mkdir for %s: %v", dst, err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("isotree: create %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("isotree: copy %s: %v", dst, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("isotree: close %s: %v", dst, err)
	}
}
