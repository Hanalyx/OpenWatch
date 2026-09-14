// @spec release-ci-gates
//
// AC traceability (this file):
//
//	AC-17  TestCopyLandsOutsideTheRepository, TestPlantingInTheCopyDoesNotTouchTheCheckout

package isotree

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The copy must be OUTSIDE the repository, or it defeats its own purpose: a
// repository-rooted walk would find it.
// @ac AC-17
func TestCopyLandsOutsideTheRepository(t *testing.T) {
	t.Run("release-ci-gates/AC-17", func(t *testing.T) {
		repo := filepath.Join("..", "..")
		abs, err := filepath.Abs(repo)
		if err != nil {
			t.Fatal(err)
		}
		dst := Copy(t, repo, "internal/isotree")
		dabs, err := filepath.Abs(dst)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(dabs, abs+string(filepath.Separator)) {
			t.Fatalf("copy %s is inside the repository %s; a tree walk would see it", dabs, abs)
		}
		if _, err := os.Stat(filepath.Join(dst, "go.mod")); err != nil {
			t.Errorf("go.mod was not copied: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "internal", "isotree", "isotree.go")); err != nil {
			t.Errorf("the requested directory was not copied at its relative path: %v", err)
		}
	})
}

// A file planted in the copy is not in the checkout.
// @ac AC-17
func TestPlantingInTheCopyDoesNotTouchTheCheckout(t *testing.T) {
	t.Run("release-ci-gates/AC-17", func(t *testing.T) {
		repo := filepath.Join("..", "..")
		dst := Copy(t, repo, "internal/isotree")
		planted := filepath.Join(dst, "internal", "isotree", "zz_planted.go")
		if err := os.WriteFile(planted, []byte("package isotree\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(repo, "internal", "isotree", "zz_planted.go")); err == nil {
			t.Fatal("the planted file appeared in the real checkout")
		}
	})
}
