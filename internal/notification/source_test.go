// @spec system-notifications
//
// Source-inspection guards: the list/read path never decrypts, and the
// package pulls in no external notification SDK.

package notification

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// readSource returns the concatenated source of the package's non-test
// .go files.
func readSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		data, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		b.Write(data)
		b.WriteString("\n")
	}
	return b.String()
}

// @ac AC-02
// The secret-free list/read methods (List, Get, scanMeta) must not call
// decryptConfig. We parse store.go and check the bodies of those funcs.
func TestListGetDoNotDecrypt(t *testing.T) {
	t.Run("system-notifications/AC-02", func(t *testing.T) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "store.go", nil, 0)
		if err != nil {
			t.Fatalf("parse store.go: %v", err)
		}
		secretFree := map[string]bool{"List": true, "Get": true, "scanMeta": true}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !secretFree[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "decryptConfig" {
					t.Errorf("%s calls decryptConfig — secret-free path must not decrypt", fn.Name.Name)
				}
				return true
			})
		}
	})
}

// @ac AC-07
// The package must not import any external notification SDK; delivery is
// net/http + encoding/json only.
func TestNoExternalNotificationSDK(t *testing.T) {
	t.Run("system-notifications/AC-07", func(t *testing.T) {
		src := readSource(t)
		banned := []string{
			"slack-go/slack",
			"nlopes/slack",
			"go-resty",
			"gomail",
			"sendgrid",
		}
		for _, b := range banned {
			if strings.Contains(src, b) {
				t.Errorf("notification package imports banned SDK %q", b)
			}
		}
		// Positive: delivery uses net/http.
		if !strings.Contains(src, "\"net/http\"") {
			t.Error("expected net/http for delivery")
		}
	})
}
