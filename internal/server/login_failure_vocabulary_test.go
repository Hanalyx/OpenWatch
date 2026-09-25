// @spec system-auth-identity

package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// loginFailureReasonSources are the files that produce the reason recorded
// on auth.login.failure. A reason produced anywhere else is invisible to
// this scan, which is the scan's known limit.
var loginFailureReasonSources = []string{
	"../identity/binder.go",
	"../identity/account_state.go",
	"auth_handlers.go",
	"sso_handlers.go",
}

// reasonReturningFuncs name functions whose string returns ARE reasons.
var reasonReturningFuncs = map[string]bool{
	"Reason":            true,
	"ssoFailureReason":  true,
	"ssoRefusalReason":  true,
	"unavailableReason": false,
}

// reasonVariables name the variables and fields a reason is assigned to
// before it is emitted.
var reasonVariables = map[string]bool{"reason": true, "loginRefused": true, "refused": true}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// emittedLoginFailureReasons collects every string literal that reaches
// detail.reason through the shapes the four source files use.
func emittedLoginFailureReasons(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	fset := token.NewFileSet()
	for _, path := range loginFailureReasonSources {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		add := func(e ast.Expr) {
			if v, ok := stringLit(e); ok && v != "" {
				found[v] = fset.Position(e.Pos()).String()
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				// const reasonX = "..."
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || d.Tok != token.CONST {
						continue
					}
					for i, name := range vs.Names {
						if strings.HasPrefix(name.Name, "reason") && i < len(vs.Values) {
							add(vs.Values[i])
						}
					}
				}
			case *ast.FuncDecl:
				inReasonFunc := reasonReturningFuncs[d.Name.Name]
				ast.Inspect(d, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.ReturnStmt:
						// return "..." inside a reason function
						if inReasonFunc && len(x.Results) == 1 {
							add(x.Results[0])
						}
						// return anon(), "..."
						if len(x.Results) == 2 {
							if call, ok := x.Results[0].(*ast.CallExpr); ok {
								if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "anon" {
									add(x.Results[1])
								}
							}
						}
					case *ast.CallExpr:
						// emitLoginFailure(r, "...", ...)
						if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "emitLoginFailure" && len(x.Args) >= 2 {
							add(x.Args[1])
						}
					case *ast.AssignStmt:
						// reason = "...", loginRefused = "...", res.refused = "..."
						for i, lhs := range x.Lhs {
							name := ""
							switch l := lhs.(type) {
							case *ast.Ident:
								name = l.Name
							case *ast.SelectorExpr:
								name = l.Sel.Name
							}
							if reasonVariables[name] && i < len(x.Rhs) {
								add(x.Rhs[i])
							}
						}
					}
					return true
				})
			}
		}
	}
	return found
}

func declaredLoginFailureReasons(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../audit/events.yaml")
	if err != nil {
		t.Fatalf("read events.yaml: %v", err)
	}
	var doc struct {
		Events []struct {
			Code         string `yaml:"code"`
			DetailSchema struct {
				Properties map[string]struct {
					Enum []string `yaml:"enum"`
				} `yaml:"properties"`
			} `yaml:"detail_schema"`
		} `yaml:"events"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse events.yaml: %v", err)
	}
	for _, e := range doc.Events {
		if e.Code == "auth.login.failure" {
			out := map[string]bool{}
			for _, v := range e.DetailSchema.Properties["reason"].Enum {
				out[v] = true
			}
			return out
		}
	}
	t.Fatal("auth.login.failure is not declared in events.yaml")
	return nil
}

// @ac AC-80
// AC-80: every reason the code can record on auth.login.failure is
// declared in the audit contract. The emitter checks key names only, so
// without this an undeclared reason passes silently.
func TestLoginFailureReasons_AreDeclared(t *testing.T) {
	t.Run("system-auth-identity/AC-80", func(t *testing.T) {
		emitted := emittedLoginFailureReasons(t)
		declared := declaredLoginFailureReasons(t)
		// The scan must see the shapes it claims to. These are reasons
		// known to be emitted, one per shape.
		for _, must := range []string{
			"account_state_unavailable", // const reason*
			"invalid_jwt",               // return anon(), "..."
			"session_owner_mismatch",    // Reason() method
			"wrong_password",            // assignment to reason
			"mfa_required",              // emitLoginFailure literal
			"sso_account_disabled",      // ssoFailureReason
		} {
			if _, ok := emitted[must]; !ok {
				t.Errorf("the scan did not see %q; it no longer reads that shape", must)
			}
		}
		var missing []string
		for v, pos := range emitted {
			if !declared[v] {
				missing = append(missing, v+" ("+pos+")")
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("reasons recorded on auth.login.failure but not declared in audit/events.yaml:\n  %s",
				strings.Join(missing, "\n  "))
		}
	})
}
