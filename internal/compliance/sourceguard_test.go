package compliance

// AC-04's guard: no exported accessor on the score receiver may return a single
// value whose UNDERLYING type is the forbidden numeric type.
//
// This is a source-level constraint, not a behavioral one, so it is checked by
// reading the package rather than by calling it. Testing that the zero value of
// Score is absent proves the current implementation behaves; it does not stop
// someone adding Percent(fallback) back tomorrow. That accessor existed in the
// first draft of this package and is the reason the guard is here.
//
// It resolves types with go/types rather than matching the declared identifier,
// because an identifier match sees float64 and misses both
//
//	type Percentage = float64   // alias
//	type Percentage float64     // named type
//
// each of which returns a score with no way to say there is none. That is the
// same defect wearing a different name, which is exactly how it would come back.
//
// Every parameter comes from the spec: which package to read, which receiver,
// which result type is forbidden, what the synthetic method is called, and which
// declaration forms must be caught. The test hardcodes none of them.

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bareResultAccessors returns "Recv.Method" for every exported method on recv
// in dir whose single result has forbidden as its underlying type, and how many
// exported methods on recv it saw at all.
//
// A directory with none is not "clean": it is the wrong directory. Without that
// count the guard passes against any package lacking the receiver, so
// source_path could be pointed anywhere and the criterion would still report
// covered. Found by mutation, not by reading.
//
// Package-level helpers are out of scope: Round1 returns a float64 and should,
// because it rounds a number a caller already proved present. The rule is about
// getting a score OUT of a Score.
func bareResultAccessors(t *testing.T, dir, recv, forbidden string) (violations []string, recvMethods int) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	for _, pkg := range pkgs {
		files := make([]*ast.File, 0, len(pkg.Files))
		for _, f := range pkg.Files {
			files = append(files, f)
		}
		conf := types.Config{
			Importer: importer.ForCompiler(fset, "source", nil),
			// A fixture package is deliberately minimal and may not resolve
			// every reference. Type errors must not mask a real finding, so they
			// are collected and ignored rather than aborting the check.
			Error: func(error) {},
		}
		info := &types.Info{Defs: map[*ast.Ident]types.Object{}}
		_, _ = conf.Check(pkg.Name, fset, files, info)

		for id, obj := range info.Defs {
			fn, ok := obj.(*types.Func)
			if !ok || id == nil || !id.IsExported() {
				continue
			}
			sig, ok := fn.Type().(*types.Signature)
			if !ok || sig.Recv() == nil || sig.Results().Len() != 1 {
				continue
			}
			if receiverName(sig.Recv().Type()) != recv {
				continue
			}
			recvMethods++
			if underlyingName(sig.Results().At(0).Type()) == forbidden {
				violations = append(violations, recv+"."+fn.Name())
			}
		}
	}
	return violations, recvMethods
}

// receiverName strips a pointer receiver down to its type name.
func receiverName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

// underlyingName resolves an alias or named type to the basic type behind it.
func underlyingName(t types.Type) string {
	if b, ok := t.Underlying().(*types.Basic); ok {
		return b.Name()
	}
	return ""
}

// repoRoot resolves a repository-relative path from this package's directory.
func repoRoot(t *testing.T, rel string) string {
	t.Helper()
	p := filepath.Join("..", "..", rel)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("source_path %q does not resolve to %q: %v", rel, p, err)
	}
	return p
}

// syntheticFixture writes one forbidden accessor in the named declaration form.
func syntheticFixture(t *testing.T, form, recv, forbidden, method string) string {
	t.Helper()
	var body string
	switch form {
	case "direct":
		body = "func (s " + recv + ") " + method + "() " + forbidden + " { return s.v }\n"
	case "alias":
		body = "type Percentage = " + forbidden + "\n\n" +
			"func (s " + recv + ") " + method + "() Percentage { return s.v }\n"
	case "named":
		body = "type Percentage " + forbidden + "\n\n" +
			"func (s " + recv + ") " + method + "() Percentage { return Percentage(s.v) }\n"
	default:
		t.Fatalf("unknown synthetic_result_type_form %q", form)
	}
	dir := t.TempDir()
	src := "package compliance\n\ntype " + recv + " struct{ v " + forbidden + " }\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write %s fixture: %v", form, err)
	}
	return dir
}

// @spec system-compliance-scoring
// @ac AC-04
// AC-04: absence is representable in the type, not signalled by a sentinel
// number. An exported accessor returning a bare forbidden type fails, in any
// declaration form.
func TestSourceGuard_NoBareResultAccessor(t *testing.T) {
	t.Run("system-compliance-scoring/AC-04", func(t *testing.T) {
		ac := criterion(t, loadCriteria(t), "AC-04")
		in := inputsOf(t, ac)
		exp := expectationsOf(t, ac)

		dir := repoRoot(t, in.str("source_path"))
		recv := in.str("receiver_type")
		forbidden := in.str("forbidden_result_type")
		method := in.str("synthetic_method_name")
		forms := in.strList("synthetic_result_type_forms")

		// The real package is clean, and the scan actually read it.
		exp.emptyList("violations")
		got, seen := bareResultAccessors(t, dir, recv, forbidden)
		if len(got) != 0 {
			t.Errorf("violations = %v, want none", got)
		}
		if seen == 0 {
			t.Fatalf("scanned %q and found no exported methods on %s; source_path points at the wrong package, so a clean result proves nothing", dir, recv)
		}

		// The guard detects the forbidden shape in every declaration form.
		// Without this half a detector that always returned nothing would pass,
		// which is the vacuous-guard failure this spec forbids elsewhere.
		wantSym := exp.str("mutation_fixture_reported_symbol")
		if built := recv + "." + method; built != wantSym {
			t.Errorf("inputs build symbol %q but expected_output says %q", built, wantSym)
		}
		wantDetected := exp.boolean("mutation_fixture_detected")
		detectedForms := 0
		for _, form := range forms {
			detected, _ := bareResultAccessors(t, syntheticFixture(t, form, recv, forbidden, method), recv, forbidden)
			gotDetected := len(detected) > 0
			if gotDetected != wantDetected {
				t.Errorf("form %q: detected = %v, want %v", form, gotDetected, wantDetected)
				continue
			}
			if gotDetected {
				detectedForms++
				if detected[0] != wantSym {
					t.Errorf("form %q: reported symbol = %q, want %q", form, detected[0], wantSym)
				}
			}
		}
		if want := int(exp.num("forms_detected")); detectedForms != want {
			t.Errorf("detected %d of the forbidden declaration forms, want %d", detectedForms, want)
		}

		in.allConsumed()
		exp.allConsumed()
	})
}
