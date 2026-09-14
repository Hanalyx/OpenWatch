// @spec system-compliance-scoring
//
// Every reader of skip_reason is on the registry, by FILE AND SYMBOL, and
// nothing on it feeds a score.
package compliance

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/isotree"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// readerID is a stable identity for one reader: file plus enclosing symbol.
//
// Keying on the FILE alone was the original defect. internal/scanresult/reader.go
// holds two registered readers, so one entry silently overwrote the other, and
// removing either symbol still passed while the other mention remained. That is
// not the file-and-symbol rule the criterion states.
type readerID struct {
	File   string
	Symbol string
}

func (r readerID) String() string { return r.File + "::" + r.Symbol }

// @ac AC-17
// AC-17: unlisted readers of skip_reason fail the build, named by file and
// symbol.
//
// The guard runs BOTH ways and, at the end, runs its own detector again against
// a planted reader. Reading the planted file back and checking it contains the
// text proves the fixture was written, not that the detector can see it.
func TestSkipReason_EveryReaderIsRegistered(t *testing.T) {
	t.Run("system-compliance-scoring/AC-17", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-17")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		regPath := in.Str("registry")
		if _, err := os.Stat(filepath.Join("..", "..", regPath)); err != nil {
			t.Fatalf("registry %s: %v", regPath, err)
		}
		scopes := in.StrList("source_scope")
		repoRoot := filepath.Join("..", "..")

		listed := map[readerID]SkipReasonReader{}
		for _, e := range SkipReasonRegistry {
			if e.Reason == "" {
				t.Errorf("%s is listed with no reason; an exemption nobody justified is "+
					"indistinguishable from an oversight", readerID{e.File, e.Symbol})
			}
			// FeedsScore is a defect, not a permission, until KN-OW-021 types
			// the reasons. Nothing may derive a number from untyped prose.
			if e.FeedsScore {
				t.Errorf("%s claims FeedsScore; no score or coverage number may depend on "+
					"untyped skip prose in this version", readerID{e.File, e.Symbol})
			}
			id := readerID{e.File, e.Symbol}
			if prev, dup := listed[id]; dup {
				t.Errorf("duplicate registry identity %s (already listed as %q); two entries "+
					"for one reader hide each other", id, prev.Reason)
			}
			listed[id] = e
		}
		exp.EmptyList("readers_feeding_a_score")

		found := skipReasonReaders(t, repoRoot, scopes, regPath)

		exp.EmptyList("unlisted_readers")
		var unlisted []string
		for _, id := range found {
			if _, ok := listed[id]; !ok {
				unlisted = append(unlisted, id.String())
			}
		}
		sort.Strings(unlisted)
		if len(unlisted) != 0 {
			t.Errorf("unlisted readers of skip_reason:\n  %s\nAdd each to %s with a stated "+
				"purpose, or stop reading the column there",
				strings.Join(unlisted, "\n  "), regPath)
		}
		// The other direction, on the SAME identity. A registry keyed by file
		// could not see a removed symbol while another mention in the file
		// remained.
		inTree := map[readerID]bool{}
		for _, id := range found {
			inTree[id] = true
		}
		for id, e := range listed {
			if !inTree[id] {
				t.Errorf("registry lists %s, which the detector does not find. Either the "+
					"code changed and the entry is stale, or the detector has gone blind and "+
					"its clean result above means nothing (reason on file: %q)", id, e.Reason)
			}
		}

		// The detector must SEE a planted reader. This RE-RUNS it rather than
		// re-reading the file: reading the fixture back proves it was written,
		// which is a fact about os.WriteFile, not about the guard.
		if !exp.Bool("mutation_fixture_detected") {
			t.Fatal("fixture must require the planted reader to be detected")
		}
		wantSymbol := exp.Str("mutation_fixture_reported_symbol")
		if !strings.Contains(in.Str("mutation_fixture"), "internal/compliance") {
			t.Fatalf("fixture plants its reader elsewhere: %q", in.Str("mutation_fixture"))
		}
		pkgPath, fn, ok := strings.Cut(wantSymbol, ".")
		if !ok {
			t.Fatalf("fixture symbol %q is not package.Symbol", wantSymbol)
		}
		// Planted in a PRIVATE COPY of the scopes, not in the checkout. Writing
		// into the live tree races any test that walks it at the same moment:
		// the retention sweeper guard failed a documentation-only pull request
		// exactly that way (CP bugs/OW-036). The copy lives under t.TempDir(),
		// outside the repository, so a repository-rooted walk never sees it and
		// nothing is left behind if this test dies before its cleanup.
		copyRoot := isotree.Copy(t, repoRoot, scopes...)
		planted := filepath.Join(copyRoot, pkgPath, "zz_skipreason_fixture.go")
		plantExclusive(t, planted,
			"package compliance\n\n"+
				"// "+fn+" reads SkipReason and is on no registry.\n"+
				"func "+fn+"(s struct{ SkipReason string }) string {\n\treturn s.SkipReason\n}\n")

		wantID := readerID{filepath.ToSlash(filepath.Join(pkgPath, "zz_skipreason_fixture.go")), fn}
		var after []string
		detected := false
		for _, id := range skipReasonReaders(t, copyRoot, scopes, regPath) {
			after = append(after, id.String())
			if id == wantID {
				detected = true
			}
		}
		if !detected {
			sort.Strings(after)
			t.Errorf("the planted reader %s was not reported by the detector; its clean result "+
				"above means nothing. Detected: %v", wantID, after)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// skipReasonReaders returns every {file, symbol} that reads skip_reason.
//
// Go is parsed, so the enclosing function or struct type names the symbol.
// TypeScript is scanned with the enclosing declaration tracked, which is the
// same instrument the arithmetic guard uses and carries the same limits.
func skipReasonReaders(t *testing.T, root string, scopes []string, regPath string) []readerID {
	t.Helper()
	var out []readerID
	seen := map[readerID]bool{}
	add := func(id readerID) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	mentions := func(s string) bool {
		return strings.Contains(s, "skip_reason") || strings.Contains(s, "SkipReason")
	}

	for _, dir := range scopes {
		scopeRoot := filepath.Join(root, dir)
		err := filepath.Walk(scopeRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			relPath, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			rel := filepath.ToSlash(relPath)
			// The registry and this guard describe the rule rather than reading
			// the value.
			if rel == regPath || strings.HasSuffix(path, "_test.go") ||
				strings.Contains(rel, ".test.ts") {
				return nil
			}
			switch {
			case strings.HasSuffix(path, ".go"):
				fset := token.NewFileSet()
				f, perr := parser.ParseFile(fset, path, nil, 0)
				if perr != nil {
					return fmt.Errorf("parse %s: %w", rel, perr)
				}
				for _, d := range f.Decls {
					switch n := d.(type) {
					case *ast.FuncDecl:
						if declMentions(fset, path, n.Pos(), n.End(), mentions) {
							add(readerID{rel, goSymbolOf(n)})
						}
					case *ast.GenDecl:
						// A struct field carrying the value is a reader too:
						// Type.Field, so removing one field is visible even
						// when the type keeps others.
						for _, spec := range n.Specs {
							ts, ok := spec.(*ast.TypeSpec)
							if !ok {
								continue
							}
							st, ok := ts.Type.(*ast.StructType)
							if !ok {
								continue
							}
							for _, fld := range st.Fields.List {
								for _, name := range fld.Names {
									if mentions(name.Name) ||
										(fld.Tag != nil && mentions(fld.Tag.Value)) {
										add(readerID{rel, ts.Name.Name + "." + name.Name})
									}
								}
							}
						}
					}
				}
			case strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".tsx"):
				body, rerr := os.ReadFile(path)
				if rerr != nil {
					return rerr
				}
				text := stripTSNonCode(string(body))
				symbol := ""
				for _, line := range strings.Split(text, "\n") {
					if name := tsSymbolOf(line); name != "" {
						symbol = name
					}
					if mentions(line) {
						add(readerID{rel, symbol})
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// declMentions reports whether the source spanned by a declaration mentions the
// column or field.
func declMentions(fset *token.FileSet, path string, from, to token.Pos, mentions func(string) bool) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	start, end := fset.Position(from).Offset, fset.Position(to).Offset
	if start < 0 || end > len(body) || start >= end {
		return false
	}
	return mentions(string(body[start:end]))
}
