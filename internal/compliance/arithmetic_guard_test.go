// @spec system-compliance-scoring
//
// No compliance arithmetic outside this package.
package compliance

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-31
// AC-31: an arithmetic operator applied to a score field is either absent or
// registered with a reason.
//
// The Go half parses. That is not a detail: the generated client names these
// fields in prose on dozens of lines, and a textual search reports every one of
// them, so a grep-based version of this guard would be unusable and would be
// silenced rather than fixed.
func TestNoComplianceArithmeticOutsideScoringPackage(t *testing.T) {
	t.Run("system-compliance-scoring/AC-31", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-31")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		fields := map[string]bool{}
		for _, f := range in.StrList("score_field_names") {
			fields[f] = true
			// A wire field and its generated Go name are the same field.
			fields[goName(f)] = true
		}
		// Browser-only aliases. They join the TypeScript matcher and stay out
		// of the Go one: "compliance" is a frontend rename of score_pct, and
		// in Go it is the scoring package, so scanning Go for it reported
		// every compliance.ScorePctSQL(...) concatenation as a score
		// computation.
		tsFields := map[string]bool{}
		for f := range fields {
			tsFields[f] = true
		}
		for _, f := range in.StrList("ts_only_score_field_names") {
			tsFields[f] = true
		}
		scopes := in.StrList("source_scope")
		// Excluded by exact package identity. The formula lives in
		// internal/compliance, and naming it here rather than omitting it from
		// the scope keeps every other production package in view: the scope
		// read internal/server and frontend/src until 2026-09-03, and
		// internal/report carried two pooled formulas the whole time.
		excluded := map[string]bool{}
		for _, pkg := range in.StrList("excluded_packages") {
			excluded[pkg] = true
		}
		if !excluded["internal/compliance"] {
			t.Fatal("the scoring package must be excluded by identity; without it the guard " +
				"reports the definition of the formula as a violation of itself")
		}
		if rule := in.Str("ast_rule"); !strings.Contains(rule, "RESOLVES") {
			t.Fatalf("fixture rule no longer describes operand resolution: %q", rule)
		}
		regPath := in.Str("registry")
		if _, err := os.Stat(filepath.Join("..", "..", regPath)); err != nil {
			t.Fatalf("registry %s: %v", regPath, err)
		}
		// Authorization is per SITE, not per file. Keying on the filename alone
		// let any new expression inherit an existing exemption: HostsListPage
		// already carries two legitimate ones, so a compliance formula added
		// there tomorrow would have been permitted automatically.
		listed := map[string]ArithmeticSite{}
		for _, e := range ArithmeticRegistry {
			if e.Reason == "" {
				t.Errorf("%s (%s) is listed with no reason", e.File, e.Symbol)
			}
			if e.Symbol == "" || e.Expr == "" {
				t.Errorf("%s is listed with no symbol or expression; a file-shaped entry "+
					"authorizes every site in the file", e.File)
			}
			id := siteKey(e.File, e.Symbol, e.Expr)
			if prev, dup := listed[id]; dup {
				t.Errorf("duplicate registry identity %s (already listed as %q); two entries "+
					"for one site hide each other", id, prev.Reason)
			}
			listed[id] = e
		}
		exp.EmptyList("registry_entries_without_reason")

		found := scanForArithmetic(t, scopes, fields, tsFields, excluded)

		// Every named operand form must be one this guard can see. A rule that
		// matches bare identifiers only misses two of the four shapes that were
		// in the tree when this was written.
		for _, form := range in.StrList("operand_forms_that_must_match") {
			if !matchesForm(t, form, tsFields) {
				t.Errorf("the guard cannot see %q, which the criterion names as a form it "+
					"must match", form)
			}
		}

		// The postfix assertion, on BOTH sides of the operator. Adding a field
		// to the list happens to catch a right-hand operand even with the !
		// excluded from the chain, so a fixture that checked only that order
		// would have passed against the broken matcher.
		if !in.Bool("postfix_assertion_transparent") {
			t.Fatal("fixture must require the postfix assertion to be transparent")
		}
		bangDetected := 0
		for _, b := range in.MapList("bang_operand_orders") {
			expr := b.Str("expr")
			side := b.Str("side")
			b.AllConsumed()
			if tsArithFor(tsFields).MatchString(expr) {
				bangDetected++
				continue
			}
			t.Errorf("the guard cannot see %q, where the score field carries a postfix "+
				"assertion on the %s of the operator; whether a violation is detected must "+
				"not depend on operand order", expr, side)
		}
		if bangDetected != exp.Int("bang_orders_detected") {
			t.Errorf("detected %d of the postfix-assertion orders, want %d",
				bangDetected, exp.Int("bang_orders_detected"))
		}

		exp.EmptyList("ast_violations")
		exp.EmptyList("unlisted_arithmetic_sites")
		var unlisted []string
		for _, v := range found {
			if _, ok := listed[siteKey(v.file, v.symbol, v.expr)]; !ok {
				unlisted = append(unlisted, fmt.Sprintf("%s:%d %s (%s)",
					v.file, v.line, v.symbol, v.expr))
			}
		}
		if len(unlisted) != 0 {
			t.Errorf("compliance arithmetic outside %s:\n  %s\nMove it into internal/compliance, "+
				"or add the site to %s with a stated reason",
				"internal/compliance", strings.Join(unlisted, "\n  "), regPath)
		}

		// The other direction, as the corpus and skip-reason registries do it:
		// an entry whose file no longer has a site. A stale exemption must not
		// outlive the code it excused, and this check is also what makes a
		// BLINDED scanner visible. A scanner that finds nothing reports no
		// unlisted sites and looks clean; it cannot also keep every registered
		// file justified. That is the failure this guard shipped with, and
		// nothing above it would have caught it.
		withSites := map[string]bool{}
		for _, v := range found {
			withSites[siteKey(v.file, v.symbol, v.expr)] = true
		}
		for _, e := range ArithmeticRegistry {
			if !withSites[siteKey(e.File, e.Symbol, e.Expr)] {
				t.Errorf("registry lists %s %s (%s), which the scanner does not find. Either "+
					"the code changed and the entry is stale, or the scanner has gone blind "+
					"and its clean result above means nothing", e.File, e.Symbol, e.Expr)
			}
		}

		// The guard must SEE both planted shapes: a Go one and a TypeScript
		// one. Without this it passes against a broken walk or a scope pointing
		// nowhere, and the clean result above would mean nothing.
		wantN := exp.Int("mutation_fixtures_detected")
		wantFiles := exp.StrList("mutation_fixtures_reported")
		plants := in.MapList("mutation_fixtures")
		if len(plants) != wantN || len(wantFiles) != wantN {
			t.Fatalf("fixture plants %d files but expects %d detected", len(plants), wantN)
		}
		var detected []string
		for _, p := range plants {
			rel, expr := p.Str("file"), p.Str("expr")
			p.AllConsumed()
			path := filepath.Join("..", "..", rel)
			body := plantedBody(rel, expr)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("plant %s: %v", rel, err)
			}
			// Removed even if an assertion below fails, so a failing run does
			// not leave the tree dirty.
			defer func(p string) {
				if err := os.Remove(p); err != nil {
					t.Errorf("remove planted fixture %s: %v", p, err)
				}
			}(path)
		}
		for _, v := range scanForArithmetic(t, scopes, fields, tsFields, excluded) {
			for _, w := range wantFiles {
				if v.file == w {
					detected = append(detected, w)
				}
			}
		}
		for _, w := range wantFiles {
			seen := false
			for _, d := range detected {
				if d == w {
					seen = true
				}
			}
			if !seen {
				t.Errorf("the planted violation in %s was not reported; the guard cannot see "+
					"that shape and its clean result means nothing", w)
			}
		}

		// Three counterexamples the guard has to survive.

		// One: a field named ONLY in the spec must change what the scanner
		// sees. The matcher used to be a hardcoded regexp, so adding a field
		// left it unchanged while every input still looked consumed.
		probeField := in.Str("newly_supplied_field")
		if !exp.Bool("newly_supplied_field_detected") {
			t.Fatal("fixture must require a newly supplied field to be detected")
		}
		widened := map[string]bool{probeField: true}
		if !tsArithFor(widened).MatchString("a." + probeField + " * 2") {
			t.Errorf("a matcher built from the field set does not see %q; score_field_names is "+
				"decorative if the scanner carries its own copy", probeField)
		}
		if tsArithFor(fields).MatchString("a." + probeField + " * 2") {
			t.Errorf("%q matches without being supplied; the fixture cannot show the field "+
				"list is load-bearing", probeField)
		}

		// Two: two sites on one line. FindStringSubmatch reported the first and
		// hid the second.
		line := in.Str("two_sites_one_line")
		wantHits := exp.Int("two_sites_one_line_detected")
		if got := len(tsArithFor(fields).FindAllStringSubmatch(line, -1)); got != wantHits {
			t.Errorf("%q yields %d matches, want %d; a line can carry two sites and only "+
				"collecting every match reports both", line, got, wantHits)
		}

		// Three: a NEW expression inside an already registered file must be
		// rejected. This is the one a file-keyed registry let through.
		second := in.Map("second_site_in_registered_file")
		secondFile, secondExpr := second.Str("file"), second.Str("expr")
		second.AllConsumed()
		if !exp.Bool("second_site_in_registered_file_rejected") {
			t.Fatal("fixture must require a second site in a registered file to be rejected")
		}
		registeredFile := false
		for _, e := range ArithmeticRegistry {
			if e.File == secondFile {
				registeredFile = true
			}
		}
		if !registeredFile {
			t.Fatalf("%s carries no registry entry; the counterexample needs a file that "+
				"already has one", secondFile)
		}
		if _, authorized := listed[siteKey(secondFile, "zzSecondSite", secondExpr)]; authorized {
			t.Errorf("a new expression in %s is already authorized; the registry is keyed by "+
				"file rather than by site", secondFile)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

type arithSite struct {
	file   string
	line   int
	symbol string
	expr   string
}

// siteKey is a stable identity for one arithmetic site: file, enclosing symbol
// and the normalized operand. Line numbers are deliberately not part of it, so
// moving code does not invalidate a reviewed exemption, but adding a DIFFERENT
// expression to the same function does.
func siteKey(file, symbol, expr string) string {
	return file + "::" + symbol + "::" + strings.Join(strings.Fields(expr), "")
}

// goName maps a wire field to the identifier oapi-codegen generates, so
// score_pct and ScorePct are one field rather than two.
func goName(wire string) string {
	parts := strings.Split(wire, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// resolvesToScoreField reports whether an expression bottoms out in a score
// field, looking through conversions, calls, selectors, parens and indexes.
//
// Bare identifiers alone are not enough: `q.data.passing_fraction * 100` and
// `float64(passing) / float64(evaluations)` are both in the criterion's list and
// neither is a bare identifier.
func resolvesToScoreField(e ast.Expr, fields map[string]bool) (string, bool) {
	switch n := e.(type) {
	case *ast.Ident:
		if fields[n.Name] {
			return n.Name, true
		}
	case *ast.SelectorExpr:
		if fields[n.Sel.Name] {
			return n.Sel.Name, true
		}
		return resolvesToScoreField(n.X, fields)
	case *ast.CallExpr:
		for _, a := range n.Args {
			if name, ok := resolvesToScoreField(a, fields); ok {
				return name, true
			}
		}
		return resolvesToScoreField(n.Fun, fields)
	case *ast.ParenExpr:
		return resolvesToScoreField(n.X, fields)
	case *ast.IndexExpr:
		return resolvesToScoreField(n.X, fields)
	case *ast.StarExpr:
		return resolvesToScoreField(n.X, fields)
	case *ast.BinaryExpr:
		if name, ok := resolvesToScoreField(n.X, fields); ok {
			return name, true
		}
		return resolvesToScoreField(n.Y, fields)
	}
	return "", false
}

func isArithmetic(op token.Token) bool {
	switch op {
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM:
		return true
	}
	return false
}

// tsArithFor builds the TypeScript matcher FROM the supplied field set.
//
// It was a hardcoded regexp, which made score_field_names decorative: adding a
// field to the spec left the scanner unchanged while every input still looked
// consumed. The field list is the only place these names are written now.
func tsArithFor(fields map[string]bool) *regexp.Regexp {
	names := make([]string, 0, len(fields))
	for f := range fields {
		names = append(names, regexp.QuoteMeta(f))
	}
	sort.Strings(names) // deterministic pattern, so a failure is reproducible
	alt := strings.Join(names, "|")
	// The postfix non-null assertion is part of the chain. TypeScript writes
	// h.compliance! for "this is not null", and that ! is punctuation about
	// nullability, not part of the operand's identity. Leaving it out made a
	// score field invisible on the LEFT of an operator, because the matcher
	// then needed an operator directly after the name and found ! instead,
	// while the same expression with the operands swapped was caught. A guard
	// whose answer depends on which side of a plus the author wrote is not a
	// guard.
	const chain = `[A-Za-z0-9_$.\[\]!]`
	// The leading chain is OPTIONAL. Requiring a first character meant a BARE
	// identifier never matched: the class consumed the field's own first letter
	// and the word boundary then failed inside it. Only member expressions were
	// ever caught, which is half the shapes the criterion names.
	operand := `(` + chain + `*\b(?:` + alt + `)\b` + chain + `*)`
	return regexp.MustCompile(operand + `\s*[*/+\-]|` + `[*/+\-]\s*` + operand)
}

// stripTSNonCode blanks comments and string literals in ONE pass, tracking
// state as a lexer does.
//
// Two regexes cannot do this, and the failure is not theoretical: stripping
// strings first lets an apostrophe inside a comment ("the host\'s score") open a
// string that runs to the next quote hundreds of lines away, silently deleting
// the code in between. Stripping comments first lets a // inside a string
// literal delete the rest of that line. The first ordering is what this guard
// shipped with, and it hid every real site in the largest file it scanned.
//
// Newlines are preserved so reported line numbers stay true.
func stripTSNonCode(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	const (
		code = iota
		lineComment
		blockComment
		str
		regexLit
	)
	state, quote := code, byte(0)
	// lastCode is the previous non-space character emitted as code. It is what
	// tells a REGEX LITERAL from division: /failed to fetch/i is not arithmetic,
	// and without this the guard reports it and gets silenced.
	lastCode := byte(0)
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case code:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state, i = lineComment, i+1
				out.WriteString("  ")
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state, i = blockComment, i+1
				out.WriteString("  ")
			case c == '/' && regexCanStart(lastCode):
				state = regexLit
				out.WriteByte(' ')
			case c == '"' || c == '\'' || c == '`':
				state, quote = str, c
				out.WriteByte(' ')
			default:
				out.WriteByte(c)
				if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
					lastCode = c
				}
			}
		case lineComment:
			if c == '\n' {
				state = code
				out.WriteByte(c)
			} else {
				out.WriteByte(' ')
			}
		case blockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state, i = code, i+1
				out.WriteString("  ")
			} else if c == '\n' {
				out.WriteByte(c)
			} else {
				out.WriteByte(' ')
			}
		case str:
			switch {
			case c == '\\' && i+1 < len(src):
				out.WriteString("  ")
				i++
			case c == quote:
				state = code
				out.WriteByte(' ')
				lastCode = quote
			case c == '\n':
				out.WriteByte(c)
			default:
				out.WriteByte(' ')
			}
		case regexLit:
			switch {
			case c == '\\' && i+1 < len(src):
				out.WriteString("  ")
				i++
			case c == '/':
				state = code
				out.WriteByte(' ')
				lastCode = '/'
			case c == '\n':
				// An unterminated literal was not one. Newline ends it rather
				// than swallowing the rest of the file.
				state = code
				out.WriteByte(c)
			default:
				out.WriteByte(' ')
			}
		}
	}
	return out.String()
}

// scanForArithmetic walks the scoped trees for compliance arithmetic.
//
// excluded holds package paths to skip by EXACT directory identity, not by
// prefix. internal/compliance is where the formula belongs, so it is excluded
// rather than left out of the scope list; a prefix match would also silence
// any package nested beneath it, which is how an exclusion written for one
// package quietly grows to cover others.
func scanForArithmetic(t *testing.T, scopes []string, fields, tsFields map[string]bool,
	excluded map[string]bool) []arithSite {
	t.Helper()
	tsArith := tsArithFor(tsFields)
	var out []arithSite
	for _, dir := range scopes {
		root := filepath.Join("..", "..", dir)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel := filepath.ToSlash(strings.TrimPrefix(path, "../../"))
			if excluded[filepath.ToSlash(filepath.Dir(rel))] {
				return nil
			}
			switch {
			case strings.HasSuffix(path, "_test.go"):
				return nil
			case strings.HasSuffix(path, ".test.ts"), strings.HasSuffix(path, ".test.tsx"):
				return nil
			case strings.HasSuffix(path, ".go"):
				fset := token.NewFileSet()
				f, perr := parser.ParseFile(fset, path, nil, 0)
				if perr != nil {
					return fmt.Errorf("parse %s: %w", rel, perr)
				}
				// Walked per declaration so each site carries its ENCLOSING
				// symbol. Without it an exemption is file-shaped and the next
				// expression in the same file inherits it.
				for _, d := range f.Decls {
					symbol := goSymbolOf(d)
					ast.Inspect(d, func(n ast.Node) bool {
						be, ok := n.(*ast.BinaryExpr)
						if !ok || !isArithmetic(be.Op) {
							return true
						}
						name, hit := resolvesToScoreField(be.X, fields)
						if !hit {
							name, hit = resolvesToScoreField(be.Y, fields)
						}
						if hit {
							out = append(out, arithSite{
								rel, fset.Position(be.Pos()).Line, symbol, name})
						}
						return true
					})
				}
			case strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".tsx"):
				body, rerr := os.ReadFile(path)
				if rerr != nil {
					return rerr
				}
				text := stripTSNonCode(string(body))
				// EVERY match on the line, not the first. A line can carry two
				// sites, and FindStringSubmatch reports one and hides the other.
				symbol := ""
				for i, line := range strings.Split(text, "\n") {
					if name := tsSymbolOf(line); name != "" {
						symbol = name
					}
					for _, m := range tsArith.FindAllStringSubmatch(line, -1) {
						hit := m[1]
						if hit == "" {
							hit = m[2]
						}
						out = append(out, arithSite{rel, i + 1, symbol, hit})
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

// matchesForm checks the guard against one of the criterion's named shapes, by
// running the shape through the same matcher the walk uses.
func matchesForm(t *testing.T, form string, fields map[string]bool) bool {
	t.Helper()
	if e, err := parser.ParseExpr(form); err == nil {
		if be, ok := e.(*ast.BinaryExpr); ok && isArithmetic(be.Op) {
			if _, hit := resolvesToScoreField(be.X, fields); hit {
				return true
			}
			if _, hit := resolvesToScoreField(be.Y, fields); hit {
				return true
			}
		}
	}
	return tsArithFor(fields).MatchString(form)
}

func plantedBody(rel, expr string) string {
	if strings.HasSuffix(rel, ".go") {
		return "package server\n\n" +
			"func zzArithmeticFixture(passing, evaluations int) float64 {\n" +
			"\treturn " + expr + "\n}\n"
	}
	return "export function zzArithmeticFixture(q: { data: { passing_fraction: number } }) {\n" +
		"  return " + expr + ";\n}\n"
}

// goSymbolOf names the declaration a site sits in: "Name" for a function,
// "Recv.Name" for a method, and the declaration keyword otherwise.
func goSymbolOf(d ast.Decl) string {
	fd, ok := d.(*ast.FuncDecl)
	if !ok {
		return "decl"
	}
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		return recvTypeName(fd.Recv.List[0].Type) + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func recvTypeName(e ast.Expr) string {
	switch n := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(n.X)
	case *ast.Ident:
		return n.Name
	case *ast.IndexExpr:
		return recvTypeName(n.X)
	}
	return "recv"
}

// tsDecl matches the declaration forms this tree uses, so a site can name the
// one it sits in.
//
// It covers object-type KEYS as well as functions and consts, because the
// generated client is nothing but nested type literals: without that branch a
// site in schema.d.ts gets an EMPTY symbol, and an empty symbol is a
// file-shaped identity, which is the thing these registries exist to stop.
var tsDecl = regexp.MustCompile(
	`^\s*(?:export\s+)?(?:default\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)|` +
		`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*[:=]|` +
		`^\s*(?:export\s+)?(?:interface|type|class)\s+([A-Za-z_$][A-Za-z0-9_$]*)|` +
		`^\s*([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:\s*\{\s*$`)

func tsSymbolOf(line string) string {
	m := tsDecl.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

// regexCanStart reports whether a / at this point opens a regex literal rather
// than dividing.
//
// It is the standard heuristic: a regex may follow an operator, an opening
// bracket, a comma, a keyword boundary or the start of input, but not an
// identifier, a number or a closing bracket, which is where division follows.
func regexCanStart(lastCode byte) bool {
	switch lastCode {
	case 0, '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '/', '%',
		'<', '>', '~', '^', "\n"[0]:
		return true
	}
	return false
}
