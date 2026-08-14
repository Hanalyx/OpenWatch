// @spec system-current-corpus
//
// AC traceability:
//
//	AC-10  TestRegistry_WellFormedAndPinned
//	AC-10  TestRegistry_MatchesTheShippedList
//	AC-11  TestGuard_EveryBareTableReadIsRegistered
//	AC-11  TestGuard_IgnoresTheViewAndTheDocComments
//	AC-11  TestGuard_AtScanSQLReallyScopes
//	AC-12  TestGuard_FailsWhenItShould
//
// The completeness guard for current-corpus scoping.
//
// WHY THIS EXISTS. Eleven reads of host_rule_state across eight packages
// have to be scoped, and the plan that raised the defect named five of
// them. Patching a list one site at a time is how the twelfth site gets
// missed. So completeness is structural: any read of the BARE table that
// is not on a reviewed exception registry fails the build.
//
// Three design rules, each of which the spec calls out because getting
// it wrong makes the guard useless rather than noisy:
//
//   - The population is STRING LITERALS, parsed, not file text. A dozen
//     doc comments mention the table by name. Matching file text fills
//     the registry with noise and hides the real entries.
//   - The match is on a WORD BOUNDARY. Otherwise host_rule_state_current
//     matches as a substring and every corrected read looks like a
//     violation, which inverts the guard.
//   - It runs BOTH directions. An entry whose function no longer holds
//     such a literal is reported too, so a stale exemption cannot
//     outlive the code it excused.
//
// A guard that cannot fail is worse than none, so its negative cases are
// permanent tests rather than a momentary edit of a real file: the
// fixture sources under testdata/ hold one example of each finding, and
// the go tool ignores that directory so they never have to compile.

package corpus

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// entryState is the reason a function is permitted to name the bare
// table. There is deliberately no state meaning "not looked at yet": a
// read either uses the view, which needs no entry, or it is an exception
// a reviewer agreed to.
type entryState string

const (
	// stateRaw is a read or write that must see EVERY row, current or
	// not. The write path is the only one: it decides what the corpus is,
	// so it cannot be scoped by it.
	stateRaw entryState = "raw"
	// stateScanScoped is a read scoped to a NAMED scan rather than to the
	// current corpus. It must carry an explicit last_scan_id comparison
	// in the same literal, so the state cannot become a rubber stamp.
	stateScanScoped entryState = "scan_scoped"
)

// regEntry is one reviewed exception. Package, File, Function and Reason
// are all required; a registry entry nobody justified is not a registry
// entry, it is a list somebody maintains.
type regEntry struct {
	Package  string
	File     string // slash-separated, relative to the module root
	Function string
	State    entryState
	Reason   string
}

// finding is one guard violation, rendered for a human.
type finding struct {
	File     string
	Function string
	Message  string
}

func (f finding) String() string {
	return fmt.Sprintf("%s: %s: %s", f.File, f.Function, f.Message)
}

// bareTable matches the table name on a word boundary. The trailing \b
// is what stops host_rule_state_current from matching: the next
// character is an underscore, which is a word character, so the boundary
// does not hold there. That single character is the difference between a
// guard and a guard that flags every corrected read.
var bareTable = regexp.MustCompile(`\bhost_rule_state\b`)

// bareTableInSQL is the population the guard actually reports on: the
// table named in a SQL clause position.
//
// The narrowing is required, not a convenience. internal/retention/
// policy.go carries `{Table: "host_rule_state", ...}` as a retention
// policy key. That is a string literal naming the table and it is not a
// read, so a guard keyed on the bare name alone reports it and the
// exception registry grows an entry that excuses nothing. The spec fixes
// the registry at exactly three entries, so the population has to be
// reads.
var bareTableInSQL = regexp.MustCompile(`(?is)\b(?:FROM|JOIN|INTO|UPDATE)\s+host_rule_state\b`)

// sqlish matches a literal that reads like SQL. It exists only to close
// the hole bareTableInSQL opens: a query assembled so that the clause
// keyword and the table name land in different literals ("FROM " + tbl)
// would name the table with no clause before it and slip through
// silently. Such a literal is reported as unclassifiable rather than
// dropped, because a guard that quietly ignores what it cannot parse is
// the hiding place it was built to remove.
var sqlish = regexp.MustCompile(`(?i)\b(SELECT|FROM|JOIN|WHERE|INSERT|UPDATE|DELETE)\b`)

// atScanCall matches a call to the shared scan-scoping helper. A
// scan_scoped read may express its comparison that way instead of
// inline, which is better rather than worse: it is the same define-once
// principle the view applies to the current corpus.
//
// Accepting it does NOT weaken the check, because
// TestGuard_AtScanSQLReallyScopes asserts the helper emits a
// last_scan_id comparison. Without that assertion this would be exactly
// the rubber stamp the state exists to prevent.
var atScanCall = regexp.MustCompile(`\bAtScanSQL\s*\(`)

// lastScanIDCmp matches an explicit comparison against last_scan_id,
// which is what a scan_scoped entry has to show.
var lastScanIDCmp = regexp.MustCompile(`\blast_scan_id\s*=`)

// sqlSite is one string literal naming the bare table, with the function
// it sits in.
type sqlSite struct {
	File     string
	Function string
	Literal  string
	// FuncSrc is the source of the enclosing declaration. A scan_scoped
	// read may express its last_scan_id comparison through the shared
	// corpus.AtScanSQL helper rather than inline, and the check has to be
	// able to see that without accepting a bare claim.
	FuncSrc string
	// Unclassified marks a literal that names the table inside SQL-like
	// text but not in a clause position. It is always a finding: the
	// guard is saying it cannot tell, which a human has to resolve.
	Unclassified bool
}

// collectSites parses every non-test Go source under root and returns
// each string literal naming the bare table, attributed to its enclosing
// function.
//
// Parsing rather than reading is the point. A comment is not a string
// literal, so the doc comments drop out for free rather than needing an
// exclusion list that would itself rot.
func collectSites(t *testing.T, root string) []sqlSite {
	t.Helper()
	var sites []sqlSite
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "frontend", "dist", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		sites = append(sites, sitesInFile(t, fset, path, filepath.ToSlash(rel))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return sites
}

// sitesInFile parses one file. It is separate from collectSites so the
// fixture tests can point at a directory whose files never compile.
func sitesInFile(t *testing.T, fset *token.FileSet, path, rel string) []sqlSite {
	t.Helper()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}

	var out []sqlSite
	// enclosing names the declaration a literal sits in. A SQL literal
	// normally sits in a function; one held by a package-level var or
	// const has no enclosing function, and reporting it under the
	// identifier's own name is better than dropping it, because a query
	// hoisted to a package var is exactly how a read would slip past a
	// function-keyed registry.
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	declSrc := func(n ast.Node) string {
		lo := fset.Position(n.Pos()).Offset
		hi := fset.Position(n.End()).Offset
		if lo < 0 || hi > len(src) || lo >= hi {
			return ""
		}
		return string(src[lo:hi])
	}

	var record func(node ast.Node, enclosing string)
	record = func(node ast.Node, enclosing string) {
		enclosingSrc := declSrc(node)
		ast.Inspect(node, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				// An unparseable literal is not silently skipped: a guard
				// that quietly drops input is how a read hides.
				t.Fatalf("%s: cannot unquote literal at %s: %v", rel, fset.Position(lit.Pos()), err)
			}
			if !bareTable.MatchString(val) {
				return true
			}
			switch {
			case bareTableInSQL.MatchString(val):
				out = append(out, sqlSite{File: rel, Function: enclosing, Literal: val, FuncSrc: enclosingSrc})
			case sqlish.MatchString(val):
				// Names the table inside something that reads like SQL,
				// but not in a clause position this guard recognizes.
				// Reported rather than dropped.
				out = append(out, sqlSite{File: rel, Function: enclosing, Literal: val,
					FuncSrc: enclosingSrc, Unclassified: true})
			}
			// Anything else names the table outside SQL entirely (a
			// retention policy key, an error string) and is not a read.
			return true
		})
	}

	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			record(d, funcName(d))
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				names := make([]string, 0, len(vs.Names))
				for _, id := range vs.Names {
					names = append(names, id.Name)
				}
				record(vs, strings.Join(names, ","))
			}
		}
	}
	return out
}

// funcName renders a declaration the way the registry names it:
// "Apply" for a plain function, "Writer.Apply" for a method, so a
// registry entry can distinguish two same-named methods on different
// types in one package.
func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	typ := d.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + d.Name.Name
	}
	return d.Name.Name
}

// scopedToANamedScan reports whether a site shows its scan scoping,
// either inline in the query or by calling the shared helper.
func scopedToANamedScan(s sqlSite) bool {
	return lastScanIDCmp.MatchString(s.Literal) ||
		lastScanIDCmp.MatchString(s.FuncSrc) ||
		atScanCall.MatchString(s.FuncSrc)
}

// runGuard is the whole check. It reports a finding for every site that
// is not registered, every scan_scoped entry whose literal carries no
// last_scan_id comparison, and every registry entry that matched no
// site.
//
// It takes the sites and the registry as arguments rather than reaching
// for the tree, which is what lets the fixture tests exercise the
// negative cases for real instead of describing them.
func runGuard(sites []sqlSite, registry []regEntry) []finding {
	type key struct{ file, fn string }
	byKey := map[key]regEntry{}
	for _, e := range registry {
		byKey[key{e.File, e.Function}] = e
	}

	matched := map[key]bool{}
	var findings []finding

	for _, s := range sites {
		k := key{s.File, s.Function}
		if s.Unclassified {
			findings = append(findings, finding{s.File, s.Function,
				"names host_rule_state inside SQL-like text but not after FROM, JOIN, INTO or " +
					"UPDATE, so the guard cannot tell whether it is a read. Assemble the query so " +
					"the clause keyword and the table name sit in the same literal"})
			continue
		}
		e, registered := byKey[k]
		if !registered {
			findings = append(findings, finding{s.File, s.Function,
				"reads the bare host_rule_state table and is not in the exception registry. " +
					"A current-score read must read host_rule_state_current; if this read genuinely " +
					"needs every row, add a registry entry with a reason"})
			continue
		}
		matched[k] = true
		if e.State == stateScanScoped && !scopedToANamedScan(s) {
			findings = append(findings, finding{s.File, s.Function,
				"is registered scan_scoped but neither its query nor its enclosing function " +
					"carries a last_scan_id comparison, inline or through corpus.AtScanSQL. " +
					"scan_scoped means scoped to a NAMED scan, so the scoping has to be visible " +
					"in the code rather than claimed in the registry"})
		}
	}

	for _, e := range registry {
		if matched[key{e.File, e.Function}] {
			continue
		}
		findings = append(findings, finding{e.File, e.Function,
			"is in the exception registry but no longer contains a query naming the bare " +
				"host_rule_state table. A stale exemption must not outlive the code it excused"})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Function < findings[j].Function
	})
	return findings
}

// moduleRoot resolves the repository root from this package's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s has no go.mod: %v", root, err)
	}
	return root
}

// -------------------------------------------------------------------
// The exception registry.
// -------------------------------------------------------------------

// pinnedRegistry is the exact set of functions permitted to name the
// bare table: the write path, which decides what the corpus IS and so
// cannot be scoped by it; the two drift reads, which scope to a NAMED
// scan because drift runs before the scan is marked completed and a
// view-based read would compare the new state against itself; and the
// shared test-seed helper, which is a WRITE that the guard sees because
// it has to be a real package (test files are not importable).
//
// This list lives in the test on purpose. It is the assertion, not the
// input: a new entry has to fail here until a reviewer adds it
// deliberately. The IMPLEMENTATION registry the guard consumes is a
// separate, non-test artifact, and the test below requires the two to
// agree.
var pinnedRegistry = []regEntry{
	{
		Package: "transactionlog", File: "internal/transactionlog/writer.go",
		Function: "Writer.Apply", State: stateRaw,
		Reason: "The write path reads the prior row to decide change_kind and then UPSERTs. " +
			"A scoped prior-state read would find no row for a rule outside the current corpus, " +
			"call the result first_seen, and append a false transactions row on every scan of " +
			"every rule one run skipped.",
	},
	{
		Package: "corpustest", File: "internal/db/corpustest/corpustest.go",
		Function: "SeedRules", State: stateRaw,
		Reason: "The shared DB seed helper, and a WRITE. It INSERTs the rows whose last_scan_id " +
			"decides corpus membership, so it cannot read through the view that membership " +
			"defines. It is a package rather than a _test.go file because test files are not " +
			"importable, which is why the guard sees it as production source at all.",
	},
	{
		Package: "drift", File: "internal/drift/service.go",
		Function: "Service.readCurrentCounts", State: stateScanScoped,
		Reason: "Drift runs inside the scan job, after writer.Apply and before " +
			"scanruns.MarkCompleted, so the view still resolves to the PREVIOUS run. " +
			"Reading it would compare the new state against itself and report every scan as stable.",
	},
	{
		Package: "drift", File: "internal/drift/service.go",
		Function: "Service.reconstructPriorCounts", State: stateScanScoped,
		Reason: "Same scan window as readCurrentCounts; reconstructs the prior counts from the " +
			"rows this named scan wrote.",
	},
}

// exceptionRegistry returns the IMPLEMENTATION registry, converted to
// the guard's local shape.
//
// The guard runs against what ships, not against the test's own copy.
// pinnedRegistry is the assertion instead: TestRegistry_WellFormedAndPinned
// compares the two, so a new exception fails until a reviewer adds it
// deliberately, which is the whole point of a registry.
func exceptionRegistry(t *testing.T) []regEntry {
	t.Helper()
	out := make([]regEntry, 0, len(Registry))
	for _, e := range Registry {
		out = append(out, regEntry{
			Package:  e.Package,
			File:     e.File,
			Function: e.Function,
			State:    entryState(e.State),
			Reason:   e.Reason,
		})
	}
	return out
}

// TestRegistry_WellFormedAndPinned is the registry's own hygiene check.
//
// An entry with no reason is not a registry entry, it is a list somebody
// maintains. A duplicate (File, Function) hides one of the two from
// anyone reading the list, and a merge is exactly where a second copy
// appears.
// @ac AC-10
func TestRegistry_WellFormedAndPinned(t *testing.T) {
	t.Run("system-current-corpus/AC-10", testRegistryWellFormedAndPinned)
}

func testRegistryWellFormedAndPinned(t *testing.T) {
	reg := exceptionRegistry(t)
	if len(reg) == 0 {
		t.Fatal("the exception registry is empty; the write path must always be in it, " +
			"so an empty registry means this test is reading the wrong thing")
	}

	seen := map[string]bool{}
	for _, e := range reg {
		where := e.File + ":" + e.Function
		if strings.TrimSpace(e.Package) == "" {
			t.Errorf("%s has no Package", where)
		}
		if strings.TrimSpace(e.File) == "" || strings.TrimSpace(e.Function) == "" {
			t.Errorf("%+v has an empty File or Function; the guard keys on both", e)
		}
		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("%s carries no reason; an exemption nobody justified is not an exemption", where)
		}
		switch e.State {
		case stateRaw, stateScanScoped:
		default:
			t.Errorf("%s has State %q, want raw or scan_scoped. There is deliberately no state "+
				"meaning \"not looked at yet\"", where, e.State)
		}
		if seen[where] {
			t.Errorf("%s appears twice; a duplicate hides one entry from review", where)
		}
		seen[where] = true
	}

	// The exact set. These are the only reads permitted to see retired
	// rows, so the list must move under review rather than by accident.
	want := []string{
		"internal/db/corpustest/corpustest.go:SeedRules",
		"internal/drift/service.go:Service.readCurrentCounts",
		"internal/drift/service.go:Service.reconstructPriorCounts",
		"internal/transactionlog/writer.go:Writer.Apply",
	}
	var got []string
	for _, e := range reg {
		got = append(got, e.File+":"+e.Function)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("registry contents:\n  got:  %v\n  want: %v\n"+
			"A read added to this list sees rules no scan evaluated. Adding one is a review "+
			"decision, so this assertion is meant to fail until someone makes it.", got, want)
	}
}

// TestRegistry_MatchesTheShippedList pins the guard to the registry that
// ships rather than to the test's own copy.
//
// The two exist for different reasons and both are needed. corpus.Registry
// is what the guard consults, so it is what decides whether a read is
// excused. pinnedRegistry is what a reviewer agreed to. Comparing them is
// what makes adding an exception a decision instead of an edit.
func TestRegistry_MatchesTheShippedList(t *testing.T) {
	t.Run("system-current-corpus/AC-10", func(t *testing.T) {
		if len(Registry) == 0 {
			t.Fatal("corpus.Registry is empty; the write path must always be in it, " +
				"so an empty registry means the guard would excuse nothing and report everything")
		}
		got := keysOf(exceptionRegistry(t))
		want := keysOf(pinnedRegistry)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("corpus.Registry and the reviewed set disagree:\n  ships:    %v\n  reviewed: %v\n"+
				"An entry added to the shipped registry without being added here is an exception "+
				"nobody reviewed, and these are the only reads permitted to see retired rows.",
				got, want)
		}
	})
}

// keysOf renders a registry as sorted "file:function" keys.
func keysOf(reg []regEntry) []string {
	out := make([]string, 0, len(reg))
	for _, e := range reg {
		out = append(out, e.File+":"+e.Function)
	}
	sort.Strings(out)
	return out
}

// -------------------------------------------------------------------
// The guard over the real tree.
// -------------------------------------------------------------------

// TestGuard_EveryBareTableReadIsRegistered runs the guard over the
// module and requires that every read of the bare table is either
// corrected to the view or registered with a reason.
// @ac AC-11
func TestGuard_EveryBareTableReadIsRegistered(t *testing.T) {
	t.Run("system-current-corpus/AC-11", testEveryBareTableReadIsRegistered)
}

func testEveryBareTableReadIsRegistered(t *testing.T) {
	sites := collectSites(t, moduleRoot(t))
	if len(sites) == 0 {
		t.Fatal("the guard found no query naming host_rule_state anywhere in the tree. " +
			"The write path must always name it, so zero sites means the walker is broken, " +
			"not that the tree is clean")
	}

	for _, f := range runGuard(sites, exceptionRegistry(t)) {
		t.Errorf("%s", f)
	}
}

// TestGuard_IgnoresTheViewAndTheDocComments pins the two ways this guard
// could be wrong in the quiet direction.
//
// Matching host_rule_state_current would flag every corrected read, and
// the natural response to a guard that flags correct code is to weaken
// it. Matching file text instead of parsed literals would report the
// doc comments, which is the same failure with a different cause.
// @ac AC-11
func TestGuard_IgnoresTheViewAndTheDocComments(t *testing.T) {
	t.Run("system-current-corpus/AC-11", testGuardIgnoresViewAndComments)
}

func testGuardIgnoresViewAndComments(t *testing.T) {
	t.Run("the view name is not the bare table", func(t *testing.T) {
		for _, s := range []string{
			`SELECT * FROM host_rule_state_current WHERE host_id = $1`,
			`FROM host_rule_state_current hrs JOIN hosts h ON h.id = hrs.host_id`,
		} {
			if bareTable.MatchString(s) {
				t.Errorf("the matcher treats %q as naming the bare table; every corrected read "+
					"would be reported as a violation", s)
			}
		}
		// The same matcher must still catch the real thing, or the check
		// above passes for the wrong reason.
		if !bareTable.MatchString(`SELECT * FROM host_rule_state WHERE host_id = $1`) {
			t.Error("the matcher does not catch the bare table at all")
		}
	})

	t.Run("doc comments produce no sites", func(t *testing.T) {
		// internal/corpus/corpus.go is entirely doc comment on this
		// subject and holds no SQL naming the bare table outside
		// CurrentSQL's own fragment, so it is a live example rather than
		// a hypothetical.
		var commentOnly []string
		fset := token.NewFileSet()
		root := moduleRoot(t)
		for _, rel := range []string{
			"internal/fleetrollup/doc.go",
			"internal/drift/doc.go",
			"internal/transactionlog/doc.go",
		} {
			path := filepath.Join(root, filepath.FromSlash(rel))
			if _, err := os.Stat(path); err != nil {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			if !bareTable.MatchString(string(raw)) {
				continue // this file does not mention the table at all
			}
			commentOnly = append(commentOnly, rel)
			if got := sitesInFile(t, fset, path, rel); len(got) != 0 {
				t.Errorf("%s mentions host_rule_state only in comments, but the guard reported "+
					"%d site(s); the population must be string literals, not file text", rel, len(got))
			}
		}
		if len(commentOnly) == 0 {
			t.Fatal("no doc-comment file mentioning host_rule_state was found, so this check " +
				"passed without testing anything")
		}
	})
}

// @ac AC-11
// TestGuard_AtScanSQLReallyScopes is what makes accepting the shared
// helper safe.
//
// The guard treats a call to corpus.AtScanSQL as proof that a
// scan_scoped read is scoped. That is only true if the helper actually
// emits the comparison. If it were ever changed to return something
// else, every scan_scoped entry would keep passing on the strength of a
// function name, which is precisely the rubber stamp the state exists to
// prevent. So the delegation is verified rather than trusted.
func TestGuard_AtScanSQLReallyScopes(t *testing.T) {
	t.Run("system-current-corpus/AC-11", func(t *testing.T) {
		got := AtScanSQL("hrs", "$2")
		if !lastScanIDCmp.MatchString(got) {
			t.Fatalf("AtScanSQL(%q, %q) = %q, which carries no last_scan_id comparison. "+
				"The guard accepts a call to this helper as evidence that a scan_scoped read "+
				"is scoped; if the helper stops emitting the comparison, that evidence is false "+
				"and every scan_scoped exemption silently becomes unchecked.", "hrs", "$2", got)
		}
		if !strings.Contains(got, "hrs.") || !strings.Contains(got, "$2") {
			t.Errorf("AtScanSQL = %q, want it to use both the qualifier and the placeholder "+
				"it was given", got)
		}
	})
}

// -------------------------------------------------------------------
// The guard's own failure cases, against fixture sources.
// -------------------------------------------------------------------

// fixtureSites parses one file under testdata/. Those files are Go
// source that the go tool never builds, so they can hold exactly the
// broken shapes this guard exists to catch.
func fixtureSites(t *testing.T, name string) []sqlSite {
	t.Helper()
	path := filepath.Join("testdata", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture %s missing: %v", name, err)
	}
	return sitesInFile(t, token.NewFileSet(), path, "testdata/"+name)
}

// TestGuard_FailsWhenItShould is the check that the guard can go red.
// Without it the guard could return nothing at all and every other test
// here would still pass.
//
// Each case asserts the COUNT and the CONTENT of the findings. A count
// alone would pass if the guard reported the right number of wrong
// things, and the failure message naming the file and function is the
// only part an engineer actually uses.
// @ac AC-12
func TestGuard_FailsWhenItShould(t *testing.T) {
	t.Run("system-current-corpus/AC-12", testGuardFailsWhenItShould)
}

func testGuardFailsWhenItShould(t *testing.T) {
	t.Run("unregistered read of the bare table", func(t *testing.T) {
		sites := fixtureSites(t, "unregistered.go.txt")
		if len(sites) != 1 {
			t.Fatalf("fixture yielded %d sites, want 1; the fixture no longer describes the case", len(sites))
		}
		got := runGuard(sites, nil)
		if len(got) != 1 {
			t.Fatalf("findings = %d, want 1: %v", len(got), got)
		}
		if got[0].File != "testdata/unregistered.go.txt" || got[0].Function != "ScoreHost" {
			t.Errorf("finding does not name the offending file and function: %+v", got[0])
		}
		if !strings.Contains(got[0].Message, "exception registry") {
			t.Errorf("finding does not say why it fired: %q", got[0].Message)
		}
	})

	t.Run("a read of the view yields nothing", func(t *testing.T) {
		sites := fixtureSites(t, "corrected.go.txt")
		if len(sites) != 0 {
			t.Fatalf("a query reading host_rule_state_current was collected as %d bare-table "+
				"site(s); the word boundary is not holding: %+v", len(sites), sites)
		}
		if got := runGuard(sites, nil); len(got) != 0 {
			t.Errorf("findings = %v, want none", got)
		}
	})

	t.Run("scan_scoped without a last_scan_id comparison", func(t *testing.T) {
		sites := fixtureSites(t, "scanscoped.go.txt")
		if len(sites) != 2 {
			t.Fatalf("fixture yielded %d sites, want 2 (one honest, one rubber stamp)", len(sites))
		}
		registry := []regEntry{
			{Package: "fixture", File: "testdata/scanscoped.go.txt", Function: "PriorForScan",
				State: stateScanScoped, Reason: "compares against the scan under evaluation"},
			{Package: "fixture", File: "testdata/scanscoped.go.txt", Function: "ClaimsToBeScoped",
				State: stateScanScoped, Reason: "claims scoping it does not do"},
		}
		got := runGuard(sites, registry)
		if len(got) != 1 {
			t.Fatalf("findings = %d, want 1: %v", len(got), got)
		}
		if got[0].Function != "ClaimsToBeScoped" {
			t.Errorf("the guard flagged %q; the honest scan_scoped read must pass and only the "+
				"rubber stamp must fail: %+v", got[0].Function, got)
		}
		if !strings.Contains(got[0].Message, "last_scan_id") {
			t.Errorf("finding does not name the missing comparison: %q", got[0].Message)
		}
	})

	t.Run("a stale registry entry", func(t *testing.T) {
		// The fixture's function no longer holds a bare-table query, so
		// the entry excusing it is dead.
		registry := []regEntry{
			{Package: "fixture", File: "testdata/corrected.go.txt", Function: "ScoreHost",
				State: stateRaw, Reason: "was raw before it moved to the view"},
		}
		got := runGuard(fixtureSites(t, "corrected.go.txt"), registry)
		if len(got) != 1 {
			t.Fatalf("findings = %d, want 1 for the stale entry: %v", len(got), got)
		}
		if got[0].Function != "ScoreHost" || !strings.Contains(got[0].Message, "stale exemption") {
			t.Errorf("the guard did not report the stale entry: %+v", got[0])
		}
	})

	t.Run("a split FROM clause is reported, not dropped", func(t *testing.T) {
		sites := fixtureSites(t, "split.go.txt")
		if len(sites) != 1 || !sites[0].Unclassified {
			t.Fatalf("fixture yielded %+v, want exactly one unclassified site. A query whose "+
				"clause keyword and table name sit in different literals must not vanish", sites)
		}
		got := runGuard(sites, nil)
		if len(got) != 1 {
			t.Fatalf("findings = %d, want 1: %v", len(got), got)
		}
		if !strings.Contains(got[0].Message, "cannot tell") {
			t.Errorf("finding does not say the guard could not classify it: %q", got[0].Message)
		}
		// A registry entry must NOT excuse it. The guard is reporting
		// that it cannot tell what the read does, and an exemption for a
		// read nobody can classify is an exemption for anything.
		registry := []regEntry{
			{Package: "fixture", File: "testdata/split.go.txt", Function: "SplitQuery",
				State: stateRaw, Reason: "attempting to excuse an unclassifiable read"},
		}
		if got := runGuard(sites, registry); len(got) == 0 {
			t.Error("a registry entry silenced an unclassifiable read; the entry cannot be a " +
				"substitute for making the query readable")
		}
	})

	t.Run("a table name outside SQL is not a read", func(t *testing.T) {
		// internal/retention/policy.go carries the table as a retention
		// policy key: a string literal naming it that is not a query.
		// Reporting it would put a non-read in a registry the spec fixes
		// at three entries.
		root := moduleRoot(t)
		rel := "internal/retention/policy.go"
		path := filepath.Join(root, filepath.FromSlash(rel))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !bareTable.MatchString(string(raw)) {
			t.Fatalf("%s no longer names host_rule_state, so this check tests nothing", rel)
		}
		if got := sitesInFile(t, token.NewFileSet(), path, rel); len(got) != 0 {
			t.Errorf("%s produced %d site(s): %+v. The retention entry names the table as a "+
				"policy key, not a query", rel, len(got), got)
		}
	})

	t.Run("a registered read passes", func(t *testing.T) {
		registry := []regEntry{
			{Package: "fixture", File: "testdata/unregistered.go.txt", Function: "ScoreHost",
				State: stateRaw, Reason: "fixture: reviewed and permitted"},
		}
		if got := runGuard(fixtureSites(t, "unregistered.go.txt"), registry); len(got) != 0 {
			t.Errorf("a registered read produced findings %v; the registry does not excuse anything, "+
				"so every other case here proves nothing", got)
		}
	})
}
