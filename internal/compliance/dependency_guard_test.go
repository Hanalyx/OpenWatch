// @spec system-compliance-scoring
//
// The scoring package's purity, checked against its real transitive imports.
package compliance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/isotree"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-30
// AC-30: the scoring package imports no database, server or engine.
//
// It reads `go list -deps`, not the import block. A direct-import scan sees
// nothing wrong with importing a package that itself opens a database, and the
// point of the constraint is that this package can be tested without one.
func TestCompliancePackage_HasNoForbiddenDependencies(t *testing.T) {
	t.Run("system-compliance-scoring/AC-30", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-30")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		scope := in.List("source_scope")
		if len(scope) != 1 {
			t.Fatalf("fixture names %d packages, want 1", len(scope))
		}
		pkg, _ := scope[0].(string)
		forbidden := in.StrList("forbidden_import_prefixes")
		// The rule text names go list -deps and says why. Reading it keeps the
		// criterion from drifting into describing a different instrument.
		if rule := in.Str("rule"); !strings.Contains(rule, "go list -deps") {
			t.Fatalf("fixture rule no longer names go list -deps: %q", rule)
		}

		// deps runs go list from a module ROOT the caller names. The clean scan
		// runs from the real repository; the planted scan runs from a private
		// copy, so nothing is written into the checkout (CP bugs/OW-036).
		deps := func(root, dir string) []string {
			t.Helper()
			cmd := exec.Command("go", "list", "-deps", "./"+strings.TrimPrefix(dir, "internal/"))
			cmd.Dir = filepath.Join(root, "internal")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -deps %s: %v", dir, err)
			}
			return strings.Split(strings.TrimSpace(string(out)), "\n")
		}
		violations := func(list []string) []string {
			var bad []string
			for _, d := range list {
				for _, p := range forbidden {
					if d == p || strings.HasPrefix(d, p+"/") {
						bad = append(bad, d)
					}
				}
			}
			return bad
		}

		exp.EmptyList("violations")
		repoRoot := filepath.Join("..", "..")
		if bad := violations(deps(repoRoot, pkg)); len(bad) != 0 {
			t.Errorf("%s transitively imports %v; the scoring package must be testable with no "+
				"database, server or engine", pkg, bad)
		}

		// The guard has to be able to SEE a violation. Without this the test
		// passes against a broken matcher, an empty dependency list, or a
		// forbidden list that no longer matches how Go spells these paths.
		if !exp.Bool("mutation_fixture_detected") {
			t.Fatal("fixture must require the planted violation to be detected")
		}
		wantImport := exp.Str("mutation_fixture_reported_import")
		// database/sql on purpose, per the fixture: a fixture importing
		// internal/server would fail as an import CYCLE once the server imports
		// this package, which is a pass for the wrong reason.
		if !strings.Contains(in.Str("mutation_fixture"), wantImport) {
			t.Fatalf("fixture's planted import is not %q", wantImport)
		}
		// The chain, not a direct import. A file importing database/sql directly
		// is found by a direct-import scan too, so it would pass a guard that
		// never runs go list -deps and prove nothing about the instrument this
		// criterion names. The intermediary is what makes only transitive
		// inspection succeed.
		// Planted in a PRIVATE COPY of the module, never the checkout. go.mod,
		// go.sum and internal/ are enough for go list -deps: external modules
		// resolve from the module cache, internal ones from the copy. Writing
		// into the live tree raced the retention sweeper guard's tree walk
		// under -p 4 (CP bugs/OW-036); the copy lives under t.TempDir(),
		// outside the repository, so no walk can see it.
		copyRoot := isotree.Copy(t, repoRoot, "internal")
		fixtureDir := filepath.Join(copyRoot, pkg, "zzdepfixture")
		if err := os.Mkdir(fixtureDir, 0o755); err != nil {
			t.Fatalf("create fixture package dir: %v", err)
		}
		// Exclusive creation on every planted file, so a stray file at the
		// path is refused rather than overwritten.
		plantExclusive(t, filepath.Join(fixtureDir, "fixture.go"),
			"package zzdepfixture\n\nimport _ \""+wantImport+"\"\n")
		plantExclusive(t, filepath.Join(copyRoot, pkg, "zz_dependency_guard_fixture.go"),
			"package compliance\n\nimport _ \"github.com/Hanalyx/openwatch/"+pkg+"/zzdepfixture\"\n")

		// The intermediary itself must NOT match the forbidden list, or the guard
		// would fire on the wrong package and the chain would go untested.
		intermediary := "github.com/Hanalyx/openwatch/" + pkg + "/zzdepfixture"
		for _, f := range forbidden {
			if intermediary == f || strings.HasPrefix(intermediary, f+"/") {
				t.Fatalf("the fixture intermediary %q matches forbidden prefix %q; it must be "+
					"reachable only through its own import of %s", intermediary, f, wantImport)
			}
		}

		bad := violations(deps(copyRoot, pkg))
		found := false
		for _, b := range bad {
			if b == wantImport {
				found = true
			}
		}
		if !found {
			t.Errorf("the planted %q import was not reported; the guard cannot see a violation "+
				"and its clean result above means nothing. Reported: %v", wantImport, bad)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// plantExclusive writes a fixture file, refusing to touch an existing one.
//
// os.WriteFile truncates. If anything already sits at a fixture path, a guard
// using it would overwrite that file and then delete it in its own cleanup,
// destroying work while reporting a pass.
func plantExclusive(t *testing.T, path, body string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("plant %s: %v; refusing to overwrite an existing file", path, err)
	}
	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		t.Fatalf("write %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}
