// Spec registry completeness. specter.yaml gates AC coverage only for the specs
// it lists, so a spec file that never gets added to the registry is silently
// ungated — its acceptance criteria are never enforced. This exact drift
// accumulated to 27 unregistered specs before scripts/repo-facts.sh surfaced it
// (see PR #722). This test makes the registry and the spec/ tree agree on every
// build, in both directions:
//   - every specs/**/*.spec.yaml `id:` MUST be listed in specter.yaml (no ungated spec)
//   - every id listed in specter.yaml MUST have a spec file (no dangling entry)
package packaging_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// specFileID matches the spec-level `id:` (first one in the file, a 2+-space
// indented child of `spec:`). Spec ids are lowercase, hyphenated
// (e.g. system-auth-identity); AC ids (`- id: AC-01`) never match this shape.
var specFileID = regexp.MustCompile(`(?m)^\s+id:\s*"?([a-z][a-z0-9-]+)"?\s*$`)

// registryItem matches a `- <spec-id>` list entry inside specter.yaml's specs: block.
var registryItem = regexp.MustCompile(`^\s+-\s+([a-z][a-z0-9-]+)\s*$`)

// specIDsOnDisk returns spec id -> relative file path for every specs/**/*.spec.yaml.
func specIDsOnDisk(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	specsDir := filepath.Join(root, "specs")
	err := filepath.WalkDir(specsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".spec.yaml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		m := specFileID.FindSubmatch(raw)
		rel, _ := filepath.Rel(root, path)
		if m == nil {
			t.Errorf("spec file has no parseable spec-level `id:`: %s", rel)
			return nil
		}
		id := string(m[1])
		if prev, dup := out[id]; dup {
			t.Errorf("duplicate spec id %q in %s and %s", id, prev, rel)
		}
		out[id] = rel
		return nil
	})
	if err != nil {
		t.Fatalf("walk specs/: %v", err)
	}
	return out
}

// registeredSpecIDs returns the set of ids listed under specter.yaml's specs: block.
func registeredSpecIDs(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "specter.yaml"))
	if err != nil {
		t.Fatalf("read specter.yaml: %v", err)
	}
	reg := map[string]bool{}
	inSpecs := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// A column-0 key (e.g. `settings:`) ends the specs: block.
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			break
		}
		if m := registryItem.FindStringSubmatch(line); m != nil {
			reg[m[1]] = true
		}
	}
	if len(reg) == 0 {
		t.Fatal("parsed 0 registered specs from specter.yaml — parser or format changed")
	}
	return reg
}

func TestSpecRegistry_MatchesSpecFiles(t *testing.T) {
	root := repoRootForLinks(t) // shared helper (packaging/tests/docs_links_test.go)

	onDisk := specIDsOnDisk(t, root)
	registered := registeredSpecIDs(t, root)

	var unregistered []string
	for id, rel := range onDisk {
		if !registered[id] {
			unregistered = append(unregistered, id+"  ("+rel+")")
		}
	}
	if len(unregistered) > 0 {
		sort.Strings(unregistered)
		t.Errorf("%d spec file(s) are NOT registered in specter.yaml (their ACs are ungated) — add each id to the domain's `specs:` list:\n  %s",
			len(unregistered), strings.Join(unregistered, "\n  "))
	}

	var dangling []string
	for id := range registered {
		if _, ok := onDisk[id]; !ok {
			dangling = append(dangling, id)
		}
	}
	if len(dangling) > 0 {
		sort.Strings(dangling)
		t.Errorf("%d id(s) in specter.yaml have no spec file (dangling registry entry) — remove them or restore the file:\n  %s",
			len(dangling), strings.Join(dangling, "\n  "))
	}
}
