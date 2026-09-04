// @spec system-compliance-scoring
//
// Provenance is recorded, never reconstructed.
//
// A stored artifact says which corpus measured it. Filling that in from the
// corpus installed today would answer a question nobody asked: it would
// describe the reader's machine rather than the scan, and it would make a
// signed artifact's meaning change under it.
package server

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// liveDescriptorNames are the identifiers a live corpus descriptor would be
// reached through once features/KN-KN-030 ships DescribeCorpus.
//
// None of them exists yet, which is exactly why the guard is written now.
// The read paths are being built in this slice, and the cheapest moment to
// forbid a call is before anyone has a reason to add one.
var liveDescriptorNames = map[string]bool{
	"DescribeCorpus":      true,
	"InstalledCorpus":     true,
	"LiveCorpus":          true,
	"CurrentCorpus":       true,
	"CurrentCorpusDigest": true,
	"CorpusDescriptor":    true,
}

// liveDescriptorRefs returns every {file, symbol} in scope that reaches for a
// live corpus descriptor.
//
// It matches call expressions and selectors by identifier, so both a bare
// DescribeCorpus() and a kensa.DescribeCorpus() are found.
func liveDescriptorRefs(t *testing.T, scopes []string) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	for _, dir := range scopes {
		root := filepath.Join("..", "..", dir)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			rel := filepath.ToSlash(strings.TrimPrefix(path, "../../"))
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parse %s: %v", rel, perr)
			}
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					var name string
					switch v := n.(type) {
					case *ast.SelectorExpr:
						name = v.Sel.Name
					case *ast.Ident:
						name = v.Name
					default:
						return true
					}
					if liveDescriptorNames[name] {
						id := rel + "::" + fn.Name.Name + " -> " + name
						if !seen[id] {
							seen[id] = true
							out = append(out, id)
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(out)
	return out
}

// @ac AC-26
// AC-26: a stored artifact whose recorded corpus differs from the one
// installed today renders its recorded value, and no read path consults the
// live corpus descriptor.
func TestProvenance_NeverReconstructedFromTheInstalledCorpus(t *testing.T) {
	t.Run("system-compliance-scoring/AC-26", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-26")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		stored := in.Str("stored_artifact_corpus_digest")
		installed := in.Str("installed_corpus_digest")
		if stored == installed {
			t.Fatal("fixture stores and installs the same digest, so rendering the wrong one " +
				"would be invisible")
		}

		// The rendering half. The snapshot records its own corpus; the trend
		// must hand that value back whatever else has changed since.
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO posture_snapshots
				(host_id, snapshot_date, passing, failing, skipped, error, total,
				 score_pct, has_critical_findings, formula_version, aggregation_method,
				 engine_version, corpus_identity_status, corpus_digest)
			VALUES ($1, current_date, 8, 2, 0, 0, 10, 80.0, false, 2, 'none',
			        'v0.9.0', 'identified', $2)`, hostID, stored); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}

		day := latestTrendCorpusPoint(t, url, hostID)
		if day.Envelope.CorpusDigest == nil {
			t.Fatalf("the stored point renders no corpus digest although it recorded %q", stored)
		}
		if *day.Envelope.CorpusDigest != exp.Str("rendered_corpus_digest") {
			t.Errorf("rendered corpus_digest = %q, want %q; the artifact records which corpus "+
				"measured it, and that answer does not change when the machine changes",
				*day.Envelope.CorpusDigest, exp.Str("rendered_corpus_digest"))
		}
		if *day.Envelope.CorpusDigest == installed {
			t.Errorf("rendered corpus_digest = %q, the corpus installed now; a stored artifact "+
				"reconstructed from today's state describes the reader, not the scan", installed)
		}

		// The source half. No read path may reach a live descriptor, checked
		// over the packages the fixture scopes.
		scopes := in.StrList("source_scope")
		if len(scopes) == 0 {
			t.Fatal("fixture scopes no packages")
		}
		exp.EmptyList("read_paths_consulting_live_descriptor")
		if refs := liveDescriptorRefs(t, scopes); len(refs) != 0 {
			t.Errorf("read paths consulting a live corpus descriptor:\n  %s\nA stored "+
				"artifact's corpus is what the scan recorded, never what is installed now",
				strings.Join(refs, "\n  "))
		}

		// The detector must SEE such a call. None exists yet, so without this
		// the check above passes for the wrong reason and would keep passing
		// after KN-KN-030 gives everyone a descriptor to call.
		planted := filepath.Join("..", "..", scopes[0], "zz_livecorpus_fixture.go")
		pkg := filepath.Base(scopes[0])
		plantMissingFile(t, planted,
			"package "+pkg+"\n\n"+
				"// fixtureReadsLiveCorpus stands in for a read path that asks the\n"+
				"// installed corpus what measured a stored artifact.\n"+
				"func fixtureReadsLiveCorpus(d interface{ DescribeCorpus() string }) string {\n"+
				"\treturn d.DescribeCorpus()\n}\n")
		defer func() {
			if err := os.Remove(planted); err != nil {
				t.Errorf("remove planted fixture: %v; the tree is left dirty", err)
			}
		}()
		after := liveDescriptorRefs(t, scopes)
		found := false
		for _, r := range after {
			if strings.Contains(r, "fixtureReadsLiveCorpus") {
				found = true
			}
		}
		if !found {
			t.Errorf("the planted live-descriptor call was not reported; the guard cannot see "+
				"one and its clean result above means nothing. Detected: %v", after)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// trendCorpusPoint decodes only what this criterion asserts.
//
// The shared hostTrendDay in the neighboring file does not carry
// corpus_digest, and widening it would change what every other trend test
// decodes.
type trendCorpusPoint struct {
	Date     string `json:"date"`
	Envelope struct {
		CorpusIdentityStatus string  `json:"corpus_identity_status"`
		CorpusDigest         *string `json:"corpus_digest"`
	} `json:"envelope"`
}

// latestTrendCorpusPoint returns the most recent point of a host's trend.
func latestTrendCorpusPoint(t *testing.T, url string, hostID uuid.UUID) trendCorpusPoint {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID.String()+"/compliance/trend",
		auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET trend = %d: %s", resp.StatusCode, b)
	}
	var body struct {
		Days []trendCorpusPoint `json:"days"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode trend: %v", err)
	}
	if len(body.Days) == 0 {
		t.Fatal("the host trend is empty although a snapshot was seeded")
	}
	return body.Days[len(body.Days)-1]
}

// plantMissingFile creates a fixture file, refusing to overwrite anything.
//
// Exclusive creation rather than a plain write: a fixture that silently
// replaced real source would corrupt the tree, and on this branch the tree
// is the only copy of a great deal of uncommitted work.
func plantMissingFile(t *testing.T, path, body string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("plant %s: %v", path, err)
	}
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		t.Fatalf("write %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}
