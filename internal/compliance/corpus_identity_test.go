// @spec system-compliance-scoring
//
// The corpus-identity states on a score-bearing envelope, and the count
// reconciliation that ties each one to the hosts it claims to describe.
//
// The singular CorpusVersion and CorpusDigest fields are the hazard these
// tests exist for. They are convenient, they read like a fact about the
// artifact, and under every state but identified they would be a fact about
// whichever contributor happened to sort first.
package compliance

import (
	"strconv"
	"testing"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// corpusFixture is one AC's inputs read into constructor arguments.
type corpusFixture struct {
	contributors []CorpusContributor
	without      int
	hostsScored  int
}

// readCorpusFixture reads either input shape the criteria use: an explicit
// contributor list, or the identified/scored pair AC-19 states.
//
// Every key is consumed, so a renamed fixture key fails here rather than
// quietly leaving an argument at its zero value.
func readCorpusFixture(t *testing.T, in *specfixture.Fields) corpusFixture {
	t.Helper()
	out := corpusFixture{contributors: []CorpusContributor{}}

	if in.Has("contributors") {
		for _, c := range in.MapList("contributors") {
			hosts := c.Int("hosts")
			version := c.Str("corpus_version")
			out.contributors = append(out.contributors, CorpusContributor{
				Version:            &version,
				Digest:             c.Str("corpus_digest"),
				ContributorsScored: hosts,
			})
			out.hostsScored += hosts
			// The entry itself, not just the outer list. AC-36 found that the
			// parent's AllConsumed checks top-level keys only.
			c.AllConsumed()
		}
	}
	if in.Has("hosts_without_corpus_identity") {
		out.without = in.Int("hosts_without_corpus_identity")
	}
	if in.Has("hosts_with_corpus_identity") {
		// AC-19 states the identified count rather than the unidentified one.
		// Every scored host that recorded no identity is unidentified, so the
		// two must account for the whole scored population between them.
		identified := in.Int("hosts_with_corpus_identity")
		scored := in.Int("hosts_scored")
		out.without = scored - identified
		out.hostsScored = scored
		return out
	}
	if in.Has("hosts_scored") {
		out.hostsScored = in.Int("hosts_scored")
	} else {
		out.hostsScored += out.without
	}
	return out
}

// build constructs the envelope a fixture describes.
//
// Engine identity is held at "every scored host named none" so the engine
// half always reconciles. That half is AC-36's subject; here it must not be
// what makes a case pass or fail.
func (f corpusFixture) build() (Envelope, error) {
	return ScoreBearingEnvelope("all_rules", AggregationEqualHostMean,
		nil, f.hostsScored, f.contributors, f.without, f.hostsScored)
}

// assertCorpora compares the RETURNED list entry by entry.
//
// A status derived correctly from a list nobody reads still lets the list be
// wrong, and the list is the durable record: the status is only its summary.
func assertCorpora(t *testing.T, label string, got []CorpusContributor, want []*specfixture.Fields) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: corpora = %+v, want %d entries", label, got, len(want))
	}
	for i, w := range want {
		wantVersion := w.Str("corpus_version")
		if got[i].Version == nil || *got[i].Version != wantVersion {
			// Dereferenced, because a *string printed with %v is an address
			// and tells whoever reads the failure nothing.
			t.Errorf("%s: corpora[%d].corpus_version = %s, want %q",
				label, i, quoteOrNull(got[i].Version), wantVersion)
		}
		if got[i].Digest != w.Str("corpus_digest") {
			t.Errorf("%s: corpora[%d].corpus_digest = %q, want %q",
				label, i, got[i].Digest, w.Str("corpus_digest"))
		}
		if got[i].ContributorsScored != w.Int("contributors_scored") {
			t.Errorf("%s: corpora[%d].contributors_scored = %d, want %d",
				label, i, got[i].ContributorsScored, w.Int("contributors_scored"))
		}
		w.AllConsumed()
	}
}

// assertNoSingularCorpus checks the pair that must stay null outside
// identified, naming the value that would have been published.
func assertNoSingularCorpus(t *testing.T, label string, env Envelope) {
	t.Helper()
	if env.CorpusVersion != nil {
		t.Errorf("%s: corpus_version = %q under status %q; that version speaks for one "+
			"contributor and the artifact has others", label, *env.CorpusVersion, env.Status)
	}
	if env.CorpusDigest != nil {
		t.Errorf("%s: corpus_digest = %q under status %q; a digest names exactly one corpus, "+
			"so publishing one here asserts agreement the inputs do not show",
			label, *env.CorpusDigest, env.Status)
	}
}

// quoteOrNull renders an optional string for a failure message.
func quoteOrNull(s *string) string {
	if s == nil {
		return "null"
	}
	return strconv.Quote(*s)
}

func loadScoringAC(t *testing.T, id string) specfixture.Criterion {
	t.Helper()
	return specfixture.Get(t, specfixture.Load(t,
		"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), id)
}

// @ac AC-19
// AC-19: before KN-KN-030 no scan carries corpus identity, so the envelope
// says unavailable explicitly rather than omitting the fields.
func TestCorpusIdentity_UnavailableBeforeDescribeCorpus(t *testing.T) {
	t.Run("system-compliance-scoring/AC-19", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-19")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		f := readCorpusFixture(t, in)
		env, err := f.build()
		if err != nil {
			t.Fatalf("construction failed: %v", err)
		}

		if string(env.Status) != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %q, want %q",
				env.Status, exp.Str("corpus_identity_status"))
		}
		assertCorpora(t, "unavailable", env.Corpora, exp.MapList("corpora"))
		if env.HostsWithoutCorpusIdentity == nil {
			t.Fatal("hosts_without_corpus_identity is absent; unknown is null, never missing")
		}
		if *env.HostsWithoutCorpusIdentity != exp.Int("hosts_without_corpus_identity") {
			t.Errorf("hosts_without_corpus_identity = %d, want %d; every scored host that "+
				"recorded no identity must be counted, not dropped",
				*env.HostsWithoutCorpusIdentity, exp.Int("hosts_without_corpus_identity"))
		}
		exp.IsNull("corpus_version")
		exp.IsNull("corpus_digest")
		assertNoSingularCorpus(t, "unavailable", env)

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-21
// AC-21: mixed provenance. No single version or digest describes the
// artifact, and populating one from either entry is the tempting wrong
// answer this case exists to catch.
func TestCorpusIdentity_MixedPublishesNoSingularValue(t *testing.T) {
	t.Run("system-compliance-scoring/AC-21", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-21")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		f := readCorpusFixture(t, in)
		env, err := f.build()
		if err != nil {
			t.Fatalf("construction failed: %v", err)
		}

		if string(env.Status) != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %q, want %q",
				env.Status, exp.Str("corpus_identity_status"))
		}
		// Ordered by digest, which is also why the expected list reverses the
		// input order: the same content must always produce the same bytes.
		assertCorpora(t, "mixed", env.Corpora, exp.MapList("corpora"))
		if env.HostsWithoutCorpusIdentity == nil ||
			*env.HostsWithoutCorpusIdentity != exp.Int("hosts_without_corpus_identity") {
			t.Errorf("hosts_without_corpus_identity = %v, want %d",
				env.HostsWithoutCorpusIdentity, exp.Int("hosts_without_corpus_identity"))
		}
		exp.IsNull("corpus_version")
		exp.IsNull("corpus_digest")
		assertNoSingularCorpus(t, "mixed", env)

		// Named digests, not just "not nil". A guard that only checked for
		// non-nil would pass on a digest invented here.
		for _, forbidden := range exp.StrList("forbidden_corpus_digest") {
			if env.CorpusDigest != nil && *env.CorpusDigest == forbidden {
				t.Errorf("corpus_digest = %q, which is one contributor's digest presented as "+
					"the artifact's", forbidden)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-22
// AC-22: partially identified. Identified and unidentified contributors
// coexist, which is what a rollout looks like in flight and the state most
// likely to be collapsed into identified.
func TestCorpusIdentity_PartiallyIdentifiedIsNotIdentified(t *testing.T) {
	t.Run("system-compliance-scoring/AC-22", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-22")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		f := readCorpusFixture(t, in)
		env, err := f.build()
		if err != nil {
			t.Fatalf("construction failed: %v", err)
		}

		if string(env.Status) != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %q, want %q",
				env.Status, exp.Str("corpus_identity_status"))
		}
		assertCorpora(t, "partially_identified", env.Corpora, exp.MapList("corpora"))
		if env.HostsWithoutCorpusIdentity == nil ||
			*env.HostsWithoutCorpusIdentity != exp.Int("hosts_without_corpus_identity") {
			t.Errorf("hosts_without_corpus_identity = %v, want %d; the unidentified host is "+
				"the whole reason this state is not identified",
				env.HostsWithoutCorpusIdentity, exp.Int("hosts_without_corpus_identity"))
		}
		exp.IsNull("corpus_version")
		exp.IsNull("corpus_digest")
		assertNoSingularCorpus(t, "partially_identified", env)

		// Both collapses are named. One corpus in the list makes identified
		// tempting; the unidentified host makes unavailable tempting.
		for _, forbidden := range exp.StrList("forbidden_corpus_identity_status") {
			if string(env.Status) == forbidden {
				t.Errorf("corpus_identity_status collapsed to %q; one identified corpus beside "+
					"an unidentified host is neither", forbidden)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-23
// AC-23: zero scored hosts. This falls out of the unavailable row rather
// than needing a status of its own. An empty fleet is not an error and not a
// mixed corpus.
func TestCorpusIdentity_ZeroScoredHosts(t *testing.T) {
	t.Run("system-compliance-scoring/AC-23", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-23")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		f := readCorpusFixture(t, in)
		env, err := f.build()
		if err != nil {
			t.Fatalf("an empty fleet was rejected as invalid: %v; scoring nobody is a normal "+
				"answer, not a failure", err)
		}

		if string(env.Status) != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %q, want %q",
				env.Status, exp.Str("corpus_identity_status"))
		}
		assertCorpora(t, "zero_scored", env.Corpora, exp.MapList("corpora"))
		if env.HostsWithoutCorpusIdentity == nil ||
			*env.HostsWithoutCorpusIdentity != exp.Int("hosts_without_corpus_identity") {
			t.Errorf("hosts_without_corpus_identity = %v, want %d",
				env.HostsWithoutCorpusIdentity, exp.Int("hosts_without_corpus_identity"))
		}
		exp.IsNull("corpus_version")
		exp.IsNull("corpus_digest")
		assertNoSingularCorpus(t, "zero_scored", env)

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-24
// AC-24: the counts reconcile on every fixture above, checked through the
// read-side Reconciles rather than by re-deriving them here.
//
// An artifact whose two count sets do not add up is the same defect as a
// mean displayed beside pooled totals it cannot be derived from.
func TestCorpusIdentity_CountsReconcileOnEveryFixture(t *testing.T) {
	t.Run("system-compliance-scoring/AC-24", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-24")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		if !exp.Bool("sum_contributors_scored_plus_unidentified_equals_hosts_scored") {
			t.Fatal("fixture must require the counts to reconcile")
		}
		exp.EmptyList("entries_with_zero_contributors")

		ids := in.StrList("fixtures")
		if len(ids) == 0 {
			t.Fatal("fixture names no cases; a reconciliation over nothing proves nothing")
		}
		for _, id := range ids {
			other := loadScoringAC(t, id)
			f := readCorpusFixture(t, specfixture.InputsOf(t, other))
			env, err := f.build()
			if err != nil {
				t.Errorf("%s: construction failed: %v", id, err)
				continue
			}
			if !env.Reconciles(f.hostsScored) {
				t.Errorf("%s: the envelope's counts do not account for %d scored hosts",
					id, f.hostsScored)
			}
			for i, c := range env.Corpora {
				if c.ContributorsScored <= 0 {
					t.Errorf("%s: corpora[%d] claims %d scored hosts; an entry that scored "+
						"nobody still changes the status", id, i, c.ContributorsScored)
				}
			}
		}

		// The loop above cannot fail on any fixture here, because none supplies
		// a zero-contributor entry. Asserting the empty expected list therefore
		// needs the case the fixtures do not carry: feed one in and require the
		// constructor to refuse it. Without this the expectation is decorative.
		zero := corpusFixture{
			contributors: []CorpusContributor{{Digest: "aaa", ContributorsScored: 0}},
			without:      0,
			hostsScored:  0,
		}
		if _, err := zero.build(); err == nil {
			t.Error("a corpus entry claiming zero scored hosts was accepted; it scores nobody, " +
				"yet its presence in the list is what turns identified into mixed")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
