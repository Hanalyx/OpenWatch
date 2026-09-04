// @spec system-compliance-scoring
//
// The frozen provenance on a signed artifact, and what a signed artifact
// from before the formula change is still allowed to be.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

func scoringAC(t *testing.T, id string) specfixture.Criterion {
	t.Helper()
	return specfixture.Get(t, specfixture.Load(t,
		"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), id)
}

// sampleEnvelope builds a score-bearing envelope with one engine, which is
// the shape every generated artifact has until KN-KN-030 ships corpus
// identity.
func sampleEnvelope(t *testing.T) (compliance.Envelope, compliance.Aggregate) {
	t.Helper()
	agg := compliance.MeanOfHostScores([]compliance.Score{
		compliance.HostScore(compliance.Counts{Pass: 9, Fail: 1}),
		compliance.HostScore(compliance.Counts{Pass: 1, Fail: 1}),
	})
	env, err := compliance.ScoreBearingEnvelope("all_rules", compliance.AggregationEqualHostMean,
		[]compliance.EngineContributor{{EngineVersion: "v0.9.0", ContributorsScored: 2}},
		0, nil, agg.HostsScored, agg.HostsScored)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return env, agg
}

// keysOf returns every key present in a marshaled document, at any depth.
func keysOf(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	var walk func(json.RawMessage)
	walk = func(m json.RawMessage) {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(m, &obj); err == nil {
			for k, v := range obj {
				out[k] = v
				walk(v)
			}
			return
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(m, &arr); err == nil {
			for _, v := range arr {
				walk(v)
			}
		}
	}
	walk(raw)
	return out
}

// @ac AC-18
// AC-18: envelope completeness on a score-bearing artifact. Serializing one
// with any envelope field absent fails, and a value that is unknown is null
// and never an empty string.
func TestProvenance_EnvelopeIsComplete(t *testing.T) {
	t.Run("system-compliance-scoring/AC-18", func(t *testing.T) {
		ac := scoringAC(t, "AC-18")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		env, agg := sampleEnvelope(t)
		prov := NewScoreProvenance(env, agg)

		kinds := in.StrList("artifact_kinds")
		if len(kinds) == 0 {
			t.Fatal("fixture names no artifact kinds")
		}
		for _, kind := range kinds {
			raw, err := json.Marshal(contentForKind(t, Kind(kind), prov))
			if err != nil {
				t.Fatalf("%s: marshal: %v", kind, err)
			}
			present := keysOf(t, raw)
			for _, field := range exp.StrList("required_fields") {
				v, ok := present[field]
				if !ok {
					t.Errorf("%s: envelope field %q is absent; every field is present and an "+
						"unknown value is null, because an absent field and a null one are "+
						"different claims to whoever verifies the artifact later", kind, field)
					continue
				}
				// An empty string is the sentinel decision 08 exists to
				// forbid: bugs/OW-009 is where an empty non-nil value became
				// indistinguishable from a real one.
				if string(v) == `""` {
					t.Errorf("%s: envelope field %q is an empty string; a missing value is "+
						"null, never \"\"", kind, field)
				}
			}
			// Read first. Inside the Errorf argument it is only evaluated when
			// the assertion FAILS, so a passing run never consumed it.
			wantFormula := exp.Int("formula_version")
			if got := present["formula_version"]; string(got) != strconv.Itoa(wantFormula) {
				t.Errorf("%s: formula_version = %s, want %d", kind, got, wantFormula)
			}
		}
		exp.EmptyList("empty_string_values")

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// contentForKind wraps a provenance envelope in the content shape a kind
// stores, so the assertions run against the document that is actually
// signed rather than against the envelope struct alone.
func contentForKind(t *testing.T, kind Kind, prov *ScoreProvenance) any {
	t.Helper()
	switch kind {
	case KindAttestation:
		return AttestationContent{Rollup: AttestationRollup{Provenance: prov}}
	case KindExecutive, "":
		return ExecutiveContent{Provenance: prov}
	}
	t.Fatalf("kind %q is not score-bearing", kind)
	return nil
}

// @ac AC-33
// AC-33: signed report kinds carry the envelope their content justifies.
// executive and attestation compute a fleet score; exception and
// remediation aggregate no scan set at all.
func TestProvenance_ArtifactClassPerReportKind(t *testing.T) {
	t.Run("system-compliance-scoring/AC-33", func(t *testing.T) {
		ac := scoringAC(t, "AC-33")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		env, agg := sampleEnvelope(t)
		prov := NewScoreProvenance(env, agg)
		readModel := NewReadModelProvenance()

		for _, kind := range in.StrList("kinds") {
			want := exp.Map(kind)
			var raw []byte
			var err error
			switch Kind(kind) {
			case KindExecutive:
				raw, err = json.Marshal(ExecutiveContent{
					ScorePct: scorePtr(agg.Score), Provenance: prov})
			case KindAttestation:
				raw, err = json.Marshal(AttestationContent{
					Rollup: AttestationRollup{ScorePct: scorePtr(agg.Score), Provenance: prov}})
			case KindException:
				raw, err = json.Marshal(ExceptionContent{
					Exceptions: []ExceptionRow{}, Provenance: readModel})
			case KindRemediation:
				raw, err = json.Marshal(RemediationContent{
					Activities: []RemediationActRow{}, Provenance: readModel})
			default:
				t.Fatalf("fixture names unknown kind %q", kind)
			}
			if err != nil {
				t.Fatalf("%s: marshal: %v", kind, err)
			}
			present := keysOf(t, raw)

			if got := present["artifact_class"]; string(got) != `"`+want.Str("artifact_class")+`"` {
				t.Errorf("%s: artifact_class = %s, want %q",
					kind, got, want.Str("artifact_class"))
			}
			if want.Has("full_envelope") {
				if !want.Bool("full_envelope") {
					t.Fatalf("%s: fixture asks for a partial score-bearing envelope", kind)
				}
				wantFormula := want.Int("formula_version")
				if got := present["formula_version"]; string(got) != strconv.Itoa(wantFormula) {
					t.Errorf("%s: formula_version = %s, want %d", kind, got, wantFormula)
				}
				if got := present["aggregation_method"]; string(got) !=
					`"`+want.Str("aggregation_method")+`"` {
					t.Errorf("%s: aggregation_method = %s, want %q",
						kind, got, want.Str("aggregation_method"))
				}
				want.AllConsumed()
				continue
			}

			// The read-model half.
			if got := present["corpus_identity_status"]; string(got) !=
				`"`+want.Str("corpus_identity_status")+`"` {
				t.Errorf("%s: corpus_identity_status = %s, want %q; the word is not_applicable "+
					"because corpus identity does not APPLY to a read model rather than being "+
					"missing from it", kind, got, want.Str("corpus_identity_status"))
			}
			// Present AND null, not omitted. Decision 06 says these two are
			// always present; omitting them would narrow it silently.
			want.IsNull("corpus_version")
			want.IsNull("corpus_digest")
			for _, field := range []string{"corpus_version", "corpus_digest"} {
				got, ok := present[field]
				if !ok {
					t.Errorf("%s: %q is omitted; a read model carries it as an explicit null",
						kind, field)
					continue
				}
				if string(got) != "null" {
					t.Errorf("%s: %q = %s, want null", kind, field, got)
				}
			}
			for _, field := range want.StrList("absent_fields") {
				if _, ok := present[field]; ok {
					t.Errorf("%s: carries %q, which has no referent on an artifact that "+
						"aggregates no scan set", kind, field)
				}
			}
			want.AllConsumed()
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-25
// AC-25: envelope ordering is deterministic, so the same content always
// produces the same bytes and therefore the same signature.
func TestProvenance_CanonicalPayloadIsOrderIndependent(t *testing.T) {
	t.Run("system-compliance-scoring/AC-25", func(t *testing.T) {
		ac := scoringAC(t, "AC-25")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		read := func(key string) []compliance.CorpusContributor {
			out := []compliance.CorpusContributor{}
			for _, c := range in.MapList(key) {
				v := c.Str("corpus_version")
				out = append(out, compliance.CorpusContributor{
					Version:            &v,
					Digest:             c.Str("corpus_digest"),
					ContributorsScored: c.Int("contributors_scored"),
				})
				c.AllConsumed()
			}
			return out
		}
		// Hoisted: in.Map returns a fresh reader each call, so consuming keys
		// on one instance leaves another unread and the criterion looks
		// half-asserted.
		pinned := in.Map("pinned")
		generatedAt := pinned.Str("generated_at")
		artifactID := pinned.Str("artifact_id")
		pinned.AllConsumed()

		build := func(contributors []compliance.CorpusContributor) []byte {
			scored := 0
			for _, c := range contributors {
				scored += c.ContributorsScored
			}
			env, err := compliance.ScoreBearingEnvelope("all_rules",
				compliance.AggregationEqualHostMean, nil, scored, contributors, 0, scored)
			if err != nil {
				t.Fatalf("envelope: %v", err)
			}
			// Generation time and artifact id are pinned by the fixture, so
			// the only variable left is contributor input order.
			doc := struct {
				GeneratedAt string           `json:"generated_at"`
				ArtifactID  string           `json:"artifact_id"`
				Provenance  *ScoreProvenance `json:"provenance"`
			}{
				GeneratedAt: generatedAt,
				ArtifactID:  artifactID,
				Provenance: NewScoreProvenance(env,
					compliance.Aggregate{HostsTotal: scored, HostsScored: scored}),
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			return raw
		}

		if in.Str("compare") != "canonical_signed_payload" {
			t.Fatalf("fixture compares %q", in.Str("compare"))
		}
		first := build(read("contributors_order_1"))
		second := build(read("contributors_order_2"))

		if !exp.Bool("payloads_byte_identical") {
			t.Fatal("fixture must require byte-identical payloads")
		}
		if string(first) != string(second) {
			t.Errorf("the two payloads differ:\n  %s\n  %s\nA signature is taken over these "+
				"bytes, so contributor input order deciding them would make one artifact "+
				"verify and an identical one fail", first, second)
		}
		// Named order, not merely equality. Two payloads could agree on a
		// wrong order and this check would pass.
		var got struct {
			Provenance struct {
				Corpora []struct {
					Digest string `json:"corpus_digest"`
				} `json:"corpora"`
			} `json:"provenance"`
		}
		if err := json.Unmarshal(first, &got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		wantOrder := exp.StrList("corpora_digest_order")
		if len(got.Provenance.Corpora) != len(wantOrder) {
			t.Fatalf("corpora = %+v, want %d entries", got.Provenance.Corpora, len(wantOrder))
		}
		for i, w := range wantOrder {
			if got.Provenance.Corpora[i].Digest != w {
				t.Errorf("corpora[%d].corpus_digest = %q, want %q; entries are sorted by digest "+
					"before signing", i, got.Provenance.Corpora[i].Digest, w)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-34
// AC-34: an artifact signed before this change carries no artifact_class and
// stays valid and unrewritten.
//
// A discriminated contract that invalidated its own history would be worse
// than the ambiguity it replaced.
func TestProvenance_LegacyArtifactStaysValidAndUnrewritten(t *testing.T) {
	t.Run("system-compliance-scoring/AC-34", func(t *testing.T) {
		ac := scoringAC(t, "AC-34")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		if in.Str("legacy_shape_amended") == "" {
			t.Fatal("fixture must record when the legacy shape was settled")
		}
		pct := 53
		legacy := legacyExecutiveContent{
			CompliancePct:   &pct,
			HostCount:       7,
			PassingRules:    8,
			FailingRules:    2,
			TopFailingRules: []TopFailingRule{},
			Coverage:        Coverage{HostsTotal: 7, HostsFresh: 7},
		}
		signedBytes, err := json.Marshal(legacy)
		if err != nil {
			t.Fatalf("marshal legacy: %v", err)
		}
		sum := sha256.Sum256(signedBytes)
		signedSHA := hex.EncodeToString(sum[:])

		present := keysOf(t, signedBytes)
		for _, field := range in.StrList("legacy_artifact_fields_present") {
			if _, ok := present[field]; !ok {
				t.Errorf("the legacy fixture does not carry %q, so it is not the shape this "+
					"criterion is about", field)
			}
		}
		for _, field := range in.StrList("legacy_artifact_fields_absent") {
			if _, ok := present[field]; ok {
				t.Errorf("the legacy fixture carries %q; a legacy artifact predates that field "+
					"and nothing adds one", field)
			}
		}
		in.Str("legacy_artifact_sha256")

		// It is recognized as legacy by the ABSENCE of artifact_class, which
		// is the only test. Nothing infers it from which score field is set.
		if !isLegacyArtifact(string(KindExecutive), signedBytes) {
			t.Fatal("an artifact with no artifact_class was not recognized as legacy; every " +
				"guarantee below rests on that recognition")
		}
		// And it is not rejected for carrying compliance_pct. That rejection
		// applies to a CURRENT artifact carrying both.
		if err := checkScoreFields("executive", signedBytes); err != nil {
			t.Errorf("a legacy artifact was rejected: %v; it carries the only score it ever "+
				"had", err)
		}
		// The mirror image, which is what makes the allowance above a
		// discrimination rather than a hole: a CURRENT artifact carrying the
		// legacy field too is rejected. Two plausible scores over one
		// population is the ambiguity this contract exists to end.
		env, agg := sampleEnvelope(t)
		both, err := json.Marshal(struct {
			CompliancePct *int             `json:"compliance_pct"`
			ScorePct      *float64         `json:"score_pct"`
			Provenance    *ScoreProvenance `json:"provenance"`
		}{CompliancePct: &pct, ScorePct: scorePtr(agg.Score),
			Provenance: NewScoreProvenance(env, agg)})
		if err != nil {
			t.Fatalf("marshal both-fields artifact: %v", err)
		}
		if isLegacyArtifact(string(KindExecutive), both) {
			t.Fatal("an artifact carrying artifact_class was read as legacy")
		}
		if err := checkScoreFields("executive", both); err == nil {
			t.Error("an artifact carrying both compliance_pct and an artifact_class was " +
				"accepted; a reader cannot tell which number the signature stands behind")
		}

		// The canonical face still reproduces the signed bytes. This is the
		// whole of "verifies and exports using its original bytes": content is
		// JSONB and never preserved them, so the face is reconstructed, and it
		// must be reconstructed through the shape the artifact was written
		// with rather than through today's struct.
		var back legacyExecutiveContent
		if err := json.Unmarshal(signedBytes, &back); err != nil {
			t.Fatalf("decode legacy: %v", err)
		}
		rebuilt, err := json.Marshal(back)
		if err != nil {
			t.Fatalf("re-marshal legacy: %v", err)
		}
		if !exp.Bool("verifies") {
			t.Fatal("fixture must require the legacy artifact to verify")
		}
		if string(rebuilt) != string(signedBytes) {
			t.Errorf("the canonical face no longer reproduces the signed bytes:\n  signed:  %s\n"+
				"  rebuilt: %s\nIts content address moves and its signature stops verifying",
				signedBytes, rebuilt)
		}
		reSum := sha256.Sum256(rebuilt)
		if hex.EncodeToString(reSum[:]) != signedSHA {
			t.Errorf("content address moved from %s to %s",
				signedSHA, hex.EncodeToString(reSum[:]))
		}
		exp.Str("sha256_after_migration")

		// Nothing backfills. Decoding through the CURRENT struct must not
		// invent an envelope either.
		if exp.Bool("artifact_class_backfilled") || exp.Bool("corpus_identity_status_backfilled") {
			t.Fatal("fixture must forbid backfilling")
		}
		var current ExecutiveContent
		if err := json.Unmarshal(signedBytes, &current); err != nil {
			t.Fatalf("decode through current struct: %v", err)
		}
		if current.Provenance != nil {
			t.Error("decoding a legacy artifact produced a provenance envelope; an artifact " +
				"that recorded no corpus must not acquire one by being read")
		}
		if current.LegacyCompliancePct == nil || *current.LegacyCompliancePct != pct {
			t.Errorf("the legacy score did not survive decoding: %v", current.LegacyCompliancePct)
		}
		if current.ScorePct != nil {
			t.Errorf("decoding a legacy artifact produced score_pct = %v; that number was "+
				"never computed for this artifact", *current.ScorePct)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
