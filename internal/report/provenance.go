package report

import (
	"github.com/Hanalyx/openwatch/internal/compliance"
)

// Two provenance shapes, one per artifact class, rather than one struct with
// optional halves.
//
// A read model must OMIT score, lens, engine_version, formula_version,
// aggregation_method, corpora and every contributor count, while still
// carrying corpus_version and corpus_digest as explicit nulls. A single
// struct cannot express "absent here, null there" with encoding/json: a
// pointer with omitempty disappears when null, and one without it serializes
// as null when it should be gone. Two types state the difference instead of
// encoding it in tag combinations nobody can read.

// EngineEntry is one engine version behind a frozen score.
type EngineEntry struct {
	EngineVersion      string `json:"engine_version"`
	ContributorsScored int    `json:"contributors_scored"`
}

// CorpusEntry is one corpus that measured part of a frozen score.
type CorpusEntry struct {
	// Version is null for a curated corpus, which has a digest and no version.
	Version            *string `json:"corpus_version"`
	Digest             string  `json:"corpus_digest"`
	ContributorsScored int     `json:"contributors_scored"`
}

// ScoreProvenance is the frozen envelope on a score-bearing artifact.
//
// Every field is present. A value that is unknown is null, never absent and
// never an empty string: bugs/OW-009 is the case where an empty non-nil
// slice serialized as "" and became indistinguishable from a real value.
type ScoreProvenance struct {
	ArtifactClass string `json:"artifact_class"`

	FormulaVersion    *int    `json:"formula_version"`
	AggregationMethod *string `json:"aggregation_method"`
	Lens              *string `json:"lens"`

	EngineIdentityStatus       string        `json:"engine_identity_status"`
	Engines                    []EngineEntry `json:"engines"`
	HostsWithoutEngineIdentity *int          `json:"hosts_without_engine_identity"`
	EngineVersion              *string       `json:"engine_version"`

	CorpusIdentityStatus       string        `json:"corpus_identity_status"`
	Corpora                    []CorpusEntry `json:"corpora"`
	HostsWithoutCorpusIdentity *int          `json:"hosts_without_corpus_identity"`
	CorpusVersion              *string       `json:"corpus_version"`
	CorpusDigest               *string       `json:"corpus_digest"`

	// Participation counts. A mean over 2 of 200 hosts and a mean over 200 of
	// 200 are different claims that a percentage alone cannot tell apart, and
	// on a signed artifact the reader cannot go and look.
	HostsTotal        int `json:"hosts_total"`
	HostsScored       int `json:"hosts_scored"`
	HostsWithoutScore int `json:"hosts_without_score"`
}

// ReadModelProvenance is the envelope on an artifact that aggregates no scan
// set.
//
// compliance_exceptions carries host_id and rule_id and no scan id, so
// contributor counts have no referent here. Attributing a corpus could only
// mean the corpus installed at generation time, which decision 08 forbids.
// The word is not_applicable rather than unavailable because corpus identity
// does not APPLY to a read model rather than being missing from it.
type ReadModelProvenance struct {
	ArtifactClass        string `json:"artifact_class"`
	CorpusIdentityStatus string `json:"corpus_identity_status"`

	// Kept as explicit nulls to honor decision 06's always-present rule.
	// Omitting them would narrow that decision and would need a superseding
	// record.
	CorpusVersion *string `json:"corpus_version"`
	CorpusDigest  *string `json:"corpus_digest"`
}

// NewReadModelProvenance builds the read-model envelope.
func NewReadModelProvenance() *ReadModelProvenance {
	env := compliance.ReadModelEnvelope()
	return &ReadModelProvenance{
		ArtifactClass:        string(env.Class),
		CorpusIdentityStatus: string(env.Status),
		CorpusVersion:        env.CorpusVersion,
		CorpusDigest:         env.CorpusDigest,
	}
}

// NewScoreProvenance converts a validated envelope plus its participation
// counts into the frozen wire shape.
//
// It takes a compliance.Envelope rather than the raw parts, so the
// validation that refuses an envelope whose counts do not reconcile runs
// before anything is signed. An artifact showing two count sets that do not
// add up is the same defect as a mean displayed beside pooled totals it
// cannot be derived from.
func NewScoreProvenance(env compliance.Envelope, agg compliance.Aggregate) *ScoreProvenance {
	p := &ScoreProvenance{
		ArtifactClass:              string(env.Class),
		FormulaVersion:             env.FormulaVersion,
		AggregationMethod:          env.AggregationMethod,
		Lens:                       env.Lens,
		EngineIdentityStatus:       string(env.EngineIdentityStatus),
		Engines:                    []EngineEntry{},
		HostsWithoutEngineIdentity: env.HostsWithoutEngineIdentity,
		EngineVersion:              env.EngineVersion,
		CorpusIdentityStatus:       string(env.Status),
		Corpora:                    []CorpusEntry{},
		HostsWithoutCorpusIdentity: env.HostsWithoutCorpusIdentity,
		CorpusVersion:              env.CorpusVersion,
		CorpusDigest:               env.CorpusDigest,
		HostsTotal:                 agg.HostsTotal,
		HostsScored:                agg.HostsScored,
		HostsWithoutScore:          agg.HostsWithoutScore,
	}
	for _, e := range env.Engines {
		p.Engines = append(p.Engines, EngineEntry{
			EngineVersion:      e.EngineVersion,
			ContributorsScored: e.ContributorsScored,
		})
	}
	for _, c := range env.Corpora {
		p.Corpora = append(p.Corpora, CorpusEntry{
			Version:            c.Version,
			Digest:             c.Digest,
			ContributorsScored: c.ContributorsScored,
		})
	}
	return p
}
