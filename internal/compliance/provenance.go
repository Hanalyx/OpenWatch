package compliance

import "sort"

// CorpusIdentityStatus says what is known about the rule corpus behind an
// artifact's numbers.
//
// The first four are score-bearing values and are derived from the contributor
// list. NotApplicable is the read-model value and is never derived, because a
// read model aggregates no scan set to derive from. Decision records 08 and 10.
type CorpusIdentityStatus string

const (
	// CorpusUnavailable means no contributing host recorded a corpus identity.
	// This is every artifact until features/KN-KN-030 ships DescribeCorpus.
	CorpusUnavailable CorpusIdentityStatus = "unavailable"

	// CorpusIdentified means exactly one corpus contributed and nothing is
	// unidentified. Only in this state do the singular convenience fields carry
	// a value.
	CorpusIdentified CorpusIdentityStatus = "identified"

	// CorpusMixed means several identified corpora contributed and nothing is
	// unidentified, which is what a fleet mid-rollout looks like. No single
	// version or digest describes it, so the singular fields stay null rather
	// than being populated from whichever entry came first.
	CorpusMixed CorpusIdentityStatus = "mixed"

	// CorpusPartiallyIdentified means identified and unidentified contributors
	// coexist. It is the state most likely to be collapsed into identified, and
	// collapsing it would overstate what the artifact can prove.
	CorpusPartiallyIdentified CorpusIdentityStatus = "partially_identified"

	// CorpusNotApplicable is the read-model value. Corpus identity does not
	// apply to an exception register or a remediation activity report rather
	// than being missing from it, which is why the word is not "unavailable".
	CorpusNotApplicable CorpusIdentityStatus = "not_applicable"
)

// ArtifactClass discriminates the two signed shapes.
type ArtifactClass string

const (
	// ScoreBearing artifacts compute a score and carry the full envelope.
	ScoreBearing ArtifactClass = "score_bearing"

	// ReadModel artifacts aggregate no scan set. compliance_exceptions carries
	// host_id and rule_id and no scan id, so contributor counts have no
	// referent, and any corpus attributed to one could only be the corpus
	// installed at generation time, which decision 08 forbids.
	ReadModel ArtifactClass = "read_model"
)

// CorpusContributor is one corpus and how many scored hosts sat on it.
//
// Version is a pointer because a curated corpus genuinely has none (decision
// 09), and decision 08 says a missing value is null and never an empty string.
// An empty-string sentinel would reintroduce exactly the ambiguity those two
// records exist to remove.
type CorpusContributor struct {
	Version            *string
	Digest             string
	ContributorsScored int
}

// Envelope is the provenance carried inside signed content.
//
// Every field is always present. A value that is unknown is null, never absent
// and never an empty string. That rule comes from OW-009, where an empty
// non-nil slice serialized as "" and became indistinguishable from a real
// signature.
//
// The aggregate shape is reserved now rather than added when KN-KN-030 lands,
// so signed content changes shape once. Before that request ships the status is
// unavailable, Corpora is empty, and the singular fields are nil.
type Envelope struct {
	Class ArtifactClass

	// Score-bearing only. A read model omits all four.
	FormulaVersion    *int
	AggregationMethod *string
	Lens              *string

	// Engines are the engine versions behind the contributing outcomes, with
	// how many scored hosts each produced. EngineIdentityStatus says whether
	// they can be summarized, and HostsWithoutEngineIdentity counts the scored
	// hosts that named none. EngineVersion is the convenience field, non-nil
	// only under identified, exactly like the corpus pair.
	Engines                    []EngineContributor
	EngineIdentityStatus       EngineIdentityStatus
	HostsWithoutEngineIdentity *int
	EngineVersion              *string

	Status CorpusIdentityStatus

	// Score-bearing only. A read model omits both.
	Corpora                    []CorpusContributor
	HostsWithoutCorpusIdentity *int

	// Convenience fields, carried by both classes. Non-nil only when Status is
	// CorpusIdentified; the durable record is Corpora.
	CorpusVersion *string
	CorpusDigest  *string
}

// FormulaVersion2 is this formula's identifier. Version 1 was passing over
// every outcome, which no code writes any more but which historical posture
// rows were computed under.
const FormulaVersion2 = 2

// Aggregation method names.
const (
	AggregationNone          = "none"
	AggregationEqualHostMean = "equal_host_mean"
)

// ErrInvalidEnvelope reports provenance that must never be signed.
type ErrInvalidEnvelope struct{ Reason string }

func (e ErrInvalidEnvelope) Error() string { return "invalid provenance envelope: " + e.Reason }

// ScoreBearingEnvelope assembles provenance for an artifact that computed a
// score, or refuses.
//
// It returns an error rather than an envelope a caller has to remember to
// validate. This goes into signed content, where a defect is durable and
// unfixable after the fact: re-serializing to correct it breaks the signature.
// An opt-in Reconciles check was the first design and was wrong for the same
// reason a nullable score was wrong. If a caller can forget the check, some
// caller will.
//
// contributors may arrive in any order; entries are sorted by digest before the
// envelope is returned, because a signature is taken over the canonical face and
// a non-deterministic order produces artifacts that differ without their content
// differing.
//
// Two entries sharing a digest are the same corpus and are merged, with their
// contributor counts summed. Left unmerged they would report `mixed` for one
// corpus. Two entries sharing a digest but disagreeing on version are rejected:
// a digest is content, so the disagreement is a bug in the caller and guessing
// which version is right would launder it into signed evidence.
// engines carry the engine versions behind the contributing outcomes WITH their
// contributor counts, copied from the scan runs rather than reported by whatever
// process is answering. hostsWithoutEngineIdentity counts the scored hosts whose
// run recorded none.
//
// It is the full corpus shape rather than a list of strings, and the difference
// matters. A distinct-version list cannot tell "every scored host ran v0.9.0"
// from "one ran v0.9.0 and the others recorded nothing": both produce the single
// entry [v0.9.0], and the singular engine_version then publishes agreement that
// does not exist. During a partial upgrade that is the common case, not an edge
// one. The counts have to reconcile with hostsScored for the same reason the
// corpus counts do.
//
// An empty version string is rejected: null means not recorded, "" is the
// sentinel that becomes indistinguishable from a version.
func ScoreBearingEnvelope(
	lens string,
	aggregation string,
	engines []EngineContributor,
	hostsWithoutEngineIdentity int,
	contributors []CorpusContributor,
	hostsWithoutCorpusIdentity int,
	hostsScored int,
) (Envelope, error) {
	if lens == "" {
		return Envelope{}, ErrInvalidEnvelope{"lens is empty"}
	}
	if aggregation != AggregationNone && aggregation != AggregationEqualHostMean {
		return Envelope{}, ErrInvalidEnvelope{"aggregation_method is not a known value"}
	}
	if hostsWithoutEngineIdentity < 0 {
		return Envelope{}, ErrInvalidEnvelope{"hosts_without_engine_identity is negative"}
	}
	mergedEngines, err := mergeEngineContributors(engines)
	if err != nil {
		return Envelope{}, err
	}
	if hostsWithoutCorpusIdentity < 0 {
		return Envelope{}, ErrInvalidEnvelope{"hosts_without_corpus_identity is negative"}
	}
	if hostsScored < 0 {
		return Envelope{}, ErrInvalidEnvelope{"hosts_scored is negative"}
	}

	merged, cerr := mergeContributors(contributors)
	if cerr != nil {
		return Envelope{}, cerr
	}

	sum := hostsWithoutCorpusIdentity
	for _, c := range merged {
		sum += c.ContributorsScored
	}
	if sum != hostsScored {
		return Envelope{}, ErrInvalidEnvelope{"corpus contributor counts do not reconcile with hosts_scored"}
	}
	engineSum := hostsWithoutEngineIdentity
	for _, e := range mergedEngines {
		engineSum += e.ContributorsScored
	}
	if engineSum != hostsScored {
		return Envelope{}, ErrInvalidEnvelope{"engine contributor counts do not reconcile with hosts_scored"}
	}

	fv := FormulaVersion2
	env := Envelope{
		Class:                      ScoreBearing,
		FormulaVersion:             &fv,
		AggregationMethod:          &aggregation,
		Lens:                       &lens,
		Engines:                    mergedEngines,
		EngineIdentityStatus:       engineStatus(mergedEngines, hostsWithoutEngineIdentity),
		HostsWithoutEngineIdentity: &hostsWithoutEngineIdentity,
		Corpora:                    merged,
		HostsWithoutCorpusIdentity: &hostsWithoutCorpusIdentity,
		Status:                     corpusStatus(merged, hostsWithoutCorpusIdentity),
	}
	// The singular pair is a convenience and carries a value in exactly one
	// state. Populating it under mixed would mean picking one of several
	// corpora and calling it the artifact's, which is the tempting wrong answer.
	if env.Status == CorpusIdentified {
		d := merged[0].Digest
		env.CorpusDigest = &d
		env.CorpusVersion = merged[0].Version
	}
	// Same rule for the engine, and for the same reason: a value ONLY under
	// identified. Under partially_identified there is one entry in the list and
	// it does not speak for the contributors that named nothing.
	if env.EngineIdentityStatus == EngineIdentified {
		v := mergedEngines[0].EngineVersion
		env.EngineVersion = &v
	}
	return env, nil
}

// HistoricalEnvelope is the envelope for an artifact describing a MEASUREMENT
// ALREADY TAKEN, whose formula may predate the current one.
//
// It is ScoreBearingEnvelope with one difference: formulaVersion is supplied
// rather than pinned to 2. A trend point written before the redesign recorded no
// formula, and stamping the current one on it would claim its number is
// comparable with today's, which is the whole reason formula_status exists.
//
// Everything else is validated identically. A historical artifact still has to
// name its lens and aggregation, and still cannot invent a corpus.
func HistoricalEnvelope(
	lens string,
	aggregation string,
	formulaVersion *int,
	engines []EngineContributor,
	hostsWithoutEngineIdentity int,
	contributors []CorpusContributor,
	hostsWithoutCorpusIdentity int,
	hostsScored int,
) (Envelope, error) {
	env, err := ScoreBearingEnvelope(lens, aggregation, engines, hostsWithoutEngineIdentity,
		contributors, hostsWithoutCorpusIdentity, hostsScored)
	if err != nil {
		return Envelope{}, err
	}
	if formulaVersion != nil && *formulaVersion != FormulaVersion2 {
		return Envelope{}, ErrInvalidEnvelope{"formula_version is neither 2 nor absent"}
	}
	env.FormulaVersion = formulaVersion
	return env, nil
}

// EngineContributor is one engine version and how many scored hosts it produced
// outcomes for.
//
// It carries a COUNT for the same reason CorpusContributor does. A bare list of
// versions cannot tell "every scored host ran v0.9.0" from "one ran v0.9.0 and
// the rest recorded nothing", and those are different claims: the first is
// agreement, the second is partial knowledge that a singular engine_version
// would misreport as agreement.
type EngineContributor struct {
	EngineVersion      string
	ContributorsScored int
}

// EngineIdentityStatus mirrors CorpusIdentityStatus, value for value, because
// the question is the same one: can this artifact name the thing behind its
// number, and if not, why.
type EngineIdentityStatus string

const (
	// EngineUnavailable: no scored contributor recorded an engine version.
	// Every scan predates migration 0063, or there were no scored hosts.
	EngineUnavailable EngineIdentityStatus = "unavailable"

	// EngineIdentified: exactly one engine version, and every scored
	// contributor is accounted for by it. The only state in which the singular
	// engine_version carries a value.
	EngineIdentified EngineIdentityStatus = "identified"

	// EngineMixed: several engine versions, all scored contributors accounted
	// for. Normal while a fleet is part way through an upgrade.
	EngineMixed EngineIdentityStatus = "mixed"

	// EnginePartiallyIdentified: some scored contributors named an engine and
	// some did not. This is the state a bare version list could not express,
	// and the one it reported as identified.
	EnginePartiallyIdentified EngineIdentityStatus = "partially_identified"
)

// engineStatus derives the status from the contributors and the unidentified
// count, exactly as corpusStatus does.
func engineStatus(engines []EngineContributor, unidentified int) EngineIdentityStatus {
	switch {
	case len(engines) == 0:
		return EngineUnavailable
	case unidentified > 0:
		return EnginePartiallyIdentified
	case len(engines) == 1:
		return EngineIdentified
	default:
		return EngineMixed
	}
}

// mergeEngineContributors validates each entry, folds duplicates by version and
// sorts.
//
// Sorted because a signature is taken over the canonical face, and a
// non-deterministic order produces artifacts that differ without their content
// differing. Same argument as the corpus contributors.
func mergeEngineContributors(in []EngineContributor) ([]EngineContributor, error) {
	byVersion := make(map[string]EngineContributor, len(in))
	for _, e := range in {
		if e.EngineVersion == "" {
			return nil, ErrInvalidEnvelope{"an engine contributor has an empty version"}
		}
		if e.ContributorsScored <= 0 {
			return nil, ErrInvalidEnvelope{"an engine contributor scored no hosts"}
		}
		prev, seen := byVersion[e.EngineVersion]
		if seen {
			prev.ContributorsScored += e.ContributorsScored
			byVersion[e.EngineVersion] = prev
			continue
		}
		byVersion[e.EngineVersion] = e
	}
	out := make([]EngineContributor, 0, len(byVersion))
	for _, e := range byVersion {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EngineVersion < out[j].EngineVersion })
	return out, nil
}

// mergeContributors validates each entry and folds duplicates by digest.
func mergeContributors(in []CorpusContributor) ([]CorpusContributor, error) {
	byDigest := make(map[string]CorpusContributor, len(in))
	for _, c := range in {
		if c.Digest == "" {
			return nil, ErrInvalidEnvelope{"a contributor has an empty corpus digest"}
		}
		if c.Version != nil && *c.Version == "" {
			// Decision 08: a missing value is null, never an empty string. A
			// non-nil pointer to "" is the sentinel that rule exists to forbid.
			return nil, ErrInvalidEnvelope{"a contributor version is a pointer to an empty string; use nil"}
		}
		if c.ContributorsScored <= 0 {
			return nil, ErrInvalidEnvelope{"a contributor scored no hosts; an entry contributing nothing is not a contributor"}
		}
		prev, seen := byDigest[c.Digest]
		if !seen {
			byDigest[c.Digest] = c
			continue
		}
		if !sameVersion(prev.Version, c.Version) {
			return nil, ErrInvalidEnvelope{"two contributors share a digest but disagree on version"}
		}
		prev.ContributorsScored += c.ContributorsScored
		byDigest[c.Digest] = prev
	}
	out := make([]CorpusContributor, 0, len(byDigest))
	for _, c := range byDigest {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out, nil
}

func sameVersion(a, b *string) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

// ReadModelEnvelope assembles provenance for an artifact that computed no
// score. Ratified 2026-09-01, decision record 10.
func ReadModelEnvelope() Envelope {
	return Envelope{
		Class:  ReadModel,
		Status: CorpusNotApplicable,
		// FormulaVersion, AggregationMethod, Lens, EngineVersion, Corpora and
		// HostsWithoutCorpusIdentity stay nil: they have no referent here.
		// CorpusVersion and CorpusDigest stay nil but are still declared, which
		// honors decision 08's always-present rule.
	}
}

// corpusStatus derives the score-bearing status from the list it summarizes, so
// the status cannot contradict the data beside it.
func corpusStatus(corpora []CorpusContributor, unidentified int) CorpusIdentityStatus {
	switch {
	case len(corpora) == 0:
		// Covers the zero-scored-host case too: an empty fleet is not an error
		// and not a mixed corpus.
		return CorpusUnavailable
	case unidentified > 0:
		return CorpusPartiallyIdentified
	case len(corpora) == 1:
		return CorpusIdentified
	default:
		return CorpusMixed
	}
}

// Reconciles re-checks a DESERIALIZED envelope's two count sets against the
// artifact's scored-host count.
//
// Construction already refuses to produce an envelope that fails this, so a
// caller inside this process never needs it. It exists for the read side:
// verifying a stored or received artifact whose bytes this process did not
// build. An artifact showing two count sets that do not add up is the same
// defect as a mean displayed beside pooled totals it cannot be derived from.
func (e Envelope) Reconciles(hostsScored int) bool {
	if e.Class == ReadModel {
		return e.Corpora == nil && e.HostsWithoutCorpusIdentity == nil &&
			e.Engines == nil && e.HostsWithoutEngineIdentity == nil
	}
	if e.HostsWithoutCorpusIdentity == nil || e.HostsWithoutEngineIdentity == nil {
		return false
	}
	engineSum := *e.HostsWithoutEngineIdentity
	for _, en := range e.Engines {
		engineSum += en.ContributorsScored
	}
	if engineSum != hostsScored {
		return false
	}
	sum := *e.HostsWithoutCorpusIdentity
	for _, c := range e.Corpora {
		if c.ContributorsScored <= 0 {
			return false
		}
		sum += c.ContributorsScored
	}
	return sum == hostsScored
}
