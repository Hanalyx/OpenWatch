// NOTE: no @spec or @ac annotations in this file.
//
// Partial unit tests for the pure scoring rules. Every number is read from the
// spec's structured fixture fields rather than restated here.
//
// These deliberately carry NO @spec or @ac annotations. Each asserts the
// arithmetic half of its criterion and ignores the response metadata the
// criterion also requires: lens, formula_version, aggregation_method and the
// echoed engine_version. Annotating them would report those criteria as covered
// when four of their expected values were never read, which is the same defect
// the spec exists to prevent, aimed at its own coverage number.
//
// The annotations move to composite contract tests once the response layer
// exists. AC-09 is no longer here: it needed the SQL side, and the whole
// criterion now lives in internal/posture/scoring_conformance_test.go where a
// database is available.
package compliance

import (
	"math"
	"testing"
)

// eq compares one-decimal presentation values. Comparing raw floats would make
// the test assert something the product never shows.
func eq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// AC-01: the host score counts only confirmed verdicts. The legacy denominator
// counted every outcome and returned 53.3 for this fixture, treating three
// inapplicable rules and two unknown ones as failures.
func TestHostScore_CountsOnlyConfirmedVerdicts(t *testing.T) {
	t.Run("unit-partial/AC-01", func(t *testing.T) {
		ac := criterion(t, loadCriteria(t), "AC-01")
		got, ok := HostScore(countsFrom(t, ac.Inputs)).Rounded()
		if !ok {
			t.Fatal("score absent, want a value")
		}
		if want := rawNum(t, ac.ExpectedOutput, "score_pct"); !eq(got, want) {
			t.Errorf("score_pct = %v, want %v", got, want)
		}
		// The forbidden value is asserted, not merely documented. Without this
		// the test would still pass if the formula regressed to a third answer.
		if bad := rawNum(t, ac.ExpectedOutput, "forbidden_score_pct"); eq(got, bad) {
			t.Errorf("score_pct = %v, which is the legacy passing/total answer the spec forbids", got)
		}
	})
}

// AC-02: a host that produced no verdict has no score, and the absence is not
// zero percent.
func TestHostScore_NoVerdictIsAbsentNotZero(t *testing.T) {
	t.Run("unit-partial/AC-02", func(t *testing.T) {
		ac := criterion(t, loadCriteria(t), "AC-02")
		c := countsFrom(t, ac.Inputs)
		s := HostScore(c)
		rawNull(t, ac.ExpectedOutput, "score_pct")
		if _, ok := s.Value(); ok {
			t.Fatalf("score present for %d skipped and no verdict, want absent", c.Skipped)
		}
		// forbidden_score_pct is read so a regression to 0.0 is caught by the
		// presence assertion above rather than merely documented in YAML.
		_ = rawNum(t, ac.ExpectedOutput, "forbidden_score_pct")
		// The raw skipped count survives even though nothing can classify it.
		if got, want := c.Skipped, int(rawNum(t, ac.ExpectedOutput, "skipped")); got != want {
			t.Errorf("skipped = %d, want %d", got, want)
		}
	})
}

// AC-03: counterexample. Every evaluated rule failed, which is a real verdict
// and not an absence. This and AC-02 must be distinguishable by score alone.
func TestHostScore_GenuineZeroIsAVerdict(t *testing.T) {
	t.Run("unit-partial/AC-03", func(t *testing.T) {
		all := loadCriteria(t)
		zero := HostScore(countsFrom(t, criterion(t, all, "AC-03").Inputs))
		absent := HostScore(countsFrom(t, criterion(t, all, "AC-02").Inputs))

		got, ok := zero.Rounded()
		if !ok {
			t.Fatal("genuine zero reported as absent; a confirmed failure is a verdict")
		}
		if want := rawNum(t, criterion(t, all, "AC-03").ExpectedOutput, "score_pct"); !eq(got, want) {
			t.Errorf("score_pct = %v, want %v", got, want)
		}
		// The discriminating assertion. Both hosts score 0 under any formula
		// that cannot express absence, which is exactly the OW-023 and OW-024
		// defect. They must differ here.
		if zero.Present() == absent.Present() {
			t.Error("a confirmed zero and an unassessable host are indistinguishable")
		}
	})
}

// AC-05: counterexample, pooled versus equal-host aggregation. Host A
// contributes ten rule rows and host B two, so pooling gives A five times the
// weight.
func TestMeanOfHostScores_EqualHostNotPooled(t *testing.T) {
	t.Run("unit-partial/AC-05", func(t *testing.T) {
		ac := criterion(t, loadCriteria(t), "AC-05")
		scores, pooled := hostsFixture(t, ac.Inputs)

		agg := MeanOfHostScores(scores)
		got, ok := agg.Score.Rounded()
		if !ok {
			t.Fatal("fleet score absent")
		}
		if want := rawNum(t, ac.ExpectedOutput, "fleet_score_pct"); !eq(got, want) {
			t.Errorf("fleet_score_pct = %v, want %v", got, want)
		}
		bad := rawNum(t, ac.ExpectedOutput, "forbidden_fleet_score_pct")
		if eq(got, bad) {
			t.Errorf("fleet_score_pct = %v, which is the pooled answer", got)
		}
		// Prove the fixture actually discriminates: if pooling and the mean
		// agreed on these hosts the criterion would pass vacuously.
		if eq(Round1(pooled), got) {
			t.Fatalf("fixture does not discriminate: pooled and mean both = %v", got)
		}
		if !eq(Round1(pooled), bad) {
			t.Errorf("pooled answer = %v, but the spec forbids %v", Round1(pooled), bad)
		}
	})
}

// AC-06: an unscored host is omitted from the mean and counted, never averaged
// in as zero.
func TestMeanOfHostScores_UnscoredHostIsOmittedNotZero(t *testing.T) {
	t.Run("unit-partial/AC-06", func(t *testing.T) {
		ac := criterion(t, loadCriteria(t), "AC-06")
		scores, _ := hostsFixture(t, ac.Inputs)

		agg := MeanOfHostScores(scores)
		got, _ := agg.Score.Rounded()
		if want := rawNum(t, ac.ExpectedOutput, "fleet_score_pct"); !eq(got, want) {
			t.Errorf("fleet_score_pct = %v, want %v", got, want)
		}
		if want := int(rawNum(t, ac.ExpectedOutput, "hosts_scored")); agg.HostsScored != want {
			t.Errorf("hosts_scored = %d, want %d", agg.HostsScored, want)
		}
		if want := int(rawNum(t, ac.ExpectedOutput, "hosts_without_score")); agg.HostsWithoutScore != want {
			t.Errorf("hosts_without_score = %d, want %d", agg.HostsWithoutScore, want)
		}
		if bad := rawNum(t, ac.ExpectedOutput, "forbidden_fleet_score_pct"); eq(got, bad) {
			t.Errorf("fleet_score_pct = %v, the answer produced by averaging the unscored host in as zero", got)
		}
	})
}

// hostsFixture builds per-host scores from a spec `hosts` list and also returns
// the pooled answer, so a test can prove its fixture discriminates between the
// two aggregation rules rather than assuming it does.
func hostsFixture(t *testing.T, in map[string]any) (scores []Score, pooledPct float64) {
	t.Helper()
	raw, ok := in["hosts"].([]any)
	if !ok {
		t.Fatalf("inputs.hosts is %T, want a list", in["hosts"])
	}
	var pass, executed int
	for _, h := range raw {
		m, _ := h.(map[string]any)
		counts, _ := m["counts"].(map[string]any)
		c := Counts{
			Pass:    intField(t, counts, "pass"),
			Fail:    intField(t, counts, "fail"),
			Skipped: intField(t, counts, "skipped"),
			Error:   intField(t, counts, "error"),
		}
		scores = append(scores, HostScore(c))
		pass += c.Pass
		executed += c.Executed()
	}
	if executed > 0 {
		pooledPct = float64(pass) / float64(executed) * 100
	}
	return scores, pooledPct
}

// rawNum and rawNull read an expectation without consumption tracking, for the
// partial tests above. A test that claims a criterion uses expectations instead.
func rawNum(t *testing.T, m map[string]any, k string) float64 {
	t.Helper()
	v, ok := m[k]
	if !ok {
		t.Fatalf("expected_output has no %q", k)
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		t.Fatalf("%s = %v (%T), want a number", k, v, v)
		return 0
	}
}

func rawNull(t *testing.T, m map[string]any, k string) {
	t.Helper()
	v, ok := m[k]
	if !ok {
		t.Fatalf("expected_output has no %q", k)
	}
	if v != nil {
		t.Fatalf("%s = %v, want null", k, v)
	}
}
