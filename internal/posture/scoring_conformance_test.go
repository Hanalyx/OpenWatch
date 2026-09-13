// @spec system-compliance-scoring
//
// The SQL side of the score. Every other test of the formula runs the Go
// implementation; this one runs the expression the rollup actually ships and
// proves the two produce the same number.
//
// It lives in internal/posture because that is where the SQL is. The scoring
// package itself must stay free of a database (C-13), so it cannot host this.
package posture

import (
	"context"
	"testing"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-09
// AC-09: rounding is half away from zero, and the SQL and Go paths agree.
//
// The fixtures are chosen to straddle a one-decimal half boundary, where a
// difference between the two implementations would actually show. Two of them
// are repeating fractions, which no float representation holds exactly and which
// caught the REAL column this arc replaced.
func TestScoring_RoundingAgreesBetweenGoAndSQL(t *testing.T) {
	t.Run("system-compliance-scoring/AC-09", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-09")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		fixtures := in.MapList("fixtures")
		want := exp.List("score_pct")
		if len(fixtures) != len(want) {
			t.Fatalf("%d fixtures but %d expected values", len(fixtures), len(want))
		}
		if !exp.Bool("go_and_sql_agree") {
			t.Fatal("fixture must claim the two paths agree; there is nothing to test otherwise")
		}

		// The SAME expression every query layer runs, with the counts supplied
		// as parameters instead of aggregated from rows. A retyped copy here
		// would agree with the rollup until someone edited one of them.
		q := `SELECT ` + compliance.ScoreSQL("$1::bigint", "$2::bigint")

		for i, f := range fixtures {
			counts := f.Map("counts")
			c := compliance.Counts{Pass: counts.Int("pass"), Fail: counts.Int("fail")}
			counts.AllConsumed()
			// fraction, kind and position name what each fixture is FOR. Reading
			// them keeps the labels honest: relabeling a boundary case in the
			// spec without changing its counts fails here.
			label := f.Str("fraction") + " (" + f.Str("kind") + ", " + f.Str("position") + ")"
			f.AllConsumed()

			var expect float64
			switch n := want[i].(type) {
			case float64:
				expect = n
			case int:
				expect = float64(n)
			default:
				t.Fatalf("expected score_pct[%d] is %T, want a number", i, want[i])
			}

			goPct, ok := compliance.HostScore(c).Rounded()
			if !ok {
				t.Fatalf("%s: Go produced no score for %d/%d", label, c.Pass, c.Fail)
			}
			var sqlPct *float64
			if err := pool.QueryRow(ctx, q, c.Pass, c.Pass+c.Fail).Scan(&sqlPct); err != nil {
				t.Fatalf("%s: SQL: %v", label, err)
			}
			if sqlPct == nil {
				t.Fatalf("%s: SQL produced no score for %d/%d", label, c.Pass, c.Fail)
			}

			if goPct != expect {
				t.Errorf("%s: Go = %v, want %v", label, goPct, expect)
			}
			if *sqlPct != expect {
				t.Errorf("%s: SQL = %v, want %v", label, *sqlPct, expect)
			}
			// The conformance assertion itself. Exact, not within a tolerance:
			// a tolerance is where a real disagreement hides.
			if goPct != *sqlPct {
				t.Errorf("%s: Go = %v but SQL = %v; C-14 requires them to agree",
					label, goPct, *sqlPct)
			}
		}

		// The absent case crosses the boundary too. A host with no verdict must
		// produce no score on BOTH sides, not zero on either.
		var none *float64
		if err := pool.QueryRow(ctx, q, 0, 0).Scan(&none); err != nil {
			t.Fatalf("SQL zero-verdict: %v", err)
		}
		if none != nil {
			t.Errorf("SQL scored a host with no verdict as %v, want no score", *none)
		}
		if compliance.HostScore(compliance.Counts{}).Present() {
			t.Error("Go scored a host with no verdict; the two paths must agree on absence too")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
