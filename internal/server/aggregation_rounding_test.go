// @spec system-compliance-scoring
//
// The rounding ORDER, checked on every surface that aggregates.
//
// Each surface computes its mean in a different place: Go for a set of scores,
// SQL for the fleet score, SQL again for the group rollup, and SQL over stored
// snapshot rows for the fleet trend. A rule enforced in one of them is a rule
// that holds until someone writes from another, which is why this test refuses
// to check just one.
package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/fleetrollup"
	"github.com/Hanalyx/openwatch/internal/group"
	"github.com/Hanalyx/openwatch/internal/posture"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/google/uuid"
)

// @ac AC-35
// AC-35: aggregation averages unrounded fractions and rounds once.
func TestAggregation_AveragesUnroundedThenRoundsOnce(t *testing.T) {
	t.Run("system-compliance-scoring/AC-35", func(t *testing.T) {
		ctx := context.Background()
		_, pool := freshAPIServer(t)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-35")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		want := exp.Num("mean_score_pct")
		bad := exp.Num("forbidden_round_then_average_pct")
		if want == bad {
			t.Fatal("fixture does not discriminate: the two rounding orders must disagree")
		}
		if !exp.Bool("all_surfaces_agree") {
			t.Fatal("fixture must require every surface to agree")
		}

		type hostFix struct {
			id         uuid.UUID
			pass, fail int
		}
		var hosts []hostFix
		var goScores []compliance.Score
		for _, h := range in.MapList("hosts") {
			id := seedHostForIntel(t, pool)
			label := h.Str("id")
			pass, fail := h.Int("pass"), h.Int("fail")
			for i := 0; i < pass; i++ {
				seedRuleStateForHost(t, pool, id, fmt.Sprintf("%s.p%d", label, i), "pass")
			}
			for i := 0; i < fail; i++ {
				seedRuleStateForHost(t, pool, id, fmt.Sprintf("%s.f%d", label, i), "fail")
			}
			hosts = append(hosts, hostFix{id: id, pass: pass, fail: fail})
			goScores = append(goScores, compliance.HostScore(compliance.Counts{Pass: pass, Fail: fail}))
			h.AllConsumed()
		}
		if len(hosts) != 2 {
			t.Fatalf("fixture seeded %d hosts, want 2", len(hosts))
		}

		// The per-host values the fixture names, so a change to either host's
		// counts is caught here rather than showing up only in the mean.
		a, _ := goScores[0].Rounded()
		b, _ := goScores[1].Rounded()
		if a != exp.Num("host_a_score_pct") {
			t.Errorf("host A = %v, want %v", a, exp.Num("host_a_score_pct"))
		}
		if b != exp.Num("host_b_score_pct") {
			t.Errorf("host B = %v, want %v", b, exp.Num("host_b_score_pct"))
		}

		got := map[string]float64{}

		for _, surface := range in.List("surfaces") {
			name, ok := surface.(string)
			if !ok {
				t.Fatalf("surfaces holds %T, want strings", surface)
			}
			switch name {
			case "go":
				pct, ok := compliance.MeanOfHostScores(goScores).Score.Rounded()
				if !ok {
					t.Fatal("go: mean absent")
				}
				got[name] = pct

			case "fleet_score":
				sc, err := fleetrollup.NewService(pool).FleetComplianceScore(ctx)
				if err != nil {
					t.Fatalf("fleet score: %v", err)
				}
				pct, ok := sc.Score.Rounded()
				if !ok {
					t.Fatal("fleet_score: mean absent")
				}
				got[name] = pct

			case "group_rollup":
				gsvc := group.NewService(pool)
				g, err := gsvc.Create(ctx, group.CreateInput{
					Name: "rounding", Kind: group.KindSite, Subtype: "Environment",
					Membership: group.MembershipManual,
				})
				if err != nil {
					t.Fatalf("create group: %v", err)
				}
				for _, h := range hosts {
					if err := gsvc.AddMember(ctx, g.ID, h.id); err != nil {
						t.Fatalf("add member: %v", err)
					}
				}
				all, err := gsvc.List(ctx, "")
				if err != nil {
					t.Fatalf("list groups: %v", err)
				}
				var found bool
				for _, gr := range all {
					if gr.ID != g.ID {
						continue
					}
					pct, ok := gr.Rollup.Score.Score.Rounded()
					if !ok {
						t.Fatal("group_rollup: mean absent")
					}
					got[name] = pct
					found = true
				}
				if !found {
					t.Fatal("group_rollup: group not returned by List")
				}

			case "fleet_trend":
				// Version-2 snapshots, so the trend must aggregate their stored
				// COUNTS. Seeding a rounded score_pct beside the counts is what
				// this criterion forbids, so the rollup writes both.
				if _, err := posture.Rollup(ctx, pool, time.Now()); err != nil {
					t.Fatalf("posture rollup: %v", err)
				}
				points, err := posture.FleetTrend(ctx, pool, 30, "")
				if err != nil {
					t.Fatalf("fleet trend: %v", err)
				}
				if len(points) != 1 {
					t.Fatalf("fleet_trend: %d days, want 1", len(points))
				}
				pct, ok := points[0].Score.Rounded()
				if !ok {
					t.Fatal("fleet_trend: mean absent")
				}
				if points[0].HostsScored != 2 {
					t.Errorf("fleet_trend: HostsScored = %d, want 2", points[0].HostsScored)
				}
				got[name] = pct

			default:
				t.Fatalf("fixture names surface %q, which this test does not exercise", name)
			}
		}

		if len(got) != 4 {
			t.Fatalf("exercised %d surfaces, want 4", len(got))
		}
		for name, pct := range got {
			if pct != want {
				t.Errorf("%s = %v, want %v", name, pct, want)
			}
			if pct == bad {
				t.Errorf("%s = %v, which is each host rounded BEFORE averaging; C-06 requires "+
					"the mean over unrounded values", name, bad)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
