// @spec api-groups
//
// The group rollup's aggregation rule. Every other group test seeds members
// with the same rule count, under which the pooled ratio and the equal-host
// mean give the same answer, so none of them can tell the two apart.
package group

import (
	"context"
	"fmt"
	"testing"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/db/corpustest"
	"github.com/Hanalyx/openwatch/internal/fleetrollup"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/Hanalyx/openwatch/internal/version"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// @ac AC-10
// AC-10: the group average is the equal-host mean over scored members.
func TestGroupRollup_EqualHostMeanNotPooled(t *testing.T) {
	t.Run("api-groups/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/groups.spec.yaml", "api-groups"), "AC-10")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		site := mustCreateSite(t, svc, ctx, "mean-site")
		for _, m := range in.MapList("members") {
			h := seedMemberWithCounts(t, pool, user, m)
			if err := svc.AddMember(ctx, site.ID, h); err != nil {
				t.Fatalf("add member: %v", err)
			}
			m.AllConsumed()
		}

		r := listOne(t, svc, ctx, site.ID)
		got := scorePct(t, r.Score.Score)
		if want := exp.Num("avg_compliance_pct"); got != want {
			t.Errorf("avg = %v, want %v (equal-host mean)", got, want)
		}
		// The two answers this fixture exists to separate. Member A carries
		// nine times member B's passing rules, so pooling weights it heavily.
		if bad := exp.Num("forbidden_pooled_pct"); got == bad {
			t.Errorf("avg = %v, the POOLED answer over the members' combined rule rows", bad)
		}
		if bad := exp.Num("forbidden_zero_averaged_pct"); got == bad {
			t.Errorf("avg = %v, the answer produced by averaging the unassessable member in as zero", bad)
		}
		if r.Score.HostsScored != exp.Int("hosts_scored") {
			t.Errorf("HostsScored = %d, want %d", r.Score.HostsScored, exp.Int("hosts_scored"))
		}
		if r.Score.HostsWithoutScore != exp.Int("hosts_without_score") {
			t.Errorf("HostsWithoutScore = %d, want %d; the member whose rules all skipped and "+
				"the member never scanned are both counted, not averaged in and not dropped",
				r.Score.HostsWithoutScore, exp.Int("hosts_without_score"))
		}
		if r.Hosts != exp.Int("hosts_total") {
			t.Errorf("Hosts = %d, want %d", r.Hosts, exp.Int("hosts_total"))
		}
		// The invariant. Member D has never been scanned, so under the old query
		// it fell out of the per-host set instead of counting as unscored.
		if r.Score.HostsScored+r.Score.HostsWithoutScore != r.Hosts {
			t.Errorf("%d scored + %d unscored != %d members; a member vanished from the "+
				"population the average claims to describe",
				r.Score.HostsScored, r.Score.HostsWithoutScore, r.Hosts)
		}

		// Genuine zero versus absent. Both used to be nil-or-zero guesses; they
		// are different facts and must stay distinguishable at this layer.
		failing := mustCreateSite(t, svc, ctx, "all-failing-site")
		fh := seedMemberWithCounts(t, pool, user, in.Map("all_failing_group_member"))
		if err := svc.AddMember(ctx, failing.ID, fh); err != nil {
			t.Fatalf("add failing member: %v", err)
		}
		fr := listOne(t, svc, ctx, failing.ID)
		zero := scorePct(t, fr.Score.Score)
		if want := exp.Num("all_failing_group_pct"); zero != want {
			t.Errorf("all-failing group = %v, want %v; every rule was evaluated and failed, "+
				"which is a real result", zero, want)
		}

		empty := mustCreateSite(t, svc, ctx, "unscanned-site")
		er := listOne(t, svc, ctx, empty.ID)
		if exp.Bool("unscanned_group_score_present") {
			t.Fatal("fixture must claim the unscanned group has no score")
		}
		if er.Score.Score.Present() {
			pct, _ := er.Score.Score.Value()
			t.Errorf("unscanned group scored %v, want no score", pct)
		}
		if fr.Score.Score.Present() == er.Score.Score.Present() {
			t.Error("a group that failed everything and a group nobody could assess are " +
				"indistinguishable")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// mustCreateSite creates a manual site group or fails the test.
func mustCreateSite(t *testing.T, svc *Service, ctx context.Context, name string) Group {
	t.Helper()
	g, err := svc.Create(ctx, CreateInput{
		Name: name, Kind: KindSite, Subtype: "Environment", Membership: MembershipManual,
	})
	if err != nil {
		t.Fatalf("create site %q: %v", name, err)
	}
	return g
}

// seedMemberWithCounts builds one host carrying exactly the fixture's outcomes.
func seedMemberWithCounts(t *testing.T, pool *pgxpool.Pool, user uuid.UUID,
	f *specfixture.Fields) uuid.UUID {
	t.Helper()
	h := seedHost(t, pool, user, "rhel", false)
	// The label is read unconditionally, so a member with no rules at all still
	// consumes its fixture id. It also prefixes the rule ids, so renaming a
	// member renames its rules and nothing silently collides.
	id := "m"
	if f.Has("id") {
		id = f.Str("id")
	}
	id += "-" + uuid.New().String()[:8]
	for i := 0; i < f.Int("pass"); i++ {
		seedRuleState(t, pool, h, fmt.Sprintf("%s.p%d", id, i), "pass", "medium")
	}
	for i := 0; i < f.Int("fail"); i++ {
		seedRuleState(t, pool, h, fmt.Sprintf("%s.f%d", id, i), "fail", "medium")
	}
	if f.Has("skipped") {
		for i := 0; i < f.Int("skipped"); i++ {
			seedRuleState(t, pool, h, fmt.Sprintf("%s.s%d", id, i), "skipped", "medium")
		}
	}
	return h
}

// @ac AC-11
// AC-11: the group's own lens, never the member's and never another group's.
//
// One host, three framework families with three different scores, its own
// target_framework set to a fourth answer, and membership in two site groups
// with different targets. Every candidate lens gives a different number, which
// is the only arrangement that can say which one was actually used.
func TestGroupRollup_UsesGroupLensNotMemberOverride(t *testing.T) {
	t.Run("api-groups/AC-11", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/groups.spec.yaml", "api-groups"), "AC-11")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		h := seedHost(t, pool, user, "rhel", false)
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, h); err != nil {
			t.Fatalf("set host OS: %v", err)
		}
		rules := in.Map("host_rules")
		for _, key := range []string{"stig_rhel9", "cis_rhel9", "nist_800_53"} {
			counts := rules.Map(key)
			for i := 0; i < counts.Int("pass"); i++ {
				seedRuleStateFW(t, pool, h, fmt.Sprintf("%s.p%d", key, i), "pass",
					fmt.Sprintf(`{%q:["X-%d"]}`, key, i))
			}
			for i := 0; i < counts.Int("fail"); i++ {
				seedRuleStateFW(t, pool, h, fmt.Sprintf("%s.f%d", key, i), "fail",
					fmt.Sprintf(`{%q:["Y-%d"]}`, key, i))
			}
			counts.AllConsumed()
		}
		rules.AllConsumed()

		// The host's OWN target. It must change nothing.
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET target_framework = $2 WHERE id = $1`,
			h, in.Str("host_target_framework")); err != nil {
			t.Fatalf("set host target: %v", err)
		}

		older := in.Map("older_group")
		newer := in.Map("newer_group")
		gOld := mustCreateTargetedSite(t, svc, ctx, older.Str("name"), older.Str("target_framework"))
		if err := svc.AddMember(ctx, gOld.ID, h); err != nil {
			t.Fatalf("add to older group: %v", err)
		}
		gNew := mustCreateTargetedSite(t, svc, ctx, newer.Str("name"), newer.Str("target_framework"))
		if err := svc.AddMember(ctx, gNew.ID, h); err != nil {
			t.Fatalf("add to newer group: %v", err)
		}
		older.AllConsumed()
		newer.AllConsumed()

		// The view the old query trusted. Asserting what it resolves to makes
		// the defect concrete: it is a single answer for a host that belongs to
		// two groups wanting two different ones.
		var het *string
		if err := pool.QueryRow(ctx,
			`SELECT target_framework FROM host_effective_target WHERE host_id = $1`, h).
			Scan(&het); err != nil {
			t.Fatalf("read host_effective_target: %v", err)
		}
		if het == nil || *het != exp.Str("host_effective_target_resolves_to") {
			t.Errorf("host_effective_target = %v, want %q. The fixture depends on that view "+
				"disagreeing with both groups: it answers with the HOST's own override, and "+
				"failing that with the target of the group joined first", het,
				exp.Str("host_effective_target_resolves_to"))
		}

		orgDefault := in.Str("org_default")
		byID := func(id uuid.UUID) float64 {
			t.Helper()
			all, err := svc.List(ctx, orgDefault)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			for _, gr := range all {
				if gr.ID == id {
					return scorePct(t, gr.Rollup.Score.Score)
				}
			}
			t.Fatalf("group %s not listed", id)
			return 0
		}

		if got, want := byID(gOld.ID), exp.Num("older_group_pct"); got != want {
			t.Errorf("older group (target %q) = %v, want %v", older.Raw()["target_framework"], got, want)
		}
		// The one that could not be right under the old query: this group is
		// rendered with its OWN target, not the one the host joined first.
		if got, want := byID(gNew.ID), exp.Num("newer_group_pct"); got != want {
			t.Errorf("newer group = %v, want %v. Reading host_effective_target would score "+
				"this card on %q, which is this host's own override and not this group's target",
				got, want, exp.Str("host_effective_target_resolves_to"))
		}
		if bad := exp.Num("forbidden_host_override_pct"); byID(gNew.ID) == bad {
			t.Errorf("newer group = %v, the host's OWN target_framework; a member override "+
				"must not participate in a group average", bad)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// seedRuleStateFW seeds one rule carrying a framework_refs mapping.
func seedRuleStateFW(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID,
	ruleID, status, refs string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
		  (host_id, rule_id, current_status, severity, last_checked_at,
		   last_scan_id, framework_refs, first_seen_at, last_changed_at)
		VALUES ($1,$2,$3,'medium',now(),$4,$5::jsonb,now(),now())`,
		hostID, ruleID, status, corpustest.CurrentRun(t, pool, hostID), refs); err != nil {
		t.Fatalf("seed fw rule: %v", err)
	}
}

// mustCreateTargetedSite creates a manual site group carrying a compliance target.
func mustCreateTargetedSite(t *testing.T, svc *Service, ctx context.Context,
	name, target string) Group {
	t.Helper()
	g := mustCreateSite(t, svc, ctx, name)
	if _, err := svc.SetTarget(ctx, g.ID, target); err != nil {
		t.Fatalf("set target %q on %q: %v", target, name, err)
	}
	g.TargetFramework = target
	return g
}

// @ac AC-12
// AC-12: the Groups-page fleet KPI is GET /fleet/score itself.
//
// The three hosts here are the three cases where the two implementations had
// already drifted apart while both looking correct.
func TestGroupSummary_IsTheFleetScore(t *testing.T) {
	t.Run("api-groups/AC-12", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/groups.spec.yaml", "api-groups"), "AC-12")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		seedMemberWithCounts(t, pool, user, in.Map("scored_host"))

		unscanned := in.Map("unscanned_host")
		if unscanned.Int("rule_state_rows") != 0 {
			t.Fatal("fixture must leave the unscanned host with no rule state")
		}
		unscanned.AllConsumed()
		_ = seedHost(t, pool, user, "rhel", false)

		// Soft-deleted, and deliberately extreme, so counting it is visible in
		// the score rather than only in a count.
		ghost := seedMemberWithCounts(t, pool, user, in.Map("soft_deleted_host"))
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET deleted_at = now() WHERE id = $1`, ghost); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		orgDefault := in.Str("org_default")
		sum, err := svc.Summary(ctx, orgDefault)
		if err != nil {
			t.Fatalf("Summary: %v", err)
		}
		fleet, err := fleetrollup.NewService(pool).
			FleetComplianceScore(ctx, fleetrollup.WithFramework(orgDefault))
		if err != nil {
			t.Fatalf("FleetComplianceScore: %v", err)
		}

		got := scorePct(t, sum.Score.Score)
		if want := exp.Num("avg_compliance_pct"); got != want {
			t.Errorf("summary avg = %v, want %v", got, want)
		}
		// The soft-deleted host scores 0 over twenty failing rules. Counting it
		// drags the equal-host mean to 37.5.
		if bad := exp.Num("forbidden_with_deleted_pct"); got == bad {
			t.Errorf("summary avg = %v, which is the soft-deleted host entering the mean", bad)
		}
		if sum.Score.HostsScored != exp.Int("hosts_scored") {
			t.Errorf("HostsScored = %d, want %d", sum.Score.HostsScored, exp.Int("hosts_scored"))
		}
		if sum.Score.HostsWithoutScore != exp.Int("hosts_without_score") {
			t.Errorf("HostsWithoutScore = %d, want %d; the never-scanned host is reported as "+
				"unscored, not omitted", sum.Score.HostsWithoutScore, exp.Int("hosts_without_score"))
		}
		if sum.Score.HostsTotal != exp.Int("hosts_total") {
			t.Errorf("HostsTotal = %d, want %d; the soft-deleted host is not in the population",
				sum.Score.HostsTotal, exp.Int("hosts_total"))
		}

		// The equality itself, on every field, not just the score.
		if !exp.Bool("matches_fleet_score") {
			t.Fatal("fixture must require the two to match")
		}
		fleetPct := scorePct(t, fleet.Score)
		if got != fleetPct || sum.Score.HostsScored != fleet.HostsScored ||
			sum.Score.HostsWithoutScore != fleet.HostsWithoutScore ||
			sum.Score.HostsTotal != fleet.HostsTotal {
			t.Errorf("summary {%v %d %d %d} != fleet score {%v %d %d %d}; the Groups page and "+
				"the fleet KPI must be one computation",
				got, sum.Score.HostsScored, sum.Score.HostsWithoutScore, sum.Score.HostsTotal,
				fleetPct, fleet.HostsScored, fleet.HostsWithoutScore, fleet.HostsTotal)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-13
// AC-13: a soft-deleted manual member votes in nothing.
//
// The deleted member's score is deliberately extreme, so counting it moves the
// NUMBER and not only a count. Under the old CTE it was excluded from the chip
// list and included in everything else, which is the shape most likely to go
// unnoticed: the card looked consistent with itself.
func TestGroupRollup_SoftDeletedManualMemberVotesInNothing(t *testing.T) {
	t.Run("api-groups/AC-13", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/groups.spec.yaml", "api-groups"), "AC-13")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		site := mustCreateSite(t, svc, ctx, "deleted-member-site")
		active := seedMemberWithCounts(t, pool, user, in.Map("active_member"))
		if err := svc.AddMember(ctx, site.ID, active); err != nil {
			t.Fatalf("add active member: %v", err)
		}
		ghost := seedMemberWithCounts(t, pool, user, in.Map("soft_deleted_member"))
		if err := svc.AddMember(ctx, site.ID, ghost); err != nil {
			t.Fatalf("add member to delete: %v", err)
		}
		// Deleted AFTER joining, which is the real sequence: membership rows
		// outlive the host.
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET deleted_at = now() WHERE id = $1`, ghost); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		r := listOne(t, svc, ctx, site.ID)
		got := scorePct(t, r.Score.Score)
		if want := exp.Num("score_pct"); got != want {
			t.Errorf("avg = %v, want %v", got, want)
		}
		if bad := exp.Num("forbidden_with_deleted_pct"); got == bad {
			t.Errorf("avg = %v, which is the soft-deleted member still voting", bad)
		}
		if r.Hosts != exp.Int("hosts") {
			t.Errorf("hosts = %d, want %d; a deleted member is not a member",
				r.Hosts, exp.Int("hosts"))
		}
		if r.Score.HostsScored != exp.Int("hosts_scored") ||
			r.Score.HostsWithoutScore != exp.Int("hosts_without_score") {
			t.Errorf("participation = %d/%d, want %d/%d", r.Score.HostsScored,
				r.Score.HostsWithoutScore, exp.Int("hosts_scored"), exp.Int("hosts_without_score"))
		}
		// The counts too. The deleted member carries twenty failures; leaving it
		// in inflates the outcomes even where it does not move the mean much.
		if int(r.Score.Counts.Pass) != exp.Int("passing") ||
			int(r.Score.Counts.Fail) != exp.Int("failing") {
			t.Errorf("counts = %d/%d, want %d/%d", r.Score.Counts.Pass, r.Score.Counts.Fail,
				exp.Int("passing"), exp.Int("failing"))
		}
		if len(r.Members) != exp.Int("member_chips") {
			t.Errorf("member chips = %d, want %d", len(r.Members), exp.Int("member_chips"))
		}

		// ScopeGroup resolves the host set bulk actions run against, and its own
		// comment promises active members.
		_, ids, err := svc.ScopeGroup(ctx, site.ID)
		if err != nil {
			t.Fatalf("ScopeGroup: %v", err)
		}
		if len(ids) != exp.Int("scope_group_hosts") {
			t.Errorf("ScopeGroup returned %d hosts, want %d; a bulk action must not reach a "+
				"deleted host", len(ids), exp.Int("scope_group_hosts"))
		}
		for _, id := range ids {
			if id == ghost {
				t.Error("ScopeGroup returned the soft-deleted member")
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-14
// AC-14: a group score carries its members' engine provenance.
//
// One member recorded an engine and one did not. That pairing is the whole
// point: a bare list of distinct versions holds one entry in this state and the
// singular engine_version then publishes agreement that does not exist. The
// counts are what make it visible.
func TestGroupRollup_CarriesMemberEngineProvenance(t *testing.T) {
	t.Run("api-groups/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/groups.spec.yaml", "api-groups"), "AC-14")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		site := mustCreateSite(t, svc, ctx, "engine-site")
		add := func(f *specfixture.Fields) {
			h := seedMemberWithCounts(t, pool, user, f)
			if err := svc.AddMember(ctx, site.ID, h); err != nil {
				t.Fatalf("add member: %v", err)
			}
			var engine any
			if f.IsNullable("engine_version") {
				f.IsNull("engine_version")
			} else {
				v := f.Str("engine_version")
				if v == version.Kensa() {
					t.Fatalf("fixture engine %q equals this process's; the two must differ", v)
				}
				engine = v
			}
			if _, err := pool.Exec(ctx,
				`UPDATE scan_runs SET engine_version = $2 WHERE host_id = $1`, h, engine); err != nil {
				t.Fatalf("stamp engine: %v", err)
			}
			f.AllConsumed()
		}
		add(in.Map("known_engine_member"))
		add(in.Map("unknown_engine_member"))

		r := listOne(t, svc, ctx, site.ID)
		if r.Score.HostsScored != exp.Int("hosts_scored") {
			t.Fatalf("HostsScored = %d, want %d", r.Score.HostsScored, exp.Int("hosts_scored"))
		}

		wantEngines := exp.MapList("engines")
		if len(r.Score.Engines) != len(wantEngines) {
			t.Fatalf("engines = %v, want %d entries; the group used to return an empty list "+
				"even after its members recorded producers", r.Score.Engines, len(wantEngines))
		}
		for i, w := range wantEngines {
			if r.Score.Engines[i].EngineVersion != w.Str("engine_version") {
				t.Errorf("engines[%d] = %q, want %q", i,
					r.Score.Engines[i].EngineVersion, w.Str("engine_version"))
			}
			if r.Score.Engines[i].ContributorsScored != w.Int("contributors_scored") {
				t.Errorf("engines[%d].contributors_scored = %d, want %d", i,
					r.Score.Engines[i].ContributorsScored, w.Int("contributors_scored"))
			}
			w.AllConsumed()
		}
		if r.Score.HostsWithoutEngine != exp.Int("hosts_without_engine_identity") {
			t.Errorf("HostsWithoutEngine = %d, want %d; the member whose run recorded nothing "+
				"is counted, not ignored", r.Score.HostsWithoutEngine,
				exp.Int("hosts_without_engine_identity"))
		}

		// The envelope this produces: partially identified, with NO singular
		// version, because the one version present does not speak for the
		// member that named none.
		env, err := compliance.ScoreBearingEnvelope("all_rules", compliance.AggregationEqualHostMean,
			r.Score.Engines, r.Score.HostsWithoutEngine, nil, r.Score.HostsScored, r.Score.HostsScored)
		if err != nil {
			t.Fatalf("envelope: %v", err)
		}
		if string(env.EngineIdentityStatus) != exp.Str("engine_identity_status") {
			t.Errorf("engine_identity_status = %q, want %q", env.EngineIdentityStatus,
				exp.Str("engine_identity_status"))
		}
		exp.IsNull("engine_version")
		if env.EngineVersion != nil {
			t.Errorf("engine_version = %q, want null under partially_identified",
				*env.EngineVersion)
		}
		if bad := exp.Str("forbidden_engine_version"); env.EngineVersion != nil &&
			*env.EngineVersion == bad {
			t.Errorf("engine_version = %q, published as agreement when one member recorded "+
				"nothing", bad)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
