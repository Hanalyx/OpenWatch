// @spec api-groups
//
// DB-backed service AC coverage (DSN-gated). The pure-validation guards
// are covered in service_test.go (AC-01 short-circuits with a nil pool);
// these exercise the real schema (migration 0027 plus hosts / liveness /
// rule_state) against a Postgres reachable via OPENWATCH_TEST_DSN. The
// endpoint RBAC + status mapping AC (AC-09) lives in internal/server.
//
//	AC-01  TestCreate_RoundTripAndColorDefault (happy-path half; guards in service_test.go)
//	AC-02  TestCreate_DuplicateAutoFamily
//	AC-03  TestAutoMembership_DerivedNotStored
//	AC-04  TestManualMembership_AddRemoveIdempotent
//	AC-05  TestUpdateDeleteNotFound
//	AC-06  TestSetMaintenance
//	AC-07  TestRollup_LivenessAndCompliance
//	AC-08  TestSummary_Counts

package group

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE group_members CASCADE",
		"TRUNCATE TABLE groups CASCADE",
		"TRUNCATE TABLE host_rule_state CASCADE",
		"TRUNCATE TABLE host_liveness CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "grp-"+id.String(), id.String()+"@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// seedHost inserts an active host with the given os_family. deleted is
// applied as a soft-delete after insert when set.
func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID, osFamily string, deleted bool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, os_family, created_by)
		 VALUES ($1, $2, '192.0.2.40'::inet, $3, $4)`,
		id, "host-"+id.String(), nullIfEmpty(osFamily), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	if deleted {
		if _, err := pool.Exec(context.Background(),
			`UPDATE hosts SET deleted_at = now() WHERE id = $1`, id); err != nil {
			t.Fatalf("soft-delete host: %v", err)
		}
	}
	return id
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func seedLiveness(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, status string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_liveness (host_id, reachability_status) VALUES ($1, $2)`,
		hostID, status)
	if err != nil {
		t.Fatalf("seed liveness: %v", err)
	}
}

func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, severity string) {
	t.Helper()
	now := time.Now()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_rule_state
		   (host_id, rule_id, current_status, severity, last_checked_at,
		    last_scan_id, first_seen_at, last_changed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $5, $5)`,
		hostID, ruleID, status, nullIfEmpty(severity), now, uuid.New())
	if err != nil {
		t.Fatalf("seed rule_state: %v", err)
	}
}

// @ac AC-01
// Happy-path Create: a manual site and an auto os_category both insert and
// round-trip their fields, and an empty color defaults to "info". The
// rejection guards are in service_test.go (nil-pool short-circuit).
func TestCreate_RoundTripAndColorDefault(t *testing.T) {
	t.Run("api-groups/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)

		site, err := svc.Create(ctx, CreateInput{
			Name: "Production", Kind: KindSite, Subtype: "Environment", Membership: MembershipManual,
		})
		if err != nil {
			t.Fatalf("create site: %v", err)
		}
		if site.Kind != KindSite || site.Membership != MembershipManual || site.MatchFamily != "" {
			t.Errorf("site round-trip = %+v", site)
		}
		if site.Color != "info" {
			t.Errorf("empty color = %q, want info default", site.Color)
		}

		auto, err := svc.Create(ctx, CreateInput{
			Name: "RHEL", Kind: KindOSCategory, Color: "rhel",
			Membership: MembershipAuto, MatchFamily: "rhel",
		})
		if err != nil {
			t.Fatalf("create auto: %v", err)
		}
		if auto.Membership != MembershipAuto || auto.MatchFamily != "rhel" || auto.Color != "rhel" {
			t.Errorf("auto round-trip = %+v", auto)
		}
	})
}

// @ac AC-02
func TestCreate_DuplicateAutoFamily(t *testing.T) {
	t.Run("api-groups/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)

		if _, err := svc.Create(ctx, CreateInput{
			Name: "RHEL", Kind: KindOSCategory, Membership: MembershipAuto, MatchFamily: "rhel",
		}); err != nil {
			t.Fatalf("first auto rhel: %v", err)
		}
		// A second auto group for the same family is rejected.
		if _, err := svc.Create(ctx, CreateInput{
			Name: "RHEL hosts", Kind: KindOSCategory, Membership: MembershipAuto, MatchFamily: "rhel",
		}); err != ErrDuplicateFamily {
			t.Errorf("dup auto err = %v, want ErrDuplicateFamily", err)
		}
		// A MANUAL workload group naming the same family is unaffected: the
		// partial unique index covers only membership=auto rows.
		if _, err := svc.Create(ctx, CreateInput{
			Name: "Database", Kind: KindOSCategory, Subtype: "rhel", Membership: MembershipManual,
		}); err != nil {
			t.Errorf("manual group with same-named subtype rejected: %v", err)
		}
	})
}

// @ac AC-03
func TestAutoMembership_DerivedNotStored(t *testing.T) {
	t.Run("api-groups/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		seedHost(t, pool, owner, "rhel", false)
		seedHost(t, pool, owner, "rhel", false)
		seedHost(t, pool, owner, "ubuntu", false) // different family: excluded
		seedHost(t, pool, owner, "rhel", true)    // soft-deleted: excluded

		auto, err := svc.Create(ctx, CreateInput{
			Name: "RHEL", Kind: KindOSCategory, Membership: MembershipAuto, MatchFamily: "rhel",
		})
		if err != nil {
			t.Fatalf("create auto: %v", err)
		}

		got := listOne(t, svc, ctx, auto.ID)
		if got.Hosts != 2 {
			t.Errorf("derived member count = %d, want 2", got.Hosts)
		}
		// No group_members rows were written for the auto group.
		var stored int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM group_members WHERE group_id = $1`, auto.ID).Scan(&stored); err != nil {
			t.Fatalf("count members: %v", err)
		}
		if stored != 0 {
			t.Errorf("auto group stored %d group_members rows, want 0", stored)
		}

		// A newly discovered matching host joins with no backfill.
		seedHost(t, pool, owner, "rhel", false)
		if got := listOne(t, svc, ctx, auto.ID); got.Hosts != 3 {
			t.Errorf("after new host, member count = %d, want 3", got.Hosts)
		}

		// AddMember on an auto group is rejected.
		victim := seedHost(t, pool, owner, "ubuntu", false)
		if err := svc.AddMember(ctx, auto.ID, victim); err == nil {
			t.Errorf("AddMember on auto group did not error")
		}
	})
}

// @ac AC-04
func TestManualMembership_AddRemoveIdempotent(t *testing.T) {
	t.Run("api-groups/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		site, err := svc.Create(ctx, CreateInput{Name: "DR", Kind: KindSite, Membership: MembershipManual})
		if err != nil {
			t.Fatalf("create site: %v", err)
		}
		h := seedHost(t, pool, owner, "rhel", false)

		if err := svc.AddMember(ctx, site.ID, h); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		// Adding the same host twice does not duplicate the membership.
		if err := svc.AddMember(ctx, site.ID, h); err != nil {
			t.Fatalf("AddMember (again): %v", err)
		}
		if got := listOne(t, svc, ctx, site.ID); got.Hosts != 1 {
			t.Errorf("after double-add, member count = %d, want 1", got.Hosts)
		}

		if err := svc.RemoveMember(ctx, site.ID, h); err != nil {
			t.Fatalf("RemoveMember: %v", err)
		}
		if got := listOne(t, svc, ctx, site.ID); got.Hosts != 0 {
			t.Errorf("after remove, member count = %d, want 0", got.Hosts)
		}
	})
}

// @ac AC-05
func TestUpdateDeleteNotFound(t *testing.T) {
	t.Run("api-groups/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		auto, err := svc.Create(ctx, CreateInput{
			Name: "RHEL", Kind: KindOSCategory, Membership: MembershipAuto, MatchFamily: "rhel",
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		// Update patches name/subtype/color only; kind/membership/family stay.
		upd, err := svc.Update(ctx, auto.ID, UpdateInput{Name: "RHEL 9", Subtype: "OS family", Color: "rhel"})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if upd.Name != "RHEL 9" || upd.Subtype != "OS family" ||
			upd.Kind != KindOSCategory || upd.Membership != MembershipAuto || upd.MatchFamily != "rhel" {
			t.Errorf("update mutated immutable fields: %+v", upd)
		}
		// Empty name -> ErrEmptyName; empty color defaults to info.
		if _, err := svc.Update(ctx, auto.ID, UpdateInput{Name: ""}); err != ErrEmptyName {
			t.Errorf("empty-name Update err = %v, want ErrEmptyName", err)
		}
		blanked, err := svc.Update(ctx, auto.ID, UpdateInput{Name: "RHEL", Color: ""})
		if err != nil || blanked.Color != "info" {
			t.Errorf("empty-color Update = %+v, err %v; want color info", blanked, err)
		}

		ghost := uuid.New()
		if _, err := svc.Get(ctx, ghost); err != ErrNotFound {
			t.Errorf("Get(unknown) err = %v, want ErrNotFound", err)
		}
		if _, err := svc.Update(ctx, ghost, UpdateInput{Name: "x"}); err != ErrNotFound {
			t.Errorf("Update(unknown) err = %v, want ErrNotFound", err)
		}
		if err := svc.Delete(ctx, ghost); err != ErrNotFound {
			t.Errorf("Delete(unknown) err = %v, want ErrNotFound", err)
		}

		// Delete cascades group_members.
		site, _ := svc.Create(ctx, CreateInput{Name: "Prod", Kind: KindSite, Membership: MembershipManual})
		h := seedHost(t, pool, owner, "rhel", false)
		if err := svc.AddMember(ctx, site.ID, h); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		if err := svc.Delete(ctx, site.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		var remaining int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM group_members WHERE group_id = $1`, site.ID).Scan(&remaining); err != nil {
			t.Fatalf("count members after delete: %v", err)
		}
		if remaining != 0 {
			t.Errorf("group_members not cascaded: %d rows remain", remaining)
		}
	})
}

// @ac AC-06
func TestSetMaintenance(t *testing.T) {
	t.Run("api-groups/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)

		g, err := svc.Create(ctx, CreateInput{Name: "Prod", Kind: KindSite, Membership: MembershipManual})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if g.Maintenance {
			t.Fatalf("new group should not be in maintenance")
		}

		on, err := svc.SetMaintenance(ctx, g.ID, true)
		if err != nil || !on.Maintenance {
			t.Fatalf("SetMaintenance(on) = %+v, err %v", on, err)
		}
		if !on.UpdatedAt.After(g.UpdatedAt) && !on.UpdatedAt.Equal(g.UpdatedAt) {
			t.Errorf("updated_at not bumped: %v -> %v", g.UpdatedAt, on.UpdatedAt)
		}
		off, err := svc.SetMaintenance(ctx, g.ID, false)
		if err != nil || off.Maintenance {
			t.Fatalf("SetMaintenance(off) = %+v, err %v", off, err)
		}
		if _, err := svc.SetMaintenance(ctx, uuid.New(), true); err != ErrNotFound {
			t.Errorf("SetMaintenance(unknown) err = %v, want ErrNotFound", err)
		}
	})
}

// @ac AC-07
func TestRollup_LivenessAndCompliance(t *testing.T) {
	t.Run("api-groups/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		site, err := svc.Create(ctx, CreateInput{Name: "Prod", Kind: KindSite, Membership: MembershipManual})
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		// h1: reachable, all passing (2/2). h2: unreachable, 1 pass + 1
		// failing-critical (1/2). Group avg = 3 pass / 4 evaluated = 75%.
		h1 := seedHost(t, pool, owner, "rhel", false)
		h2 := seedHost(t, pool, owner, "rhel", false)
		seedLiveness(t, pool, h1, "reachable")
		seedLiveness(t, pool, h2, "unreachable")
		seedRuleState(t, pool, h1, "r-a", "pass", "medium")
		seedRuleState(t, pool, h1, "r-b", "pass", "medium")
		seedRuleState(t, pool, h2, "r-a", "pass", "medium")
		seedRuleState(t, pool, h2, "r-c", "fail", "critical")
		if err := svc.AddMember(ctx, site.ID, h1); err != nil {
			t.Fatalf("add h1: %v", err)
		}
		if err := svc.AddMember(ctx, site.ID, h2); err != nil {
			t.Fatalf("add h2: %v", err)
		}

		r := listOne(t, svc, ctx, site.ID)
		if r.Hosts != 2 || r.Online != 1 || r.Down != 1 {
			t.Errorf("rollup hosts/online/down = %d/%d/%d, want 2/1/1", r.Hosts, r.Online, r.Down)
		}
		if r.CriticalHosts != 1 {
			t.Errorf("critical_hosts = %d, want 1", r.CriticalHosts)
		}
		if r.AvgCompliancePct == nil || *r.AvgCompliancePct != 75 {
			t.Errorf("avg_compliance_pct = %v, want 75", r.AvgCompliancePct)
		}
		if len(r.Members) != 2 {
			t.Errorf("member chips = %d, want 2", len(r.Members))
		}

		// A group whose members have no evaluated rule_state reports nil.
		empty, _ := svc.Create(ctx, CreateInput{Name: "DR", Kind: KindSite, Membership: MembershipManual})
		hNew := seedHost(t, pool, owner, "rhel", false)
		if err := svc.AddMember(ctx, empty.ID, hNew); err != nil {
			t.Fatalf("add hNew: %v", err)
		}
		if er := listOne(t, svc, ctx, empty.ID); er.AvgCompliancePct != nil {
			t.Errorf("unscanned group avg = %v, want nil", er.AvgCompliancePct)
		}
	})
}

// @ac AC-08
func TestSummary_Counts(t *testing.T) {
	t.Run("api-groups/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		site, _ := svc.Create(ctx, CreateInput{Name: "Prod", Kind: KindSite, Membership: MembershipManual})
		auto, _ := svc.Create(ctx, CreateInput{
			Name: "RHEL", Kind: KindOSCategory, Membership: MembershipAuto, MatchFamily: "rhel",
		})

		// Hosts: hRhel auto-matches the RHEL group; hSite is a manual member
		// of the (maintenance) site; hFree matches nothing. One rule each so
		// fleet avg is computable.
		hRhel := seedHost(t, pool, owner, "rhel", false)
		hSite := seedHost(t, pool, owner, "ubuntu", false)
		hFree := seedHost(t, pool, owner, "debian", false)
		seedRuleState(t, pool, hRhel, "r-a", "pass", "medium")
		seedRuleState(t, pool, hSite, "r-a", "fail", "medium")
		seedRuleState(t, pool, hFree, "r-a", "pass", "medium")
		if err := svc.AddMember(ctx, site.ID, hSite); err != nil {
			t.Fatalf("add hSite: %v", err)
		}
		if _, err := svc.SetMaintenance(ctx, site.ID, true); err != nil {
			t.Fatalf("maintenance: %v", err)
		}

		sum, err := svc.Summary(ctx)
		if err != nil {
			t.Fatalf("Summary: %v", err)
		}
		if sum.Groups != 2 || sum.Sites != 1 || sum.OSCategories != 1 {
			t.Errorf("counts groups/sites/os = %d/%d/%d, want 2/1/1", sum.Groups, sum.Sites, sum.OSCategories)
		}
		// hSite is the only host in a maintenance group.
		if sum.HostsMaintenance != 1 {
			t.Errorf("hosts_maintenance = %d, want 1", sum.HostsMaintenance)
		}
		// hFree is ungrouped (no manual group, no auto match). hRhel is in
		// the auto group; hSite is a manual member.
		if sum.Ungrouped != 1 {
			t.Errorf("ungrouped = %d, want 1", sum.Ungrouped)
		}
		// Fleet avg over 3 evaluated rows (2 pass) = 67%.
		if sum.AvgCompliancePct == nil || *sum.AvgCompliancePct != 67 {
			t.Errorf("fleet avg = %v, want 67", sum.AvgCompliancePct)
		}
		_ = auto
	})
}

// listOne returns the rollup for a single group id from List, failing the
// test if the group is absent.
func listOne(t *testing.T, svc *Service, ctx context.Context, id uuid.UUID) Rollup {
	t.Helper()
	all, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, g := range all {
		if g.ID == id {
			return g.Rollup
		}
	}
	t.Fatalf("group %s not found in List", id)
	return Rollup{}
}
