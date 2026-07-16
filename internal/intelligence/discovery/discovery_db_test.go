// @spec system-host-discovery
//
// AC traceability (this file):
//
//	AC-08  TestDiscover_HappyPath_PersistsAndPublishes
//	AC-24  TestDiscover_NoClobberOnPartialCollection
//	AC-25  TestDiscover_CategoryFreshness
//	AC-27  TestDiscover_FreshnessReason

package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// freshDBHost spins up a clean DB, seeds a user + host + a host-scope
// SSH credential, and returns the host id + a usable credential.Service.
func freshDBHost(t *testing.T) (*pgxpool.Pool, uuid.UUID, *credential.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	if err := secretkey.SetEphemeral(); err != nil {
		t.Fatalf("SetEphemeral: %v", err)
	}
	// CASCADE — see scheduler/service_db_test.go for the rationale.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")

	createdBy, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		createdBy, "disc-creator", "disc@example.com", hash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	hostID, _ := uuid.NewV7()
	_, err = pool.Exec(ctx,
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		hostID, "test-host-"+hostID.String()[:8], "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	credSvc := credential.NewService(pool)
	_, err = credSvc.NewCredential(ctx, credential.NewParams{
		Scope:      credential.ScopeSystem,
		Name:       "default-disc",
		Username:   "admin",
		AuthMethod: credential.AuthPassword,
		Password:   "test-password",
		IsDefault:  true,
		CreatedBy:  createdBy,
	})
	if err != nil {
		t.Fatalf("seed system default credential: %v", err)
	}
	return pool, hostID, credSvc
}

// @ac AC-08
// AC-08: Discover end-to-end on a reachable host with a valid
// credential persists host_system_info, updates hosts.os_*, and returns
// the captured facts. The stub SSH transport stands in for a real host
// — the path through the service (lookup → resolve → dial → probe
// batch → persist → publish → audit) is otherwise the same as
// production.
func TestDiscover_HappyPath_PersistsAndPublishes(t *testing.T) {
	t.Run("system-host-discovery/AC-08", func(t *testing.T) {
		pool, hostID, credSvc := freshDBHost(t)

		stub := newStubSSHTransport()
		stub.SeedAll()

		emits := newAuditRecorder()
		bus := newStubBus()
		svc := NewService(pool, emits.Emit, bus).
			WithHostLookup(PoolHostLookup{Pool: pool}).
			WithCredentialService(credSvc).
			WithSSHTransport(stub)

		facts, err := svc.Discover(context.Background(), hostID)
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}

		// Sanity on returned facts.
		if facts.OSName == "" || facts.OSFamily == "" {
			t.Errorf("Discover returned empty OSName=%q OSFamily=%q — fixtures should have populated them", facts.OSName, facts.OSFamily)
		}
		// Spec C-08: row UPSERTed into host_system_info.
		var (
			osName string
			osFam  string
			collAt time.Time
		)
		err = pool.QueryRow(context.Background(),
			`SELECT os_name, os_family, collected_at
			   FROM host_system_info
			  WHERE host_id = $1`, hostID).Scan(&osName, &osFam, &collAt)
		if err != nil {
			t.Fatalf("read host_system_info: %v", err)
		}
		if osName == "" || osFam == "" {
			t.Errorf("host_system_info missing fields: os_name=%q os_family=%q", osName, osFam)
		}
		// Spec C-09: denormalized hosts.os_* columns also updated.
		var hostOSFam *string
		err = pool.QueryRow(context.Background(),
			`SELECT os_family FROM hosts WHERE id = $1`, hostID).Scan(&hostOSFam)
		if err != nil {
			t.Fatalf("read hosts.os_family: %v", err)
		}
		if hostOSFam == nil || *hostOSFam == "" {
			t.Errorf("hosts.os_family is empty after Discover — denormalized column not updated")
		}
		// AC-11 sanity: bus saw the event. (AC-11 has its own test too;
		// this is just defensive against silently dropping the publish.)
		if !bus.Saw("host.discovered") {
			t.Errorf("eventbus did not receive host.discovered")
		}
		// AC-12 sanity: audit emitted exactly once. (AC-12 also has its
		// own test; defensive duplication is cheap.)
		if got := emits.CountFor("host.discovery.completed"); got != 1 {
			t.Errorf("audit emits for host.discovery.completed = %d, want 1", got)
		}
	})
}

// @ac AC-24
// AC-24: a partial-collection run does not blank previously-good categories.
func TestDiscover_NoClobberOnPartialCollection(t *testing.T) {
	t.Run("system-host-discovery/AC-24", func(t *testing.T) {
		pool, hostID, _ := freshDBHost(t)
		ctx := context.Background()
		svc := &Service{pool: pool}
		allObserved := map[FactCategory]bool{
			CatOSRelease: true, CatUname: true, CatMemory: true, CatDisk: true,
			CatHostname: true, CatFQDN: true, CatSELinux: true, CatAppArmor: true, CatFirewall: true,
		}

		// First run: fully observed fingerprint.
		full := SystemFacts{
			OSName: "Rocky Linux", OSVersion: "9.4", OSID: "rocky", OSFamily: "rhel",
			KernelRelease: "5.14.0-570", Architecture: "x86_64",
			MemTotalMB: 8000, DiskTotalGB: 100, DiskUsedGB: 60, DiskFreeGB: 40,
			Hostname: "web01", SELinuxStatus: "Enforcing", AppArmorEnabled: false,
			FirewallService: "firewalld", FirewallStatus: "active",
			CollectedAt: time.Now().UTC(), Observed: allObserved,
		}
		if err := svc.persist(ctx, hostID, full); err != nil {
			t.Fatalf("first persist: %v", err)
		}

		// Second run: only os_release + uname observed; firewall/disk/selinux
		// probes failed (fields empty, categories absent from Observed).
		partial := SystemFacts{
			OSName: "Rocky Linux", OSVersion: "9.5", OSID: "rocky", OSFamily: "rhel",
			KernelRelease: "5.14.0-580", Architecture: "x86_64",
			CollectedAt: time.Now().UTC(),
			Observed:    map[FactCategory]bool{CatOSRelease: true, CatUname: true},
		}
		if err := svc.persist(ctx, hostID, partial); err != nil {
			t.Fatalf("second persist: %v", err)
		}

		var osVer, kernel, fwSvc, selinux string
		var diskFree int
		if err := pool.QueryRow(ctx, `
			SELECT os_version, kernel_release, COALESCE(firewall_service, ''),
			       COALESCE(selinux_status, ''), COALESCE(disk_free_gb, 0)
			  FROM host_system_info WHERE host_id = $1`, hostID).
			Scan(&osVer, &kernel, &fwSvc, &selinux, &diskFree); err != nil {
			t.Fatalf("read host_system_info: %v", err)
		}
		// Observed categories updated.
		if osVer != "9.5" {
			t.Errorf("os_version = %q, want 9.5 (observed, updated)", osVer)
		}
		if kernel != "5.14.0-580" {
			t.Errorf("kernel_release = %q, want 5.14.0-580 (observed, updated)", kernel)
		}
		// Unobserved categories retained prior values, NOT blanked.
		if fwSvc != "firewalld" {
			t.Errorf("firewall_service = %q, want firewalld retained (unobserved)", fwSvc)
		}
		if selinux != "Enforcing" {
			t.Errorf("selinux_status = %q, want Enforcing retained (unobserved)", selinux)
		}
		if diskFree != 40 {
			t.Errorf("disk_free_gb = %d, want 40 retained (unobserved)", diskFree)
		}

		// hosts.os_* also updated from the merged (observed) facts.
		var hOsVer string
		_ = pool.QueryRow(ctx, `SELECT COALESCE(os_version, '') FROM hosts WHERE id = $1`, hostID).Scan(&hOsVer)
		if hOsVer != "9.5" {
			t.Errorf("hosts.os_version = %q, want 9.5", hOsVer)
		}
	})
}

// @ac AC-25
// AC-25: persist stamps per-category freshness — observed categories are "ok"
// (observed_at advances), unobserved categories with a prior observation flip
// to "stale" keeping their earlier observed_at.
func TestDiscover_CategoryFreshness(t *testing.T) {
	t.Run("system-host-discovery/AC-25", func(t *testing.T) {
		pool, hostID, _ := freshDBHost(t)
		ctx := context.Background()
		svc := &Service{pool: pool}
		allObserved := map[FactCategory]bool{
			CatOSRelease: true, CatUname: true, CatMemory: true, CatDisk: true,
			CatHostname: true, CatFQDN: true, CatSELinux: true, CatAppArmor: true, CatFirewall: true,
		}

		run1 := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		if err := svc.persist(ctx, hostID, SystemFacts{
			OSVersion: "9.4", KernelRelease: "5.14.0-570", FirewallService: "firewalld",
			CollectedAt: run1, Observed: allObserved,
		}); err != nil {
			t.Fatalf("run1 persist: %v", err)
		}

		run2 := time.Now().UTC().Truncate(time.Second)
		if err := svc.persist(ctx, hostID, SystemFacts{
			OSVersion: "9.5", KernelRelease: "5.14.0-580",
			CollectedAt: run2, Observed: map[FactCategory]bool{CatOSRelease: true, CatUname: true},
		}); err != nil {
			t.Fatalf("run2 persist: %v", err)
		}

		var osStatus, fwStatus string
		var fwEarlier bool
		if err := pool.QueryRow(ctx, `
			SELECT category_freshness->'os_release'->>'status',
			       category_freshness->'firewall'->>'status',
			       (category_freshness->'firewall'->>'observed_at')::timestamptz
			         < (category_freshness->'os_release'->>'observed_at')::timestamptz
			  FROM host_system_info WHERE host_id = $1`, hostID).
			Scan(&osStatus, &fwStatus, &fwEarlier); err != nil {
			t.Fatalf("read freshness: %v", err)
		}
		if osStatus != "ok" {
			t.Errorf("os_release status = %q, want ok (observed run2)", osStatus)
		}
		if fwStatus != "stale" {
			t.Errorf("firewall status = %q, want stale (unobserved run2)", fwStatus)
		}
		if !fwEarlier {
			t.Errorf("firewall observed_at should be earlier than os_release (kept run1 time)")
		}
	})
}

// @ac AC-27
// AC-27: a stale category carries the reason it was not re-observed. A second
// run whose Attempts records firewall="denied" and disk="failed" persists those
// reasons on the stale freshness entries; an observed category has status "ok"
// with no reason; a stale category whose reason was unrecorded defaults to
// "failed", never a false "denied".
func TestDiscover_FreshnessReason(t *testing.T) {
	t.Run("system-host-discovery/AC-27", func(t *testing.T) {
		pool, hostID, _ := freshDBHost(t)
		ctx := context.Background()
		svc := &Service{pool: pool}
		allObserved := map[FactCategory]bool{
			CatOSRelease: true, CatUname: true, CatMemory: true, CatDisk: true,
			CatHostname: true, CatFQDN: true, CatSELinux: true, CatAppArmor: true, CatFirewall: true,
		}

		// Run 1: fully observed.
		if err := svc.persist(ctx, hostID, SystemFacts{
			OSVersion: "9.4", KernelRelease: "5.14.0-570", FirewallService: "firewalld",
			DiskTotalGB: 100, DiskFreeGB: 40, SELinuxStatus: "Enforcing",
			CollectedAt: time.Now().Add(-time.Hour).UTC(), Observed: allObserved,
		}); err != nil {
			t.Fatalf("run1 persist: %v", err)
		}

		// Run 2: os_release observed; firewall denied, disk failed, selinux
		// unobserved with NO recorded reason (defaults to failed).
		if err := svc.persist(ctx, hostID, SystemFacts{
			OSVersion:   "9.5",
			CollectedAt: time.Now().UTC(),
			Observed:    map[FactCategory]bool{CatOSRelease: true},
			Attempts: map[FactCategory]string{
				CatFirewall: outcomeDenied,
				CatDisk:     outcomeFailed,
			},
		}); err != nil {
			t.Fatalf("run2 persist: %v", err)
		}

		var osStatus, osReason, fwStatus, fwReason, diskReason, selinuxReason string
		if err := pool.QueryRow(ctx, `
			SELECT category_freshness->'os_release'->>'status',
			       COALESCE(category_freshness->'os_release'->>'reason', ''),
			       category_freshness->'firewall'->>'status',
			       COALESCE(category_freshness->'firewall'->>'reason', ''),
			       COALESCE(category_freshness->'disk'->>'reason', ''),
			       COALESCE(category_freshness->'selinux'->>'reason', '')
			  FROM host_system_info WHERE host_id = $1`, hostID).
			Scan(&osStatus, &osReason, &fwStatus, &fwReason, &diskReason, &selinuxReason); err != nil {
			t.Fatalf("read freshness: %v", err)
		}
		if osStatus != "ok" || osReason != "" {
			t.Errorf("os_release = {status:%q reason:%q}, want ok with no reason", osStatus, osReason)
		}
		if fwStatus != "stale" || fwReason != "denied" {
			t.Errorf("firewall = {status:%q reason:%q}, want stale/denied", fwStatus, fwReason)
		}
		if diskReason != "failed" {
			t.Errorf("disk reason = %q, want failed", diskReason)
		}
		// Unrecorded reason on a stale category defaults to failed — never denied.
		if selinuxReason != "failed" {
			t.Errorf("selinux reason = %q, want failed (unrecorded default)", selinuxReason)
		}
	})
}
