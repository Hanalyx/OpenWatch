// @spec system-os-intelligence
//
// AC traceability (this file):
//
//	AC-18  TestMergeUnobserved_NoClobberAndNoFalseEvents
//	AC-19  TestComputeSnapFreshness
//	AC-20  TestComputeSnapFreshness_Reason

package collector

import (
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/intelligence/probe"
)

// @ac AC-18
// AC-18: an unobserved category carries forward its prior value (no clobber,
// no false change event); an observed category keeps this cycle's value even
// when genuinely empty; a nil Observed map carries forward everything.
func TestMergeUnobserved_NoClobberAndNoFalseEvents(t *testing.T) {
	t.Run("system-os-intelligence/AC-18", func(t *testing.T) {
		prior := Snapshot{
			Packages: map[string]string{"openssh": "9.0"},
			Services: map[string]string{"sshd": "active"},
			Users:    map[string]UserSnapshot{"root": {}},
		}

		// This cycle observed ONLY packages; services/users probes failed (nil).
		cycle := Snapshot{
			Packages: map[string]string{"openssh": "9.6"},
			Observed: map[SnapCategory]bool{SnapPackages: true},
		}
		merged := mergeUnobserved(cycle, prior)

		// Unobserved categories carried forward, not blanked.
		if merged.Services["sshd"] != "active" {
			t.Errorf("services not carried forward: %+v", merged.Services)
		}
		if _, ok := merged.Users["root"]; !ok {
			t.Errorf("users not carried forward: %+v", merged.Users)
		}
		// Observed category kept this cycle's value.
		if merged.Packages["openssh"] != "9.6" {
			t.Errorf("packages = %+v, want observed 9.6", merged.Packages)
		}

		// Diff against prior sees only the real package change, no false
		// service/user "removed" events from the failed probes.
		events := Diff(prior, merged)
		if len(events) != 1 || events[0].Code != "system.package.updated" {
			t.Fatalf("events = %+v, want exactly one system.package.updated", events)
		}

		// Observed-but-empty overwrites (a real observation of "no services").
		cycle2 := Snapshot{
			Services: map[string]string{},
			Observed: map[SnapCategory]bool{SnapServices: true},
		}
		merged2 := mergeUnobserved(cycle2, prior)
		if len(merged2.Services) != 0 {
			t.Errorf("observed-empty services should overwrite, got %+v", merged2.Services)
		}
		if merged2.Packages["openssh"] != "9.0" {
			t.Errorf("packages (unobserved) not carried forward in cycle2: %+v", merged2.Packages)
		}

		// Nil Observed → carry forward everything (safe default).
		merged3 := mergeUnobserved(Snapshot{}, prior)
		if merged3.Packages["openssh"] != "9.0" || merged3.Services["sshd"] != "active" {
			t.Errorf("nil Observed should carry forward all: %+v", merged3)
		}
	})
}

// @ac AC-19
// AC-19: computeSnapFreshness stamps observed→ok (observed_at=now),
// unobserved-with-prior→stale (prior observed_at kept, attempt advances), and
// omits never-observed categories.
func TestComputeSnapFreshness(t *testing.T) {
	t.Run("system-os-intelligence/AC-19", func(t *testing.T) {
		now := time.Now().UTC()
		earlier := now.Add(-time.Hour)
		prior := map[string]snapFreshnessEntry{
			"packages": {ObservedAt: earlier, AttemptAt: earlier, Status: "ok"},
			"services": {ObservedAt: earlier, AttemptAt: earlier, Status: "ok"},
		}

		out := computeSnapFreshness(map[SnapCategory]bool{SnapPackages: true}, nil, prior, now)

		if e := out["packages"]; e.Status != "ok" || !e.ObservedAt.Equal(now) {
			t.Errorf("packages = %+v, want ok observed_at=now", e)
		}
		if e := out["services"]; e.Status != "stale" || !e.ObservedAt.Equal(earlier) || !e.AttemptAt.Equal(now) {
			t.Errorf("services = %+v, want stale keeping earlier observed_at, attempt=now", e)
		}
		if _, ok := out["users"]; ok {
			t.Errorf("users should be absent (never observed, no prior)")
		}

		if out2 := computeSnapFreshness(map[SnapCategory]bool{}, nil, nil, now); len(out2) != 0 {
			t.Errorf("nil prior + nothing observed should be empty, got %+v", out2)
		}
	})
}

// @ac AC-20
// AC-20: a stale category carries the reason it was not re-observed, from the
// cycle's Attempts map; an unrecorded cause defaults to "failed", never a false
// "denied".
func TestComputeSnapFreshness_Reason(t *testing.T) {
	t.Run("system-os-intelligence/AC-20", func(t *testing.T) {
		now := time.Now().UTC()
		earlier := now.Add(-time.Hour)
		prior := map[string]snapFreshnessEntry{
			"services":        {ObservedAt: earlier, AttemptAt: earlier, Status: "ok"},
			"packages":        {ObservedAt: earlier, AttemptAt: earlier, Status: "ok"},
			"listening_ports": {ObservedAt: earlier, AttemptAt: earlier, Status: "ok"},
		}
		attempts := map[SnapCategory]string{
			SnapServices: probe.OutcomeDenied,
			SnapPackages: probe.OutcomeTimeout,
			// listening_ports unobserved with NO recorded reason → defaults to failed.
		}

		out := computeSnapFreshness(map[SnapCategory]bool{}, attempts, prior, now)

		if e := out["services"]; e.Status != "stale" || e.Reason != "denied" {
			t.Errorf("services = %+v, want stale/denied", e)
		}
		if e := out["packages"]; e.Status != "stale" || e.Reason != "timeout" {
			t.Errorf("packages = %+v, want stale/timeout", e)
		}
		if e := out["listening_ports"]; e.Status != "stale" || e.Reason != "failed" {
			t.Errorf("listening_ports = %+v, want stale/failed (unrecorded default)", e)
		}
		// An observed category carries no reason.
		out2 := computeSnapFreshness(map[SnapCategory]bool{SnapServices: true}, attempts, prior, now)
		if e := out2["services"]; e.Status != "ok" || e.Reason != "" {
			t.Errorf("observed services = %+v, want ok with no reason", e)
		}
	})
}
