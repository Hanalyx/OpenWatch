// @spec system-os-intelligence
//
// AC traceability (this file):
//
//	AC-18  TestMergeUnobserved_NoClobberAndNoFalseEvents

package collector

import "testing"

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
