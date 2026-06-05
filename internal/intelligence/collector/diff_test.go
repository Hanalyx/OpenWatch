// @spec system-os-intelligence
//
// AC traceability (this file):
//
//	AC-06  TestDiff_PackageUpdated
//	AC-07  TestDiff_PortOpened
//	AC-08  TestDiff_PrivilegedGroupAdded
//	AC-13  TestDiff_NoChangesEmitsZeroEvents

package collector

import (
	"testing"
)

// @ac AC-06
// AC-06: package version changed between cycles → one
// system.package.updated event with prior + current.
func TestDiff_PackageUpdated(t *testing.T) {
	t.Run("system-os-intelligence/AC-06", func(t *testing.T) {
		prior := Snapshot{Packages: map[string]string{"openssh": "9.0"}}
		current := Snapshot{Packages: map[string]string{"openssh": "9.6"}}
		events := Diff(prior, current)
		if len(events) != 1 {
			t.Fatalf("Diff returned %d events, want 1: %+v", len(events), events)
		}
		ev := events[0]
		if ev.Code != "system.package.updated" {
			t.Errorf("Diff code=%q, want system.package.updated", ev.Code)
		}
		if ev.Detail["name"] != "openssh" {
			t.Errorf("detail.name=%v, want openssh", ev.Detail["name"])
		}
		if ev.Detail["prior"] != "9.0" {
			t.Errorf("detail.prior=%v, want 9.0", ev.Detail["prior"])
		}
		if ev.Detail["current"] != "9.6" {
			t.Errorf("detail.current=%v, want 9.6", ev.Detail["current"])
		}
	})
}

// @ac AC-07
// AC-07: a new listening port → one security.port.opened. Unchanged
// ports do NOT emit.
func TestDiff_PortOpened(t *testing.T) {
	t.Run("system-os-intelligence/AC-07", func(t *testing.T) {
		prior := Snapshot{ListeningPorts: []ListeningPort{{Port: 22, Protocol: "tcp"}}}
		current := Snapshot{ListeningPorts: []ListeningPort{
			{Port: 22, Protocol: "tcp"},
			{Port: 443, Protocol: "tcp"},
		}}
		events := Diff(prior, current)
		var portEvents []Event
		for _, ev := range events {
			if ev.Code == "security.port.opened" {
				portEvents = append(portEvents, ev)
			}
		}
		if len(portEvents) != 1 {
			t.Fatalf("port.opened count=%d, want 1; full events=%+v", len(portEvents), events)
		}
		if got, ok := portEvents[0].Detail["port"].(int); !ok || got != 443 {
			t.Errorf("port.opened detail.port=%v, want 443", portEvents[0].Detail["port"])
		}
	})
}

// @ac AC-08
// AC-08: a user newly in the wheel group → one
// account.user.privileged_group_added event.
func TestDiff_PrivilegedGroupAdded(t *testing.T) {
	t.Run("system-os-intelligence/AC-08", func(t *testing.T) {
		prior := Snapshot{Groups: map[string][]string{"wheel": {"root"}}}
		current := Snapshot{Groups: map[string][]string{"wheel": {"root", "alice"}}}
		events := Diff(prior, current)
		var added []Event
		for _, ev := range events {
			if ev.Code == "account.user.privileged_group_added" {
				added = append(added, ev)
			}
		}
		if len(added) != 1 {
			t.Fatalf("privileged_group_added count=%d, want 1; full events=%+v", len(added), events)
		}
		if added[0].Detail["user"] != "alice" {
			t.Errorf("detail.user=%v, want alice", added[0].Detail["user"])
		}
		if added[0].Detail["group"] != "wheel" {
			t.Errorf("detail.group=%v, want wheel", added[0].Detail["group"])
		}
	})
}

// @ac AC-13
// AC-13: identical snapshots → zero events.
func TestDiff_NoChangesEmitsZeroEvents(t *testing.T) {
	t.Run("system-os-intelligence/AC-13", func(t *testing.T) {
		snap := Snapshot{
			Packages:       map[string]string{"openssh": "9.0"},
			ListeningPorts: []ListeningPort{{Port: 22, Protocol: "tcp"}},
			Groups:         map[string][]string{"wheel": {"root"}},
		}
		events := Diff(snap, snap)
		if len(events) != 0 {
			t.Errorf("Diff on identical snapshots emitted %d events, want 0", len(events))
		}
	})
}
