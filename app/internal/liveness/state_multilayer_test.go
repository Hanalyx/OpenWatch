// @spec system-liveness-loop
//
// AC traceability (this file):
//
//	AC-28  TestAdvanceCounters_PerLayerIncrement
//	AC-29  TestDeriveMonitoringState_FailingLayerPicksBand
//	AC-30  TestDeriveMonitoringState_HysteresisHoldsPriorBand
//	AC-31  TestBandForMultiLayer_RecoveryNeedsConsecutiveSuccesses

package liveness

import (
	"errors"
	"testing"
)

// @ac AC-28
// AC-28: AdvanceCounters increments the failing layer's failure counter
// and resets its success counter; layers not attempted are unchanged.
func TestAdvanceCounters_PerLayerIncrement(t *testing.T) {
	t.Run("system-liveness-loop/AC-28", func(t *testing.T) {
		t.Run("ping fails — only ping counters move", func(t *testing.T) {
			prev := LayerCounters{PingOK: 3, SSHOK: 5, PrivilegeOK: 7}
			r := MultiLayerResult{PingErr: errors.New("icmp_timeout"), FirstFailedLayer: LayerPing}
			got := AdvanceCounters(prev, r)
			if got.PingFail != 1 || got.PingOK != 0 {
				t.Errorf("ping: fail=%d ok=%d, want 1 / 0", got.PingFail, got.PingOK)
			}
			if got.SSHOK != 5 || got.PrivilegeOK != 7 {
				t.Errorf("untouched layers got mutated: %+v", got)
			}
		})
		t.Run("ssh fails — only ssh counters move", func(t *testing.T) {
			prev := LayerCounters{PingOK: 1, SSHOK: 4}
			r := MultiLayerResult{
				PingOK: true, SSHAttempted: true, SSHOK: false,
				SSHErr: errors.New("banner_mismatch"), FirstFailedLayer: LayerSSH,
			}
			got := AdvanceCounters(prev, r)
			if got.SSHFail != 1 || got.SSHOK != 0 {
				t.Errorf("ssh: fail=%d ok=%d, want 1 / 0", got.SSHFail, got.SSHOK)
			}
			if got.PingOK != 2 {
				t.Errorf("ping success should have advanced: %d", got.PingOK)
			}
		})
		t.Run("privilege fails — only privilege counters move", func(t *testing.T) {
			prev := LayerCounters{PingOK: 1, SSHOK: 1, PrivilegeOK: 2}
			r := MultiLayerResult{
				PingOK: true, SSHAttempted: true, SSHOK: true,
				PrivilegeAttempted: true, PrivilegeOK: false,
				PrivilegeErr:       errors.New("sudo -n true: exit 1"),
				FirstFailedLayer:   LayerPrivilege,
			}
			got := AdvanceCounters(prev, r)
			if got.PrivilegeFail != 1 || got.PrivilegeOK != 0 {
				t.Errorf("priv: fail=%d ok=%d, want 1 / 0", got.PrivilegeFail, got.PrivilegeOK)
			}
			if got.PingOK != 2 || got.SSHOK != 2 {
				t.Errorf("upper layers should have advanced: %+v", got)
			}
		})
		t.Run("layers not attempted leave counters frozen", func(t *testing.T) {
			prev := LayerCounters{PingOK: 1, SSHOK: 5, SSHFail: 0, PrivilegeOK: 8, PrivilegeFail: 0}
			r := MultiLayerResult{
				PingErr: errors.New("icmp_timeout"), FirstFailedLayer: LayerPing,
				// SSHAttempted=false, PrivilegeAttempted=false
			}
			got := AdvanceCounters(prev, r)
			if got.SSHOK != 5 || got.SSHFail != 0 {
				t.Errorf("ssh frozen: got %+v", got)
			}
			if got.PrivilegeOK != 8 || got.PrivilegeFail != 0 {
				t.Errorf("priv frozen: got %+v", got)
			}
		})
	})
}

// @ac AC-29
// AC-29: DeriveMonitoringState maps the failing layer to the right
// band once the per-layer threshold is crossed.
func TestDeriveMonitoringState_FailingLayerPicksBand(t *testing.T) {
	t.Run("system-liveness-loop/AC-29", func(t *testing.T) {
		thr := DefaultMultiLayerThresholds()

		cases := []struct {
			name  string
			prior MonitoringState
			c     LayerCounters
			r     MultiLayerResult
			want  MonitoringState
		}{
			{
				name:  "ping fails 3× from online → down",
				prior: StateOnline,
				c:     LayerCounters{PingFail: 3},
				r:     MultiLayerResult{FirstFailedLayer: LayerPing},
				want:  StateDown,
			},
			{
				name:  "ssh fails 2× from online → critical",
				prior: StateOnline,
				c:     LayerCounters{PingOK: 5, SSHFail: 2},
				r:     MultiLayerResult{PingOK: true, SSHAttempted: true, FirstFailedLayer: LayerSSH},
				want:  StateCritical,
			},
			{
				name:  "privilege fails 2× from online → degraded",
				prior: StateOnline,
				c:     LayerCounters{PingOK: 5, SSHOK: 5, PrivilegeFail: 2},
				r: MultiLayerResult{
					PingOK: true, SSHAttempted: true, SSHOK: true,
					PrivilegeAttempted: true, FirstFailedLayer: LayerPrivilege,
				},
				want: StateDegraded,
			},
			{
				name:  "all layers pass → online",
				prior: StateOnline,
				c:     LayerCounters{PingOK: 10, SSHOK: 10, PrivilegeOK: 10},
				r: MultiLayerResult{
					PingOK: true, SSHAttempted: true, SSHOK: true,
					PrivilegeAttempted: true, PrivilegeOK: true,
					FirstFailedLayer: LayerNone,
				},
				want: StateOnline,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := DeriveMonitoringState(tc.prior, tc.c, thr, tc.r)
				if got != tc.want {
					t.Errorf("got=%s, want=%s", got, tc.want)
				}
			})
		}
	})
}

// @ac AC-30
// AC-30: A single failure below threshold does NOT flap a stable host
// down past one band — hysteresis keeps the operator from drowning
// in transient blips.
func TestDeriveMonitoringState_HysteresisHoldsPriorBand(t *testing.T) {
	t.Run("system-liveness-loop/AC-30", func(t *testing.T) {
		thr := DefaultMultiLayerThresholds()

		t.Run("1 ping fail from online → critical (one step), not down", func(t *testing.T) {
			c := LayerCounters{PingFail: 1}
			r := MultiLayerResult{FirstFailedLayer: LayerPing}
			got := DeriveMonitoringState(StateOnline, c, thr, r)
			if got == StateDown {
				t.Errorf("flapped to down on first failure; want intermediate band")
			}
			if got != StateCritical {
				t.Errorf("got %s, want critical (one-step degradation)", got)
			}
		})

		t.Run("1 sudo fail from online → degraded (one step)", func(t *testing.T) {
			c := LayerCounters{PingOK: 5, SSHOK: 5, PrivilegeFail: 1}
			r := MultiLayerResult{
				PingOK: true, SSHAttempted: true, SSHOK: true,
				PrivilegeAttempted: true, FirstFailedLayer: LayerPrivilege,
			}
			// PrivilegeFailuresToDegraded is 2; first failure should hold.
			got := DeriveMonitoringState(StateOnline, c, thr, r)
			if got != StateOnline {
				t.Errorf("got %s, want online (held below threshold)", got)
			}
		})

		t.Run("2nd sudo fail crosses threshold → degraded", func(t *testing.T) {
			c := LayerCounters{PingOK: 5, SSHOK: 5, PrivilegeFail: 2}
			r := MultiLayerResult{
				PingOK: true, SSHAttempted: true, SSHOK: true,
				PrivilegeAttempted: true, FirstFailedLayer: LayerPrivilege,
			}
			got := DeriveMonitoringState(StateOnline, c, thr, r)
			if got != StateDegraded {
				t.Errorf("got %s, want degraded (threshold reached)", got)
			}
		})
	})
}

// @ac AC-31
// AC-31: Recovery from a bad band requires SuccessesToOnline
// consecutive passes on every attempted layer — a single good probe
// doesn't immediately flip a host back to online.
func TestBandForMultiLayer_RecoveryNeedsConsecutiveSuccesses(t *testing.T) {
	t.Run("system-liveness-loop/AC-31", func(t *testing.T) {
		thr := DefaultMultiLayerThresholds() // SuccessesToOnline = 3

		// Host is in 'down'. First good probe arrives.
		prior := LayerCounters{PingFail: 5}
		r := MultiLayerResult{
			PingOK: true, SSHAttempted: true, SSHOK: true,
			PrivilegeAttempted: true, PrivilegeOK: true,
			FirstFailedLayer: LayerNone,
		}
		nextC, band, changed := BandForMultiLayer(StateDown, prior, thr, r)
		if band == StateOnline {
			t.Errorf("flapped from down→online on a single success probe")
		}
		if changed {
			t.Errorf("band changed unexpectedly: %s", band)
		}
		if nextC.PingOK != 1 || nextC.SSHOK != 1 || nextC.PrivilegeOK != 1 {
			t.Errorf("counters: %+v", nextC)
		}

		// Second good probe.
		_, band, _ = BandForMultiLayer(band, nextC, thr,
			MultiLayerResult{
				PingOK: true, SSHAttempted: true, SSHOK: true,
				PrivilegeAttempted: true, PrivilegeOK: true,
			})
		if band == StateOnline {
			t.Errorf("flapped online after only 2 successes; want >= 3")
		}

		// Third good probe — counters PingOK/SSHOK/PrivilegeOK now 3 each.
		c3 := LayerCounters{PingOK: 3, SSHOK: 3, PrivilegeOK: 3}
		_, band, changed = BandForMultiLayer(StateDown, c3, thr,
			MultiLayerResult{
				PingOK: true, SSHAttempted: true, SSHOK: true,
				PrivilegeAttempted: true, PrivilegeOK: true,
			})
		if band != StateOnline {
			t.Errorf("got %s, want online after 3 consecutive successes", band)
		}
		if !changed {
			t.Errorf("change flag must be true on online transition")
		}
	})
}
