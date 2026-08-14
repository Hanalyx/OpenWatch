// @spec system-drift-detector
//
// AC traceability (this file):
//   AC-15  TestDetectForScan_MajorWorsening_PublishesDriftDetected
//   AC-16  TestDetectForScan_Stable_NoPublish
//   AC-17  TestDetectForScan_PublishCountsMatchAuditDetail
//   AC-18  TestNewService_NilBus_AuditStillFires

package drift

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/eventbus"
)

// @ac AC-15
// AC-15: major worsening detection publishes DriftDetected on the bus.
func TestDetectForScan_MajorWorsening_PublishesDriftDetected(t *testing.T) {
	t.Run("system-drift-detector/AC-15", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		bus := eventbus.NewBus()
		defer bus.Shutdown()
		sub := bus.Subscribe(eventbus.SubscribeOptions{
			Kinds: []eventbus.EventKind{eventbus.EventKindDriftDetected},
		})
		defer sub.Unsubscribe()

		// A RESCAN of eight rules the host already carried. Six flip
		// pass -> fail: prior 8/8 = 100%, current 2/8 = 25%, a 75-point
		// drop and well into major worsening.
		//
		// The eight rows carry the CURRENT scan id and the six flips
		// carry state_changed, which is what writer.Apply leaves behind
		// on a rescan. The earlier fixture seeded eight extra rows under
		// a separate prior scan id and marked every transaction
		// first_seen, a state no scan produces: the same rule cannot be
		// first_seen and also have a prior row. It only read as a
		// worsening while the current counts were unscoped and summed
		// both sets. Scoped to one scan it reads as a first-ever scan,
		// which is stable, and correctly so.
		currentScanID, _ := uuid.NewV7()
		for i := 0; i < 6; i++ {
			ruleID := "rule.now.f." + uuid.NewString()[:8]
			seedRuleState(t, pool, hostID, currentScanID, ruleID, "fail", "high")
			seedTransaction(t, pool, hostID, currentScanID, ruleID, "fail", "high", "state_changed")
		}
		for i := 0; i < 2; i++ {
			ruleID := "rule.now.p." + uuid.NewString()[:8]
			seedRuleState(t, pool, hostID, currentScanID, ruleID, "pass", "high")
		}

		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), bus)
		report, err := svc.DetectForScan(context.Background(), hostID, currentScanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}
		if report.Kind != DriftMajorWorsening {
			t.Fatalf("Kind = %q, want major_worsening", report.Kind)
		}

		select {
		case ev := <-sub.Events():
			d, ok := ev.(eventbus.DriftDetected)
			if !ok {
				t.Fatalf("got %T, want DriftDetected", ev)
			}
			if d.DriftType != "major" {
				t.Errorf("DriftType = %q, want major", d.DriftType)
			}
			if d.HostID != hostID {
				t.Errorf("HostID mismatch")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("no DriftDetected event received within 500ms")
		}
	})
}

// @ac AC-16
// AC-16: stable detection publishes nothing to the bus.
func TestDetectForScan_Stable_NoPublish(t *testing.T) {
	t.Run("system-drift-detector/AC-16", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		bus := eventbus.NewBus()
		defer bus.Shutdown()
		sub := bus.Subscribe(eventbus.SubscribeOptions{
			Kinds: []eventbus.EventKind{eventbus.EventKindDriftDetected},
		})
		defer sub.Unsubscribe()

		// Steady state: same 5 pass + 1 fail before and after.
		// Use the same scanID for both prior + current so the
		// reconstruction sees no transition.
		scanID, _ := uuid.NewV7()
		for i := 0; i < 5; i++ {
			ruleID := "rule.stable.p." + uuid.NewString()[:8]
			seedRuleState(t, pool, hostID, scanID, ruleID, "pass", "high")
			seedTransaction(t, pool, hostID, scanID, ruleID, "pass", "high", "first_seen")
		}
		ruleFailID := "rule.stable.f." + uuid.NewString()[:8]
		seedRuleState(t, pool, hostID, scanID, ruleFailID, "fail", "high")
		seedTransaction(t, pool, hostID, scanID, ruleFailID, "fail", "high", "first_seen")

		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), bus)
		_, err := svc.DetectForScan(context.Background(), hostID, scanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}

		select {
		case ev := <-sub.Events():
			t.Errorf("received unexpected DriftDetected on stable: %+v", ev)
		case <-time.After(150 * time.Millisecond):
			// Expected.
		}
	})
}

// @ac AC-17
// AC-17: published DriftDetected per-severity counts match the audit
// detail values produced from the same Report.
func TestDetectForScan_PublishCountsMatchAuditDetail(t *testing.T) {
	t.Run("system-drift-detector/AC-17", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		bus := eventbus.NewBus()
		defer bus.Shutdown()
		sub := bus.Subscribe(eventbus.SubscribeOptions{
			Kinds: []eventbus.EventKind{eventbus.EventKindDriftDetected},
		})
		defer sub.Unsubscribe()

		// Setup follows the existing AC-09 pattern: only seed CURRENT
		// state in host_rule_state; the drift detector reconstructs
		// the PRIOR via transactions.
		scanID, _ := uuid.NewV7()
		// 2 critical → fail, 1 high → fail, 2 medium stay pass.
		critRules := []string{"crit-1", "crit-2"}
		highRules := []string{"high-1"}
		passRules := []string{"pass-m-1", "pass-m-2"}

		for _, r := range critRules {
			seedRuleState(t, pool, hostID, scanID, r, "fail", "critical")
			seedTransaction(t, pool, hostID, scanID, r, "fail", "critical", "state_changed")
		}
		for _, r := range highRules {
			seedRuleState(t, pool, hostID, scanID, r, "fail", "high")
			seedTransaction(t, pool, hostID, scanID, r, "fail", "high", "state_changed")
		}
		for _, r := range passRules {
			seedRuleState(t, pool, hostID, scanID, r, "pass", "medium")
		}
		currentScanID := scanID

		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), bus)
		report, err := svc.DetectForScan(context.Background(), hostID, currentScanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}

		// Audit detail — severity counts live in detail.severity_transitions.
		var auditDetail struct {
			SeverityTransitions struct {
				CriticalBecameFailing int `json:"critical_became_failing"`
				HighBecameFailing     int `json:"high_became_failing"`
			} `json:"severity_transitions"`
		}
		mu.Lock()
		var found bool
		for _, c := range calls {
			if c.Code == audit.ComplianceDriftDetected {
				_ = json.Unmarshal(c.Event.Detail, &auditDetail)
				found = true
				break
			}
		}
		mu.Unlock()
		if !found {
			t.Fatal("compliance.drift.detected audit not emitted")
		}

		// Bus event.
		select {
		case ev := <-sub.Events():
			d, ok := ev.(eventbus.DriftDetected)
			if !ok {
				t.Fatalf("got %T", ev)
			}
			if d.CriticalBecameFailing != auditDetail.SeverityTransitions.CriticalBecameFailing {
				t.Errorf("bus CriticalBecameFailing = %d, audit detail = %d",
					d.CriticalBecameFailing, auditDetail.SeverityTransitions.CriticalBecameFailing)
			}
			if d.HighBecameFailing != auditDetail.SeverityTransitions.HighBecameFailing {
				t.Errorf("bus HighBecameFailing = %d, audit detail = %d",
					d.HighBecameFailing, auditDetail.SeverityTransitions.HighBecameFailing)
			}
			if d.CriticalBecameFailing != report.CriticalBecameFailing {
				t.Errorf("bus vs report CriticalBecameFailing mismatch")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("no DriftDetected event")
		}
	})
}

// @ac AC-18
// AC-18: NewService(pool, emit, thresholds, nil) — nil bus, audit still
// fires.
func TestNewService_NilBus_AuditStillFires(t *testing.T) {
	t.Run("system-drift-detector/AC-18", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		var mu sync.Mutex
		var calls []emitCall

		// A rescan flipping six of eight rules, so a major worsening
		// fires. Same shape as AC-15 above: one scan id across all eight
		// rows, state_changed on the flips.
		currentScanID, _ := uuid.NewV7()
		for i := 0; i < 6; i++ {
			r := "rule.f." + uuid.NewString()[:8]
			seedRuleState(t, pool, hostID, currentScanID, r, "fail", "high")
			seedTransaction(t, pool, hostID, currentScanID, r, "fail", "high", "state_changed")
		}
		for i := 0; i < 2; i++ {
			r := "rule.p2." + uuid.NewString()[:8]
			seedRuleState(t, pool, hostID, currentScanID, r, "pass", "high")
		}

		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), nil)
		_, err := svc.DetectForScan(context.Background(), hostID, currentScanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}
		// Audit should have fired (major worsening).
		if countEmissions(&mu, &calls, audit.ComplianceDriftDetected) == 0 {
			t.Error("nil bus suppressed audit emission; want audit still fires")
		}
	})
}
