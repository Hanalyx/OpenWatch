// @spec system-alert-router
//
// AC traceability (this file):
//   AC-01  TestAlertTypeEnum_HasExactlyFiveValues
//   AC-02  TestSeverityEnum_HasExactlyFiveValues_OrderPreserved
//   AC-15  TestValidateDedupTTL_RangeCheck

package alertrouter

import (
	"errors"
	"testing"
	"time"
)

// @ac AC-01
// AC-01: AlertType enum has exactly 5 values listed in AllAlertTypes.
func TestAlertTypeEnum_HasExactlyFiveValues(t *testing.T) {
	t.Run("system-alert-router/AC-01", func(t *testing.T) {
		if len(AllAlertTypes) != 5 {
			t.Errorf("AllAlertTypes = %d, want 5", len(AllAlertTypes))
		}
		expected := map[AlertType]bool{
			AlertTypeHostUnreachable:  false,
			AlertTypeHostRecovered:    false,
			AlertTypeDriftMajor:       false,
			AlertTypeDriftMinor:       false,
			AlertTypeDriftImprovement: false,
		}
		for _, k := range AllAlertTypes {
			if _, ok := expected[k]; !ok {
				t.Errorf("AllAlertTypes contains unexpected value %q", k)
			}
			expected[k] = true
		}
		for k, found := range expected {
			if !found {
				t.Errorf("AllAlertTypes missing %q", k)
			}
		}
	})
}

// @ac AC-02
// AC-02: Severity enum has exactly 5 values; SeverityOrder ranks
// critical=0 ... info=4 so comparison works (lower = higher severity).
func TestSeverityEnum_HasExactlyFiveValues_OrderPreserved(t *testing.T) {
	t.Run("system-alert-router/AC-02", func(t *testing.T) {
		if len(AllSeverities) != 5 {
			t.Errorf("AllSeverities = %d, want 5", len(AllSeverities))
		}
		// Ordering: critical → high → medium → low → info.
		wantOrder := []Severity{
			SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo,
		}
		for i, s := range wantOrder {
			if AllSeverities[i] != s {
				t.Errorf("AllSeverities[%d] = %q, want %q", i, AllSeverities[i], s)
			}
		}
		// SeverityOrder: critical=0, info=4.
		if SeverityOrder[SeverityCritical] != 0 {
			t.Errorf("SeverityOrder[Critical] = %d, want 0", SeverityOrder[SeverityCritical])
		}
		if SeverityOrder[SeverityInfo] != 4 {
			t.Errorf("SeverityOrder[Info] = %d, want 4", SeverityOrder[SeverityInfo])
		}
		// Critical is strictly higher (lower rank) than High.
		if SeverityOrder[SeverityCritical] >= SeverityOrder[SeverityHigh] {
			t.Errorf("Critical rank %d should be < High rank %d",
				SeverityOrder[SeverityCritical], SeverityOrder[SeverityHigh])
		}
	})
}

// @ac AC-15
// AC-15: ValidateDedupTTL rejects values < 60s or > 24h with a typed
// error (ErrDedupTTLOutOfRange).
func TestValidateDedupTTL_RangeCheck(t *testing.T) {
	t.Run("system-alert-router/AC-15", func(t *testing.T) {
		cases := []struct {
			name    string
			ttl     time.Duration
			wantErr bool
		}{
			{"below_min", 30 * time.Second, true},
			{"exact_min", 60 * time.Second, false},
			{"middle", 60 * time.Minute, false},
			{"exact_max", 24 * time.Hour, false},
			{"above_max", 25 * time.Hour, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := ValidateDedupTTL(tc.ttl)
				if (err != nil) != tc.wantErr {
					t.Errorf("ValidateDedupTTL(%s) err = %v, wantErr %v", tc.ttl, err, tc.wantErr)
				}
				if tc.wantErr && !errors.Is(err, ErrDedupTTLOutOfRange) {
					t.Errorf("ValidateDedupTTL(%s) err = %v, want errors.Is ErrDedupTTLOutOfRange", tc.ttl, err)
				}
			})
		}
	})
}
