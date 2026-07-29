// @spec api-reports
//
//	AC-25  TestDispatcher_SkipsUnlicensedAttestation
package reportschedule

import (
	"context"
	"testing"

	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/report"
	"github.com/google/uuid"
)

// countingGen records whether Generate was reached.
type countingGen struct{ generated int }

func (g *countingGen) Generate(_ context.Context, _ string, _ report.GenerateRequest) (report.Report, error) {
	g.generated++
	return report.Report{ID: uuid.New()}, nil
}
func (g *countingGen) Export(_ context.Context, _ uuid.UUID, _ string) ([]byte, string, error) {
	return []byte("pdf"), "application/pdf", nil
}

// noopDeliver stands in for the email path, which this AC does not exercise.
type noopDeliver struct{}

func (noopDeliver) SendReportEmail(_ context.Context, _ uuid.UUID, _, _, _ string, _ []byte) error {
	return nil
}

// @ac AC-25
// AC-25 (behavioural, fire-time half): an attestation schedule does not mint
// the paid artifact when the licence is absent, and DOES when it is present.
//
// The source-inspection AC proves the check is written. This proves it works,
// which matters because the fire-time gate is the one an operator cannot see:
// a schedule created while licensed would otherwise keep producing the artifact
// on a timer forever after the licence lapsed, with no request to refuse.
func TestDispatcher_SkipsUnlicensedAttestation(t *testing.T) {
	t.Run("api-reports/AC-25", func(t *testing.T) {
		if err := license.Init(); err != nil {
			t.Fatalf("license init: %v", err)
		}
		sch := Schedule{ID: uuid.New(), Kind: "attestation"}

		// Unlicensed: skipped, and skipping is not an error. An unlicensed
		// schedule is inert, not broken.
		gen := &countingGen{}
		d := &Dispatcher{gen: gen, deliver: noopDeliver{}}
		if err := d.run(context.Background(), sch); err != nil {
			t.Fatalf("unlicensed run should skip cleanly, got %v", err)
		}
		if gen.generated != 0 {
			t.Errorf("unlicensed attestation must NOT be generated; Generate called %d time(s)", gen.generated)
		}

		// The free kind is unaffected by the gate: it must REACH Generate.
		// Delivery is stubbed; only the gate decision matters here.
		gen2 := &countingGen{}
		d2 := &Dispatcher{gen: gen2, deliver: noopDeliver{}}
		_ = d2.run(context.Background(), Schedule{ID: uuid.New(), Kind: "executive"})
		if gen2.generated != 1 {
			t.Errorf("executive (free) must reach Generate; called %d time(s)", gen2.generated)
		}

		// And a LICENSED attestation must reach Generate too, so the gate is
		// proven to be the licence and not the kind alone.
		restore := license.EnableFeatureForTesting(license.ComplianceAttestation)
		defer restore()
		gen3 := &countingGen{}
		d3 := &Dispatcher{gen: gen3, deliver: noopDeliver{}}
		_ = d3.run(context.Background(), sch)
		if gen3.generated != 1 {
			t.Errorf("licensed attestation must reach Generate; called %d time(s)", gen3.generated)
		}
	})
}
