// @spec api-reports
//
// Report faces (export). The pure render test needs no DB; the
// export/caching path is OPENWATCH_TEST_DSN-gated:
//
//	AC-12  TestRenderExecutivePDF        (renderer emits a structurally valid PDF)
//	AC-13  TestExport_FacesAndCaching    (json + pdf faces, report_faces cache, errors)

package report

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// @ac AC-12
// The PDF renderer emits a structurally valid, non-trivial PDF document
// (magic header + EOF trailer) from a report + its content. Pure: no DB.
func TestRenderExecutivePDF(t *testing.T) {
	t.Run("api-reports/AC-12", func(t *testing.T) {
		pct := 65
		rep := Report{
			Title:         executiveTitle,
			ScopeLabel:    "RHEL hosts · CIS",
			DataAsOf:      time.Date(2026, 6, 21, 14, 30, 0, 0, time.UTC),
			GeneratedBy:   "alice@example.com",
			ContentSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		}
		c := ExecutiveContent{
			CompliancePct:  &pct,
			HostCount:      5,
			PassingRules:   1812,
			FailingRules:   821,
			CriticalIssues: 0,
			TopFailingRules: []TopFailingRule{
				{RuleID: "audit-chmod-changes", FailingHostCount: 5},
				{RuleID: "audit-chown-changes", FailingHostCount: 5},
			},
			Coverage: Coverage{HostsTotal: 5, HostsFresh: 4, HostsStale: 1, HostsUnreachable: 1},
		}

		pdf, err := renderExecutivePDF(rep, c)
		if err != nil {
			t.Fatalf("renderExecutivePDF: %v", err)
		}
		if len(pdf) < 800 {
			t.Errorf("pdf is implausibly small: %d bytes", len(pdf))
		}
		if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
			t.Errorf("pdf does not start with the %%PDF- magic: %q", pdf[:min(8, len(pdf))])
		}
		if !bytes.Contains(pdf, []byte("%%EOF")) {
			t.Errorf("pdf has no %%%%EOF trailer")
		}
	})
}

// @ac AC-13
// Export serves the json face (canonical content) and the pdf face
// (rendered + cached in report_faces). A second pdf export re-streams the
// cached bytes; an unknown face is ErrInvalidFace; an unknown id is
// ErrNotFound.
func TestExport_FacesAndCaching(t *testing.T) {
	t.Run("api-reports/AC-13", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		h := seedHost(t, pool, owner, false)
		seedRuleState(t, pool, h, "r1", "fail", "high")

		rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		// json face == the canonical stored content.
		jsonBody, jsonMedia, err := svc.Export(ctx, rep.ID, FaceJSON)
		if err != nil {
			t.Fatalf("Export json: %v", err)
		}
		if jsonMedia != "application/json" {
			t.Errorf("json media = %q", jsonMedia)
		}
		if !bytes.Equal(jsonBody, rep.Content) {
			t.Errorf("json face is not the canonical content")
		}

		// pdf face renders and caches.
		pdfBody, pdfMedia, err := svc.Export(ctx, rep.ID, FacePDF)
		if err != nil {
			t.Fatalf("Export pdf: %v", err)
		}
		if pdfMedia != "application/pdf" {
			t.Errorf("pdf media = %q", pdfMedia)
		}
		if !bytes.HasPrefix(pdfBody, []byte("%PDF-")) {
			t.Errorf("pdf face is not a PDF")
		}

		// A report_faces row was written with status ready + a content hash.
		var status, blob string
		var size int
		if err := pool.QueryRow(ctx,
			`SELECT status, blob_sha256, size_bytes FROM report_faces WHERE snapshot_id = $1 AND face = 'pdf'`,
			rep.ID).Scan(&status, &blob, &size); err != nil {
			t.Fatalf("face row lookup: %v", err)
		}
		if status != "ready" || len(blob) != 64 || size != len(pdfBody) {
			t.Errorf("face row = status %q, blob %q (len %d), size %d (want ready/64/%d)",
				status, blob, len(blob), size, len(pdfBody))
		}

		// Second export re-streams the cached bytes (identical).
		pdfBody2, _, err := svc.Export(ctx, rep.ID, FacePDF)
		if err != nil {
			t.Fatalf("Export pdf #2: %v", err)
		}
		if !bytes.Equal(pdfBody, pdfBody2) {
			t.Errorf("cached pdf differs from first render")
		}

		// Unknown face -> ErrInvalidFace.
		if _, _, err := svc.Export(ctx, rep.ID, "oscal"); !errors.Is(err, ErrInvalidFace) {
			t.Errorf("Export bogus face err = %v, want ErrInvalidFace", err)
		}
		// Unknown id -> ErrNotFound.
		if _, _, err := svc.Export(ctx, uuid.New(), FacePDF); !errors.Is(err, ErrNotFound) {
			t.Errorf("Export unknown id err = %v, want ErrNotFound", err)
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
