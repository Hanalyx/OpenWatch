// @spec api-reports
//
// AC traceability (DSN-gated):
//
//	AC-27  TestFrameworkLabels_SignedIdentityAndStoredLabels

package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// @ac AC-27
// AC-27 (D-2 S-7): a report scoped to NIST SP 800-171 is distinguishable from
// one scoped to NIST 800-53 both in its signed content, which carries the
// exact framework key, and in the label every face shows. A report generated
// before the label change keeps the label it was generated with: faces read
// the stored scope_label, and nothing recomputes or re-signs an old artifact.
func TestFrameworkLabels_SignedIdentityAndStoredLabels(t *testing.T) {
	t.Run("api-reports/AC-27", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		signer, _ := NewSigner("")
		svc := NewService(pool).WithSigner(signer)
		owner := seedUser(t, pool)
		h := seedHost(t, pool, owner, false)
		scan := seedScanRun(t, pool, h)
		seedScanResult(t, pool, scan, h, "r1", "pass", `{"nist_800_53": ["AC-2"], "nist_800_171": ["3.1.1[a]"]}`)
		seedScanResult(t, pool, scan, h, "r2", "fail", `{"nist_800_171": ["3.13.9[c]"]}`)

		gen := func(framework string) (Report, AttestationContent) {
			t.Helper()
			rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{Kind: KindAttestation, Framework: framework})
			if err != nil {
				t.Fatalf("Generate %s: %v", framework, err)
			}
			var c AttestationContent
			if err := json.Unmarshal(rep.Content, &c); err != nil {
				t.Fatalf("decode content: %v", err)
			}
			return rep, c
		}
		r171, c171 := gen("nist_800_171")
		r53, c53 := gen("nist_800_53")

		// Signed content carries the exact key, not a family or a label.
		if c171.Framework != "nist_800_171" || c53.Framework != "nist_800_53" {
			t.Errorf("signed framework = %q / %q, want nist_800_171 / nist_800_53", c171.Framework, c53.Framework)
		}
		if r171.ScopeLabel != "All hosts · NIST SP 800-171 Rev 2" || r53.ScopeLabel != "All hosts · NIST 800-53" {
			t.Errorf("scope labels = %q / %q", r171.ScopeLabel, r53.ScopeLabel)
		}
		if ExportFilename(r171, FacePDF) == ExportFilename(r53, FacePDF) {
			t.Errorf("both reports export as %q", ExportFilename(r171, FacePDF))
		}
		if !strings.Contains(ExportFilename(r171, FacePDF), "nist-sp-800-171-rev-2") {
			t.Errorf("800-171 filename = %q, want it to name the framework", ExportFilename(r171, FacePDF))
		}

		// A report written by the previous code carried the collapsed label.
		// Faces must keep showing what it was generated with.
		const oldLabel = "All hosts · NIST"
		if _, err := pool.Exec(ctx, `UPDATE report_snapshots SET scope_label = $1 WHERE id = $2`, oldLabel, r53.ID); err != nil {
			t.Fatalf("seed a pre-change label: %v", err)
		}
		old, err := svc.Get(ctx, r53.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if old.ScopeLabel != oldLabel {
			t.Errorf("stored label = %q, want %q unchanged", old.ScopeLabel, oldLabel)
		}
		if name := ExportFilename(old, FacePDF); !strings.Contains(name, "all-hosts-nist-") || strings.Contains(name, "800-53") {
			t.Errorf("filename for the older report = %q, want it built from the stored label", name)
		}
		// Its signed content is untouched: the JSON face still hashes to the
		// stored content address and the signature still verifies.
		body, _, err := svc.Export(ctx, r53.ID, FaceJSON)
		if err != nil {
			t.Fatalf("Export json: %v", err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != old.ContentSHA256 {
			t.Errorf("json face no longer hashes to content_sha256")
		}
		if !VerifySignature(signer.PublicKey(), old.ContentSHA256, old.Signature) {
			t.Errorf("signature over the older report no longer verifies")
		}
	})
}
