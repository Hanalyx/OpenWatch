// @spec system-report-schedule
//
// AC traceability:
//   AC-03  buildReportEmail produces a multipart/mixed message with a
//          text body part and a base64 application/pdf attachment

package notification

import (
	"strings"
	"testing"
)

// @ac AC-03
func TestBuildReportEmail_MultipartAttachment(t *testing.T) {
	t.Run("system-report-schedule/AC-03", testBuildReportEmail)
}

func testBuildReportEmail(t *testing.T) {
	msg := string(buildReportEmail(
		"openwatch@corp.com", []string{"auditor@corp.com"},
		"Framework Attestation - 2026-06-22",
		"Your scheduled report is attached.",
		"openwatch-attestation-2026-06-22.pdf",
		[]byte("%PDF-1.4 fake pdf bytes"),
	))

	if !strings.Contains(msg, "To: auditor@corp.com") {
		t.Errorf("missing To header")
	}
	if !strings.Contains(msg, "Subject: Framework Attestation - 2026-06-22") {
		t.Errorf("missing Subject header")
	}
	if !strings.Contains(msg, "Content-Type: multipart/mixed; boundary=") {
		t.Errorf("not multipart/mixed: %q", msg[:200])
	}
	// Text body part.
	if !strings.Contains(msg, "Content-Type: text/plain; charset=utf-8") ||
		!strings.Contains(msg, "Your scheduled report is attached.") {
		t.Errorf("missing text body part")
	}
	// PDF attachment part: application/pdf, base64, filename.
	if !strings.Contains(msg, "Content-Type: application/pdf") {
		t.Errorf("missing pdf content-type")
	}
	if !strings.Contains(msg, "Content-Transfer-Encoding: base64") {
		t.Errorf("missing base64 encoding")
	}
	if !strings.Contains(msg, `filename="openwatch-attestation-2026-06-22.pdf"`) {
		t.Errorf("missing attachment filename")
	}
}
