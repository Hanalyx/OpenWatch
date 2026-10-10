// @spec release-evidence-capture

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Release evidence capture (release-evidence-capture). The behavior lives in
// scripts/evidence_capture.py and is driven by scripts/test_evidence_capture.py,
// one unittest class per criterion. The suite runs once; each criterion checks
// that every case in its class passed, so a deleted or skipped case is noticed.

var (
	evidenceCaptureOnce   sync.Once
	evidenceCaptureOut    []byte
	evidenceCaptureErr    error
	evidenceCapturePassed map[string]int
)

func evidenceCaptureSuite(t *testing.T) map[string]int {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "tar")
	dir := appDir(t)
	evidenceCaptureOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_evidence_capture.py"))
		cmd.Dir = dir
		evidenceCaptureOut, evidenceCaptureErr = cmd.CombinedOutput()
		evidenceCapturePassed = map[string]int{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.\w+\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(evidenceCaptureOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				evidenceCapturePassed[m[1]]++
			}
		}
	})
	if evidenceCaptureErr != nil {
		t.Fatalf("scripts/test_evidence_capture.py: %v\n%s", evidenceCaptureErr,
			tailOf(evidenceCaptureOut, 40))
	}
	return evidenceCapturePassed
}

func requireEvidenceCaptureClass(t *testing.T, class string, want int) {
	t.Helper()
	if got := evidenceCaptureSuite(t)[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
}

// @ac AC-01
// AC-01: raw stdout, raw stderr and the exit status, byte for byte.
func TestEvidenceCapture_KeepsRawStreamsAndExitStatus(t *testing.T) {
	t.Run("release-evidence-capture/AC-01", func(t *testing.T) {
		requireEvidenceCaptureClass(t, "CaptureRawStreams", 7)
	})
}

// @ac AC-02
// AC-02: a capture appears under its final name only when sealed.
func TestEvidenceCapture_WritesAtomically(t *testing.T) {
	t.Run("release-evidence-capture/AC-02", func(t *testing.T) {
		requireEvidenceCaptureClass(t, "CaptureAtomicWrite", 7)
	})
}

// @ac AC-03
// AC-03: bound to the host, the candidate and the invocation.
func TestEvidenceCapture_BindsHostCandidateAndInvocation(t *testing.T) {
	t.Run("release-evidence-capture/AC-03", func(t *testing.T) {
		requireEvidenceCaptureClass(t, "CaptureBinding", 4)
	})
}

// @ac AC-04
// AC-04: secrets stay out of arguments and evidence.
func TestEvidenceCapture_KeepsSecretsOut(t *testing.T) {
	t.Run("release-evidence-capture/AC-04", func(t *testing.T) {
		requireEvidenceCaptureClass(t, "CaptureSecrets", 8)
	})
}

// @ac AC-05
// AC-05: interrupted, timed-out and unstartable commands are kept and named.
func TestEvidenceCapture_KeepsInterruptedCaptures(t *testing.T) {
	t.Run("release-evidence-capture/AC-05", func(t *testing.T) {
		requireEvidenceCaptureClass(t, "CaptureInterruption", 5)
	})
}

// @ac AC-06
// AC-06: verification catches any change to a sealed capture.
func TestEvidenceCapture_VerifiesSealedCaptures(t *testing.T) {
	t.Run("release-evidence-capture/AC-06", func(t *testing.T) {
		requireEvidenceCaptureClass(t, "CaptureVerify", 8)
	})
}

// @ac AC-07
// AC-07: a remote capture is verified after transfer, before it is named.
func TestEvidenceCapture_VerifiesAfterTransfer(t *testing.T) {
	t.Run("release-evidence-capture/AC-07", func(t *testing.T) {
		requireEvidenceCaptureClass(t, "CaptureTransfer", 12)
	})
}
