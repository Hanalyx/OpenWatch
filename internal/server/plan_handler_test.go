// @spec api-remediation
//
//	AC-13  TestRemediationPlan_FailsHonestly
package server

import (
	"os"
	"strings"
	"testing"
)

// @ac AC-13
// AC-13: the plan endpoint fails honestly rather than emptily.
//
// The two failure modes matter more than the success path. A missing rule
// corpus must not render as a plan with no steps: an operator reads that as
// "this fix does nothing" and approves it. And a host that cannot be reached
// must say so, because planning touches the host and its failures belong to
// the host, not to the fix.
func TestRemediationPlan_FailsHonestly(t *testing.T) {
	t.Run("api-remediation/AC-13", func(t *testing.T) {
		b, err := os.ReadFile("remediation_handlers.go")
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)

		i := strings.Index(src, "func (h *handlers) GetRemediationPlan")
		if i < 0 {
			t.Fatal("GetRemediationPlan has moved; this check is stale")
		}
		body := src[i:]
		if end := strings.Index(body, "\n// planFailureMessage"); end > 0 {
			body = body[:end]
		}

		// A missing corpus is 503, never a 200 with an empty plan.
		if !strings.Contains(body, "h.remediationPlan == nil") ||
			!strings.Contains(body, "StatusServiceUnavailable") {
			t.Error("an absent plan closure must return 503, not an empty plan")
		}
		// The host's failure is reported as the host's.
		if !strings.Contains(body, "StatusBadGateway") ||
			!strings.Contains(body, "planFailureMessage") {
			t.Error("a planning failure must return 502 naming the cause")
		}
		// Permission gate, same as the rest of the remediation surface.
		if !strings.Contains(body, "auth.RemediationRead") {
			t.Error("the plan endpoint must enforce remediation:read")
		}
		// Uncached by construction: no store, no memo, no TTL in the handler.
		for _, bad := range []string{"cache", "memo", "ttl"} {
			if strings.Contains(strings.ToLower(body), bad) {
				t.Errorf("the plan must be live; found %q in the handler", bad)
			}
		}

		// Every reason branch has to produce operator-actionable text, not an
		// enum name echoed back.
		msg := src[strings.Index(src, "func planFailureMessage"):]
		if end := strings.Index(msg, "\nfunc "); end > 0 {
			msg = msg[:end]
		}
		// One plain explanation per reason Kensa actually reports. There is no
		// ReasonUnreachable constant, so an unreachable host lands in the
		// default branch carrying the wrapped error, which names it.
		for _, want := range []string{
			"not trusted",            // ReasonHostKeyUnknown
			"could not be decrypted", // ReasonCredentialDecryptionFailed
			"already running",        // ReasonHostBusy
			"timed out",              // ReasonTimeout
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("planFailureMessage lacks a plain explanation for %q", want)
			}
		}
		if !strings.Contains(msg, "could not plan against the host: ") {
			t.Error("the default branch must carry the underlying error, not swallow it")
		}
	})
}
