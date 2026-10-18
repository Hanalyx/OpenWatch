//go:build sshdiag

// The unprotected baseline: a diagnostic, not a test of the contract. It
// asserts nothing; it records what the unprotected Dial costs an account
// behind pam_faillock, the incident slice 4 bounds. It is outside the
// default build, so the suite neither runs nor skips it. Run it with:
//
//	OPENWATCH_SSH_CONTAINER_TESTS=1 OPENWATCH_TEST_DSN=... \
//	  go test -tags sshdiag -run TestUnprotectedDial_ContainerBaseline -v ./internal/ssh/

package ssh

import (
	"context"
	"testing"
	"time"
)

// TestUnprotectedDial_ContainerBaseline records, without asserting a
// number, what the unprotected Dial costs the same account: the incident
// this slice bounds. It is evidence for the review, not a contract.
func TestUnprotectedDial_ContainerBaseline(t *testing.T) {
	c := startSSHD(t)
	c.setPassword("P2")
	for i := range 3 {
		cl, err := Dial(context.Background(), "127.0.0.1", c.port, activePassword("ops", "P1"), DialOptions{Mode: ModeTOFU, Timeout: 5 * time.Second})
		if err == nil {
			_ = cl.Close()
		}
		t.Logf("baseline: after %d unprotected dial(s) with a rotated-out password, pam_faillock records %d failures (deny = 3)", i+1, c.failures())
	}
	cl, err := Dial(context.Background(), "127.0.0.1", c.port, activePassword("ops", "P2"), DialOptions{Mode: ModeTOFU, Timeout: 5 * time.Second})
	if err == nil {
		_ = cl.Close()
	}
	t.Logf("baseline: the correct password afterwards: %v", err)
}
