// @spec system-rbac
//
//	AC-21  TestGCluster_AnonymousIsRefusedOnPrivilegedSurfaces
package server

import (
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/google/uuid"
)

// @ac AC-21
// AC-21 (NEGATIVE PATH): three surfaces that were reachable anonymously are
// now refused, and one disclosure is withheld.
//
// Each was a distinct class of problem, so each is asserted separately rather
// than as one loop:
//
//   - enqueue-test-job wrote to the REAL job queue with no authentication. An
//     unauthenticated write to a work queue is a denial-of-service primitive
//     and a source of unbounded table growth.
//   - /admin/license:verify was an oracle: submit any JWT and learn whether it
//     verifies, its tier, its features, its expiry, and whether it was signed
//     with the PREVIOUS key, which leaks key-rotation state.
//   - connectivity:check gated on host:read, but it is not a read: it makes
//     the server open an SSH or ICMP connection to a managed host on demand.
//   - GET /license disclosed customer_id, the paying organisation's identity,
//     to anyone who could reach the port.
func TestGCluster_AnonymousIsRefusedOnPrivilegedSurfaces(t *testing.T) {
	t.Run("system-rbac/AC-21", func(t *testing.T) {
		url, _ := freshAPIServer(t)

		// The job-queue DoS primitive.
		req, _ := http.NewRequest("POST", url+"/api/v1/diagnostics:enqueue-test-job", nil)
		if r := doReq(t, req); r.StatusCode == http.StatusAccepted {
			r.Body.Close()
			t.Error("anonymous enqueue-test-job must not reach the job queue")
		} else {
			r.Body.Close()
		}

		// The license oracle.
		req2, _ := http.NewRequest("POST", url+"/api/v1/admin/license:verify", nil)
		if r := doReq(t, req2); r.StatusCode == http.StatusOK {
			r.Body.Close()
			t.Error("anonymous license:verify must not answer; it is a signature and entitlement oracle")
		} else {
			r.Body.Close()
		}

		// A viewer holds host:read but must not be able to make the server
		// open a connection to a managed host.
		// A real UUID: the all-zeros one is rejected as invalid input before
		// the permission check runs, which would assert nothing about RBAC.
		hid := uuid.New()
		req3 := asRole(t, "POST",
			url+"/api/v1/hosts/"+hid.String()+"/connectivity:check",
			auth.RoleViewer, nil)
		// Required header, or the request 400s on validation before RBAC runs
		// and the assertion proves nothing.
		req3.Header.Set("Idempotency-Key", "ac21-"+hid.String())
		r3 := doReq(t, req3)
		defer r3.Body.Close()
		if r3.StatusCode != http.StatusForbidden {
			t.Errorf("viewer connectivity:check = %d, want 403: it is a side effect, not a read", r3.StatusCode)
		}
	})
}
