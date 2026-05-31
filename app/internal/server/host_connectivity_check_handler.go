// On-demand connectivity probe — POST /hosts/{id}/connectivity:check.
//
// Spec: app/specs/api/host-connectivity-check.spec.yaml.
//
// The handler delegates to liveness.Service.ProbeHost — same in-process
// machinery the periodic loop uses. Credential-free (TCP banner on
// port 22). State-transition audit is emitted inside ProbeHost, so the
// handler MUST NOT emit a duplicate event (spec C-07).

package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/liveness"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// PostHostConnectivityCheck implements api.ServerInterface.
// Spec AC-01..AC-13.
func (h *handlers) PostHostConnectivityCheck(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
	_ api.PostHostConnectivityCheckParams,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	if h.liveSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"liveness service not wired", true)
		return
	}

	ctx := r.Context()
	hostID := uuid.UUID(id)

	got, err := h.hosts.GetByID(ctx, hostID)
	if err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}

	port := got.Port
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", got.IPAddress, port)

	result, err := h.liveSvc.ProbeHost(ctx, hostID, addr)
	if err != nil {
		if errors.Is(err, liveness.ErrProbeInFlight) {
			writeError(w, http.StatusConflict, "conflict.probe_in_flight", "client",
				"a probe for this host is already in flight", true)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"probe failed", true)
		return
	}

	probedAt := time.Now().UTC()
	resp := api.ConnectivityCheckResult{
		Reachable:             result.Reachable,
		ResponseTimeMs:        int(result.ResponseTime / time.Millisecond),
		ProbedAt:              probedAt,
		NewReachabilityStatus: postProbeStatus(result),
	}
	if et := result.LastErrorType(); et != "" {
		resp.ErrorType = &et
	}
	writeJSON(w, http.StatusOK, resp)
}

// postProbeStatus returns the reachability_status the probe-result row
// would carry post-hysteresis. The actual write is done inside
// ProbeHost via the same computeNewState path — we just mirror the
// classification here for the response field.
//
// For the on-demand response we report:
//   - reachable     → on success
//   - unreachable   → on failure (subsequent probe-history is what
//     decides the persisted hysteresis state; the response carries the
//     immediate classification of this single probe)
func postProbeStatus(r liveness.ProbeResult) api.ConnectivityCheckResultNewReachabilityStatus {
	if r.Reachable {
		return api.ConnectivityCheckResultNewReachabilityStatusReachable
	}
	return api.ConnectivityCheckResultNewReachabilityStatusUnreachable
}
