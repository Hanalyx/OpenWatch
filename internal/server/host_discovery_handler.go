// On-demand OS fingerprint Discovery — POST /hosts/{id}/discovery:run.
//
// Spec: app/specs/system/host-discovery.spec.yaml AC-08, AC-09, AC-10.
//
// The handler delegates to discovery.Service.Discover, which opens one
// SSH session, runs the closed probe batch, persists host_system_info +
// denormalized hosts.os_* columns in a single transaction, publishes
// the eventbus event, and emits the audit event.

package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/server/api"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// PostHostDiscoveryRun implements api.ServerInterface.PostHostDiscoveryRun.
// Spec AC-08 (200 happy path), AC-09 (403 RBAC), AC-10 (404 unknown host).
func (h *handlers) PostHostDiscoveryRun(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
	params api.PostHostDiscoveryRunParams,
) {
	// Idempotency-Key validation parallels :connectivity:check. The
	// middleware enforces single-execution semantics; the handler just
	// rejects empty / missing keys.
	if strings.TrimSpace(params.IdempotencyKey) == "" {
		writeError(w, http.StatusBadRequest, "idempotency.key_required", "client",
			"Idempotency-Key header is required", false)
		return
	}

	// AC-09: host:write is the bar — Discovery mutates host_system_info
	// AND the denormalized hosts.os_* columns. Audit events are not
	// emitted on permission denial (handled by EnforcePermission).
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}

	if h.discoSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"discovery service not wired", true)
		return
	}

	hostID := uuid.UUID(id)
	facts, err := h.discoSvc.Discover(r.Context(), hostID)
	if err != nil {
		// AC-10: unknown host id → 404 hosts.not_found.
		if errors.Is(err, discovery.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		// Credential-resolver missing → host has no usable credential.
		if errors.Is(err, credential.ErrNoCredential) {
			writeError(w, http.StatusBadGateway, "host.unreachable", "client",
				"host has no usable credential for SSH dial", false)
			return
		}
		// SSH dial failures map to 502 host.unreachable so the operator
		// can distinguish "host is gone" from "server problem". Probe
		// sub-command failures stay non-fatal per spec C-03 (partial
		// success) — they never bubble out as errors here.
		if isSSHDialError(err) {
			writeError(w, http.StatusBadGateway, "host.unreachable", "client",
				"ssh dial failed: "+err.Error(), true)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"discovery failed: "+err.Error(), true)
		return
	}

	writeJSON(w, http.StatusOK, factsToResponse(hostID, facts))
}

// isSSHDialError returns true for the internal/ssh sentinel errors that
// indicate the SSH dial path failed (not auth, not authz, not host).
// Kept inline so we don't drag the full owssh err set into discovery's
// public surface.
func isSSHDialError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, owssh.ErrConnect) ||
		errors.Is(err, owssh.ErrDialTimeout) ||
		errors.Is(err, owssh.ErrAuthFailed) ||
		errors.Is(err, owssh.ErrNoAuthMethod) ||
		errors.Is(err, owssh.ErrHostKeyUnknown) ||
		errors.Is(err, owssh.ErrHostKeyMismatch)
}

// factsToResponse maps SystemFacts into the OpenAPI HostSystemInfo
// schema. The schema fields use pointer types for nullables so empty
// values render as JSON null instead of "" / 0.
func factsToResponse(hostID uuid.UUID, f discovery.SystemFacts) api.HostSystemInfo {
	resp := api.HostSystemInfo{
		HostId:      openapitypes.UUID(hostID),
		CollectedAt: f.CollectedAt,
	}
	str := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	intp := func(n int) *int {
		if n == 0 {
			return nil
		}
		return &n
	}
	resp.OsName = str(f.OSName)
	resp.OsVersion = str(f.OSVersion)
	resp.OsVersionFull = str(f.OSVersionFull)
	resp.OsId = str(f.OSID)
	resp.OsIdLike = str(f.OSIDLike)
	resp.OsPrettyName = str(f.OSPrettyName)
	resp.PlatformIdentifier = str(f.PlatformIdentifier)
	resp.OsFamily = str(f.OSFamily)
	resp.KernelName = str(f.KernelName)
	resp.KernelRelease = str(f.KernelRelease)
	resp.KernelVersion = str(f.KernelVersion)
	resp.Architecture = str(f.Architecture)
	resp.MemTotalMb = intp(f.MemTotalMB)
	resp.MemAvailableMb = intp(f.MemAvailableMB)
	resp.SwapTotalMb = intp(f.SwapTotalMB)
	resp.DiskTotalGb = intp(f.DiskTotalGB)
	resp.DiskUsedGb = intp(f.DiskUsedGB)
	resp.DiskFreeGb = intp(f.DiskFreeGB)
	resp.Hostname = str(f.Hostname)
	resp.Fqdn = str(f.FQDN)
	resp.SelinuxStatus = str(f.SELinuxStatus)
	if f.AppArmorEnabled {
		v := true
		resp.ApparmorEnabled = &v
	}
	resp.FirewallService = str(f.FirewallService)
	resp.FirewallStatus = str(f.FirewallStatus)
	return resp
}
