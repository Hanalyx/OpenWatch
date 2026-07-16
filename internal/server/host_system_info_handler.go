// GET /api/v1/hosts/{id}/system-info — read the latest Discovery
// result for one host. Spec api-host-system-info v1.0.0.
//
// Mirrors api-os-intelligence GET /intelligence/state/{host_id}:
//   - 200 with the HostSystemInfo JSON when a row exists.
//   - 404 hosts.not_found when (a) host unknown, (b) host
//     soft-deleted, or (c) host exists but Discovery hasn't run.
//     The handler intentionally collapses (a) + (b) + (c) under the
//     same envelope so operators cannot probe host existence here.
//
// RBAC: host:read. The DB read is a single SELECT with a $1
// parameterized host_id — no string concat (spec C-02).

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// GetHostSystemInfo implements api.ServerInterface.
// Spec api-host-system-info AC-01..AC-05.
func (h *handlers) GetHostSystemInfo(
	w http.ResponseWriter,
	r *http.Request,
	id openapitypes.UUID,
) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}

	hid := uuid.UUID(id)

	// Probe the host first. If missing / soft-deleted, return 404 with
	// the same envelope the no-row path uses below. Spec C-03.
	if _, err := h.hosts.GetByID(r.Context(), hid); err != nil {
		if errors.Is(err, host.ErrHostNotFound) {
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"host lookup failed", true)
		return
	}

	// Single parameterized read. Spec C-02.
	const q = `
		SELECT os_name, os_version, os_version_full, os_id, os_id_like,
		       os_pretty_name, platform_identifier, os_family,
		       kernel_name, kernel_release, kernel_version, architecture,
		       mem_total_mb, mem_available_mb, swap_total_mb,
		       disk_total_gb, disk_used_gb, disk_free_gb,
		       hostname, fqdn,
		       selinux_status, apparmor_enabled,
		       firewall_service, firewall_status,
		       collected_at, category_freshness
		  FROM host_system_info
		 WHERE host_id = $1`

	resp := api.HostSystemInfo{HostId: openapitypes.UUID(hid)}
	var freshRaw []byte
	err := h.pool.QueryRow(r.Context(), q, hid).Scan(
		&resp.OsName, &resp.OsVersion, &resp.OsVersionFull, &resp.OsId, &resp.OsIdLike,
		&resp.OsPrettyName, &resp.PlatformIdentifier, &resp.OsFamily,
		&resp.KernelName, &resp.KernelRelease, &resp.KernelVersion, &resp.Architecture,
		&resp.MemTotalMb, &resp.MemAvailableMb, &resp.SwapTotalMb,
		&resp.DiskTotalGb, &resp.DiskUsedGb, &resp.DiskFreeGb,
		&resp.Hostname, &resp.Fqdn,
		&resp.SelinuxStatus, &resp.ApparmorEnabled,
		&resp.FirewallService, &resp.FirewallStatus,
		&resp.CollectedAt, &freshRaw,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Spec C-03: same envelope as the unknown-host path.
			writeError(w, http.StatusNotFound, "hosts.not_found", "client",
				"host not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"system_info lookup failed", true)
		return
	}

	// category_freshness is JSONB; NULL for rows written before migration
	// 0052. Unmarshal into the typed map when present; a decode failure is
	// non-fatal — the row's facts are still valid without freshness metadata.
	if len(freshRaw) > 0 {
		var cf api.CategoryFreshness
		if json.Unmarshal(freshRaw, &cf) == nil && len(cf) > 0 {
			resp.CategoryFreshness = &cf
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
