// OS discovery scheduler HTTP config + sweep surface.
//
// Spec: app/specs/api/system-discovery-config.spec.yaml
//
// Mirrors intelligence_config_handlers.go verbatim — same shape, same
// validation/audit pattern. The sweep handler is the only divergence:
// it dispatches a fleet-wide enqueue of host.discovery jobs and
// reports the count.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
)

// GetSystemDiscoveryConfig implements api.ServerInterface.
// Spec api-system-discovery-config AC-01 / AC-02.
func (h *handlers) GetSystemDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemRead); denied {
		return
	}
	if h.sysCfg == nil {
		writeJSON(w, http.StatusOK, discoveryConfigResponse(systemconfig.DefaultDiscovery()))
		return
	}
	cfg, err := h.sysCfg.LoadDiscovery(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to load discovery config", true)
		return
	}
	writeJSON(w, http.StatusOK, discoveryConfigResponse(cfg))
}

// PutSystemDiscoveryConfig implements api.ServerInterface.
// Spec api-system-discovery-config AC-03 / AC-04 / AC-05 / AC-06 / AC-07.
func (h *handlers) PutSystemDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemConfigWrite); denied {
		return
	}
	var req api.DiscoveryConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"malformed request body", false)
		return
	}

	cfg := systemconfig.DiscoveryConfig{
		IntervalSec:          req.IntervalSec,
		RateLimit:            req.RateLimit,
		DetectOnFirstContact: req.DetectOnFirstContact,
		MaintenanceGlobal:    req.MaintenanceGlobal,
	}
	if err := cfg.Validate(); err != nil {
		field := firstInvalidDiscoveryField(cfg)
		writeErrorDetail(w, http.StatusBadRequest, "validation.range_exceeded", "client",
			err.Error(), false, map[string]any{"field": field})
		return
	}

	changedBy := auth.FromContext(r.Context()).ID
	if changedBy == "" {
		changedBy = "anonymous"
	}
	if h.sysCfg == nil {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"systemconfig store not wired", true)
		return
	}
	if err := h.sysCfg.SetDiscovery(r.Context(), cfg, changedBy); err != nil {
		if errors.Is(err, systemconfig.ErrInvalidConfig) {
			field := firstInvalidDiscoveryField(cfg)
			writeErrorDetail(w, http.StatusBadRequest, "validation.range_exceeded", "client",
				err.Error(), false, map[string]any{"field": field})
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to save discovery config", true)
		return
	}

	writeJSON(w, http.StatusOK, toAPIDiscoveryConfig(cfg))
}

// PostSystemDiscoverySweep implements api.ServerInterface.
// Spec api-system-discovery-config AC-08 / AC-09 / AC-10.
func (h *handlers) PostSystemDiscoverySweep(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.SystemConfigWrite); denied {
		return
	}

	ctx := r.Context()
	hosts, err := h.listUndiscoveredHosts(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"failed to query hosts for sweep", true)
		return
	}

	// Make sure the context carries a correlation_id so queue.Enqueue's
	// guard passes when the operator request crosses the async boundary.
	if _, ok := correlation.From(ctx); !ok {
		ctx = correlation.Set(ctx, correlation.Generate(correlation.PrefixRequest))
	}

	enqueued := 0
	for _, hostID := range hosts {
		if _, err := queue.Enqueue(ctx, h.pool, discovery.JobKindHostDiscovery,
			discovery.HostDiscoveryJobPayload{HostID: hostID}); err == nil {
			enqueued++
		}
		// best-effort — one bad enqueue does not abort the sweep
	}

	writeJSON(w, http.StatusOK, api.DiscoverySweepResponse{Enqueued: enqueued})
}

// listUndiscoveredHosts returns the host ids the sweep should enqueue:
// non-deleted, non-maintenance, hosts.os_discovered_at IS NULL.
func (h *handlers) listUndiscoveredHosts(ctx context.Context) ([]uuid.UUID, error) {
	const q = `
		SELECT id FROM hosts
		 WHERE deleted_at IS NULL
		   AND maintenance_mode = false
		   AND os_discovered_at IS NULL`
	rows, err := h.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// discoveryConfigResponse wraps active + defaults. Spec C-01.
func discoveryConfigResponse(active systemconfig.DiscoveryConfig) api.DiscoveryConfigResponse {
	return api.DiscoveryConfigResponse{
		Config:   toAPIDiscoveryConfig(active),
		Defaults: toAPIDiscoveryConfig(systemconfig.DefaultDiscovery()),
	}
}

func toAPIDiscoveryConfig(c systemconfig.DiscoveryConfig) api.DiscoveryConfig {
	return api.DiscoveryConfig{
		IntervalSec:          c.IntervalSec,
		RateLimit:            c.RateLimit,
		DetectOnFirstContact: c.DetectOnFirstContact,
		MaintenanceGlobal:    c.MaintenanceGlobal,
	}
}

// firstInvalidDiscoveryField returns the name of the first out-of-bounds
// field so the 400 envelope's detail.field points at the value the user
// broke first. Order matches systemconfig.DiscoveryConfig.Validate.
func firstInvalidDiscoveryField(c systemconfig.DiscoveryConfig) string {
	switch {
	case c.IntervalSec < 3600 || c.IntervalSec > 604800:
		return "interval_sec"
	case c.RateLimit < 1 || c.RateLimit > 500:
		return "rate_limit"
	}
	return ""
}
