// Capability discovery: what THIS deployment may use.
//
// Spec api-capabilities.
package server

import (
	"net/http"
	"sort"

	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/server/api"
)

// GetCapabilities implements api.ServerInterface.
//
// Built entirely from the feature registry plus the runtime entitlement check,
// so a capability cannot appear here without being registered first. That is
// the same registry-first rule the roadmap applies to gating: if it is not in
// licensing/features.yaml, it does not exist.
//
// WHY IT IS UNAUTHENTICATED: the interface needs to know what the deployment
// offers before a user signs in, exactly like GET /license. It discloses
// capability ids, their tier, and whether each is available here. It does not
// disclose customer identity, key material, expiry, or anything about who
// holds the license. GET /license is the authenticated surface for that, and
// its customer_id is now gated on system:read.
//
// There are no quotas in the response because there are no quotas in the
// product: tiering is by capability alone. OpenWatch does not cap hosts,
// scans, or users, so a "78% of your host allowance" indicator would be
// inventing a limit that does not exist.
func (h *handlers) GetCapabilities(w http.ResponseWriter, r *http.Request) {
	tier := license.TierFree
	status := license.StatusNoLicense
	if st := license.CurrentState(); st != nil && st.License != nil {
		tier = st.License.Tier
		status = st.License.Status
	}

	caps := make([]api.Capability, 0, len(license.FeatureRegistry))
	for id, meta := range license.FeatureRegistry {
		caps = append(caps, api.Capability{
			Id:          string(id),
			Tier:        api.CapabilityTier(meta.Tier),
			Available:   license.IsEnabled(id),
			Description: meta.Description,
		})
	}
	// Stable order: a map iteration would make the response non-deterministic
	// and churn any client that diffs it.
	sort.Slice(caps, func(i, j int) bool { return caps[i].Id < caps[j].Id })

	writeJSON(w, http.StatusOK, api.CapabilitiesResponse{
		Tier:         api.CapabilitiesResponseTier(tier),
		Status:       api.CapabilitiesResponseStatus(status),
		Capabilities: caps,
	})
}
