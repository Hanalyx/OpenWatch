// Package eereg is the capability-injection seam between the permissively
// licensed OpenWatch core and optional, separately licensed feature modules.
//
// The core depends only on the interfaces declared here and on free-tier
// default implementations. A build that includes the EE module tree (built
// with the "ee" tag) registers richer implementations at process init via the
// Set* functions; the default (CE) build registers nothing and the free-tier
// defaults stand.
//
// Invariant: nothing under ee/ may be imported by the core. The core reaches
// EE capabilities only through this registry, so the dependency arrow points
// one way (ee -> core, never core -> ee). scripts/check-ee-boundary.sh
// enforces it.
//
// Scaffold note: the four capability interfaces currently expose only the
// Available probe. Feature-specific methods are added to each interface when
// its implementation is relocated into ee/<feature>/ (one change per feature,
// temporal_queries first). Until a core call site routes through this package,
// the seam is behavior-neutral — it changes nothing about the running product.
package eereg

import "errors"

// ErrRequiresLicense reports that a capability is provided only by a licensed
// EE module that is either not present (CE build) or not entitled (no valid
// license). EE implementations return it from methods invoked without
// entitlement; the free-tier defaults report unavailability via Available.
var ErrRequiresLicense = errors.New("eereg: capability requires a licensed OpenWatch module")

// Capability is the probe every EE capability shares. Available reports whether
// a licensed implementation is wired in. Core call sites check Available before
// offering the feature, and fall back to the free-core path (or a 402) when it
// is false.
type Capability interface {
	Available() bool
}

// The four EE capabilities from the feature carve. Each embeds Capability for
// now; feature-specific methods are added when the feature is relocated into
// ee/. The free-core counterparts (single-rule remediation, basic exceptions,
// unsigned export) are separate code and do NOT route through this registry.
type (
	// TemporalAnalytics backs point-in-time posture, drift, and historical
	// reconstruction (temporal_queries — entirely EE).
	TemporalAnalytics interface{ Capability }

	// BulkRemediator backs bulk and automated/fleet remediation
	// (remediation_execution). Single-rule manual remediation is free-core.
	BulkRemediator interface{ Capability }

	// SignedExporter backs signed/attested audit evidence bundles
	// (audit_export). Unsigned JSON/CSV export is free-core.
	SignedExporter interface{ Capability }

	// StagedApprover backs the multi-stage / policy-enforced exception approval
	// workflow (structured_exceptions). Basic exception governance is free-core.
	StagedApprover interface{ Capability }
)

// unavailable is the free-tier default for every capability: not present.
type unavailable struct{}

func (unavailable) Available() bool { return false }

// Registry state. Registration happens once, at process init (from the ee
// module's init under the "ee" build tag), before any reads on the serve path,
// so plain package-level vars are sufficient and no locking is needed.
var (
	temporal TemporalAnalytics = unavailable{}
	bulk     BulkRemediator    = unavailable{}
	exporter SignedExporter    = unavailable{}
	approver StagedApprover    = unavailable{}
)

// SetTemporalAnalytics injects the licensed temporal_queries implementation.
// Called only from the ee module's init under the "ee" build tag.
func SetTemporalAnalytics(t TemporalAnalytics) { temporal = t }

// SetBulkRemediator injects the licensed bulk/automated remediation
// implementation. Called only from the ee module's init.
func SetBulkRemediator(b BulkRemediator) { bulk = b }

// SetSignedExporter injects the licensed signed-bundle exporter. Called only
// from the ee module's init.
func SetSignedExporter(s SignedExporter) { exporter = s }

// SetStagedApprover injects the licensed multi-stage approval implementation.
// Called only from the ee module's init.
func SetStagedApprover(s StagedApprover) { approver = s }

// TemporalQueries returns the wired temporal implementation, or the free-tier
// default. Core call sites use this; they never import ee/ directly.
func TemporalQueries() TemporalAnalytics { return temporal }

// BulkRemediation returns the wired bulk-remediation implementation, or the
// free-tier default.
func BulkRemediation() BulkRemediator { return bulk }

// SignedExport returns the wired signed-exporter implementation, or the
// free-tier default.
func SignedExport() SignedExporter { return exporter }

// StagedApproval returns the wired multi-stage approver, or the free-tier
// default.
func StagedApproval() StagedApprover { return approver }
