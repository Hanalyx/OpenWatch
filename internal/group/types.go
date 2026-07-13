// Package group implements host groups: operator-curated SITES (manual
// membership) and OS CATEGORIES (auto membership derived from
// hosts.os_family, or manual workload groups). A host belongs to many
// groups. The service owns CRUD, membership, the maintenance flag, and
// the per-group rollups the Groups page renders.
//
// Spec: api-groups v1.0.0.
package group

import (
	"time"

	"github.com/google/uuid"
)

// Kind distinguishes a site (environment/topology) from an os_category
// (platform/workload).
type Kind string

const (
	KindSite       Kind = "site"
	KindOSCategory Kind = "os_category"
)

// Membership is how a group's hosts are determined.
type Membership string

const (
	// MembershipManual: hosts are assigned explicitly (group_members).
	MembershipManual Membership = "manual"
	// MembershipAuto: hosts are every host whose os_family == MatchFamily,
	// computed live (no stored membership, no backfill).
	MembershipAuto Membership = "auto"
)

// Group is one row of the groups table.
type Group struct {
	ID          uuid.UUID
	Name        string
	Kind        Kind
	Subtype     string
	Color       string
	Membership  Membership
	MatchFamily string // "" for manual groups
	Maintenance bool
	// TargetFramework is the compliance TARGET family a member host is held to
	// (Phase 3). "" means no group target. Only a site group may carry one
	// (D1); the service rejects a target on an os_category group.
	TargetFramework string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// MemberChip is a compact member-host descriptor for the card preview.
type MemberChip struct {
	HostID   uuid.UUID
	Hostname string
	// Status is the host's monitoring band (online/degraded/critical/
	// down/...) or "unknown" when never probed.
	Status string
}

// Rollup is the computed member summary the list view shows per group.
type Rollup struct {
	Hosts            int
	Online           int
	Down             int
	CriticalHosts    int
	AvgCompliancePct *int // nil when no member host has been scanned
	Members          []MemberChip
}

// GroupWithRollup is a group plus its computed metrics.
type GroupWithRollup struct { //nolint:revive // name intentionally mirrors the api.GroupWithRollup OpenAPI schema
	Group
	Rollup
}

// FleetSummary backs the Groups-page KPI row.
type FleetSummary struct {
	Groups           int
	Sites            int
	OSCategories     int
	HostsMaintenance int
	AvgCompliancePct *int
	Ungrouped        int
}

// CreateInput is the payload to create a group.
type CreateInput struct {
	Name        string
	Kind        Kind
	Subtype     string
	Color       string
	Membership  Membership
	MatchFamily string
}

// UpdateInput patches a group's editable fields.
type UpdateInput struct {
	Name    string
	Subtype string
	Color   string
}
