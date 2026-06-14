// Package report implements the Reports library: point-in-time,
// immutable compliance artifacts. The MVP generates exactly one kind,
// the Fleet Compliance Executive Summary. Generating it computes a
// posture snapshot from data that already exists (host_rule_state
// pass/fail counts + critical, host count, top failing rules) and
// stores it as a JSON document; the row is then never recomputed.
//
// DEFERRED (not built here, see the migration + spec excludes): Ed25519
// signing, PDF/OSCAL rendering, the Scheduled dispatcher, the Templates
// gallery, retention sweeps.
//
// Spec: api-reports v1.0.0.
package report

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Kind is the report flavor. The MVP only generates KindExecutive.
type Kind string

const (
	// KindExecutive is the Fleet Compliance Executive Summary.
	KindExecutive Kind = "executive"
)

// Report is one row of the reports table. Content holds the rendered
// JSON posture document (see ExecutiveContent for the executive shape).
type Report struct {
	ID          uuid.UUID
	Title       string
	Kind        Kind
	ScopeLabel  string
	DataAsOf    time.Time
	GeneratedBy string
	Format      string
	Content     json.RawMessage
	CreatedAt   time.Time
}

// ExecutiveContent is the JSON posture document stored for an executive
// summary report. It is computed once at generation time from
// host_rule_state and frozen.
type ExecutiveContent struct {
	// CompliancePct is the fleet average compliance (passing /
	// evaluated), rounded to a whole percent. Nil when no host has been
	// evaluated yet.
	CompliancePct *int `json:"compliance_pct"`
	// HostCount is the number of active (non-deleted) hosts.
	HostCount int `json:"host_count"`
	// PassingRules / FailingRules are host_rule_state rows by status.
	PassingRules int `json:"passing_rules"`
	FailingRules int `json:"failing_rules"`
	// CriticalIssues is the count of failing rows with critical severity.
	CriticalIssues int `json:"critical_issues"`
	// TopFailingRules lists the rules failing on the most hosts.
	TopFailingRules []TopFailingRule `json:"top_failing_rules"`
}

// TopFailingRule is one entry in the executive summary's top-failing
// list: a rule id and how many hosts it fails on.
type TopFailingRule struct {
	RuleID           string `json:"rule_id"`
	FailingHostCount int    `json:"failing_host_count"`
}
