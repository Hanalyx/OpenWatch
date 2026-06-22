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
	// KindAttestation is the Framework Attestation: the auditor/GRC bulk
	// evidence path. Its snapshot freezes the latest completed scan per
	// in-scope host; its bulk faces (CSV now, OSCAL SAR next) reconstruct
	// per-(host, rule) outcomes from those immutable scan_results.
	KindAttestation Kind = "attestation"
)

// AttestationContent is the frozen snapshot for a Framework Attestation:
// it captures WHICH scan attests each in-scope host (point-in-time, since
// scan_results are immutable), not the bulk rows themselves - the CSV /
// OSCAL faces reconstruct those from the referenced scans on demand.
type AttestationContent struct {
	// Framework is the lens (a framework_refs key), or "" for all.
	Framework string `json:"framework"`
	// HostsTotal is the active in-scope host count; HostsAttested is how
	// many of those have a completed scan to attest from.
	HostsTotal    int `json:"hosts_total"`
	HostsAttested int `json:"hosts_attested"`
	// Attested lists, per attested host, the scan the attestation is over.
	Attested []AttestedHost `json:"attested"`
}

// AttestedHost ties an in-scope host to the completed scan that attests
// it (its latest as of generation time) and when that scan finished.
type AttestedHost struct {
	HostID    uuid.UUID `json:"host_id"`
	ScanID    uuid.UUID `json:"scan_id"`
	ScannedAt time.Time `json:"scanned_at"`
}

// Report is one row of the report_snapshots table. Content holds the
// rendered JSON posture document (see ExecutiveContent for the executive
// shape).
type Report struct {
	ID          uuid.UUID
	Title       string
	Kind        Kind
	ScopeLabel  string
	Scope       Scope
	DataAsOf    time.Time
	GeneratedBy string
	Format      string
	Content     json.RawMessage
	// ContentSHA256 is the snapshot's content address: the hex SHA-256 of
	// the canonical (marshaled) Content. Identical content yields an
	// identical hash; it is the stable identity the signature signs over.
	ContentSHA256 string
	// Signature is the Ed25519 signature over the content address (nil
	// when the snapshot was generated without a signer). SigningKeyID is
	// the fingerprint of the key that produced it.
	Signature    []byte
	SigningKeyID string
	CreatedAt    time.Time
}

// Scope is the structured slice of the fleet a report summarizes: an
// optional group and/or framework lens. The zero value (no group, no
// framework) is the all-hosts, all-frameworks scope. It is stored as the
// reports.scope JSONB column and echoed on the API so a caller can see
// (and reproduce) exactly what a report covers.
type Scope struct {
	// GroupID, when set, scopes the report to that group's member hosts.
	GroupID *uuid.UUID `json:"group_id,omitempty"`
	// GroupName is the group's display name at generation time, frozen
	// onto the report so the label survives a later group rename/delete.
	GroupName string `json:"group_name,omitempty"`
	// Framework, when non-empty, scopes the report to rules whose
	// framework_refs contain this key (same lens as the fleet rollup).
	Framework string `json:"framework,omitempty"`
}

// GenerateRequest is the (all-optional) input to Generate. An empty
// request generates the all-hosts, all-frameworks executive summary —
// the pre-A1 behavior.
type GenerateRequest struct {
	// Kind selects the report kind; "" defaults to executive. attestation
	// produces the Framework Attestation (CSV/OSCAL bulk faces).
	Kind Kind
	// GroupID scopes the report to one group's member hosts.
	GroupID *uuid.UUID
	// Framework scopes the report to one framework lens.
	Framework string
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
	// Coverage describes how much of the in-scope fleet the numbers
	// actually reflect (fresh vs stale/never-scanned, and unreachable).
	Coverage Coverage `json:"coverage"`
}

// Coverage is the staleness disclosure behind every report: of the
// in-scope active hosts, how many have fresh compliance data versus
// stale-or-never-scanned, and how many are currently unreachable. It is
// the basis of the coverage caveat - the honesty that lets a reader trust
// or discount the headline numbers. hosts_fresh + hosts_stale ==
// hosts_total; hosts_unreachable is an independent reachability count (a
// host can be both stale and unreachable).
type Coverage struct {
	HostsTotal       int `json:"hosts_total"`
	HostsFresh       int `json:"hosts_fresh"`
	HostsStale       int `json:"hosts_stale"`
	HostsUnreachable int `json:"hosts_unreachable"`
}

// FrameworkCount is one entry in the fleet framework catalog: a
// framework_refs key present somewhere in the fleet and the number of
// distinct rules mapped to it. Backs the report scope picker's framework
// lens.
type FrameworkCount struct {
	Framework string `json:"framework"`
	RuleCount int    `json:"rule_count"`
}

// TopFailingRule is one entry in the executive summary's top-failing
// list: a rule id and how many hosts it fails on.
type TopFailingRule struct {
	RuleID           string `json:"rule_id"`
	FailingHostCount int    `json:"failing_host_count"`
}
