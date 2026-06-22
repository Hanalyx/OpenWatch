// Package report implements the Reports library: point-in-time,
// immutable, Ed25519-signed compliance artifacts. It generates four kinds
// (executive summary, framework attestation, exception register,
// remediation activity), each computed once from data that already exists
// and stored as a frozen JSON document; the row is never recomputed. Each
// kind renders to downloadable faces (PDF / CSV / OSCAL SAR / JSON).
//
// DEFERRED: the Templates gallery and retention sweeps (see the spec
// excludes). Recurring generation + email delivery lives in
// internal/reportschedule.
//
// Spec: api-reports.
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
	// KindException is the Exception Register: a Compliance/GRC point-in-time
	// read-model of compliance waivers (compliance_exceptions) - who waived
	// which rule on which host, the justification, the approver, and the
	// expiry. Faces: a CSV register + a bounded PDF summary (counts by
	// status + active + expiring-soon).
	KindException Kind = "exception"
	// KindRemediation is the Remediation Activity report: an Operations
	// read-model of remediation execute/rollback requests over a time
	// window (remediation_requests filtered on requested_at). Faces: a CSV
	// activity log + a bounded PDF summary (counts by outcome).
	KindRemediation Kind = "remediation"
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
	// Rollup is the headline compliance aggregate, FROZEN into the signed
	// snapshot at generation time (computed once from the frozen scans'
	// immutable scan_results, framework-lensed). Because it is part of the
	// content it is signed + tamper-evident, and the in-app view, the PDF
	// cover, and the signature all read the same numbers (P1: one snapshot,
	// identical across every face). It is bounded (aggregates + a small
	// top-N), never the per-(host, rule) rows.
	Rollup AttestationRollup `json:"rollup"`
}

// AttestationRollup is the bounded compliance aggregate stored on an
// attestation snapshot: pass/fail/total counts, fleet compliance percent,
// and a sampled top-failing list, over the frozen scans (framework-lensed).
type AttestationRollup struct {
	// CompliancePct is passing / (passing + failing), rounded half up; nil
	// when nothing was evaluated (so an unevaluated set reads as n/a, not 0%).
	CompliancePct *int `json:"compliance_pct"`
	// TotalChecks is every (host, rule) outcome counted; the rest are the
	// per-status splits.
	TotalChecks int `json:"total_checks"`
	Passing     int `json:"passing"`
	Failing     int `json:"failing"`
	Skipped     int `json:"skipped"`
	Errored     int `json:"errored"`
	// TopFailing lists the rules failing on the most hosts (capped).
	TopFailing []TopFailingRule `json:"top_failing"`
}

// ExceptionContent is the frozen snapshot for an Exception Register: a
// point-in-time summary of compliance waivers plus the register rows. The
// CSV face writes one row per exception; the PDF face renders the bounded
// summary (counts + expiring-soon).
type ExceptionContent struct {
	Summary    ExceptionSummary `json:"summary"`
	Exceptions []ExceptionRow   `json:"exceptions"`
}

// ExceptionSummary is the bounded rollup of the in-scope waivers by state.
// Active counts approved waivers not past their expiry; ExpiringSoon is the
// subset of Active whose expiry falls within the next 30 days.
type ExceptionSummary struct {
	Total        int `json:"total"`
	Active       int `json:"active"`
	Requested    int `json:"requested"`
	Approved     int `json:"approved"`
	Rejected     int `json:"rejected"`
	Revoked      int `json:"revoked"`
	Expired      int `json:"expired"`
	ExpiringSoon int `json:"expiring_soon"`
}

// ExceptionRow is one waiver in the register. Requester/reviewer are
// resolved to usernames (or "" when unresolved) so the register reads
// without a second lookup. Active is true for an approved, unexpired waiver.
type ExceptionRow struct {
	HostName    string     `json:"host_name"`
	RuleID      string     `json:"rule_id"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	ReviewedBy  string     `json:"reviewed_by"`
	ReviewedAt  *time.Time `json:"reviewed_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Active      bool       `json:"active"`
}

// RemediationContent is the frozen snapshot for a Remediation Activity
// report: the period it covers, a summary of requests by outcome, and the
// activity rows. The CSV face writes one row per request; the PDF face
// renders the bounded summary.
type RemediationContent struct {
	// PeriodFrom/PeriodTo bound the window (by requested_at). PeriodTo is
	// the generation instant; PeriodFrom is PeriodTo minus the period.
	PeriodFrom time.Time           `json:"period_from"`
	PeriodTo   time.Time           `json:"period_to"`
	Summary    RemediationSummary  `json:"summary"`
	Activities []RemediationActRow `json:"activities"`
}

// RemediationSummary is the bounded rollup of in-window requests by outcome.
type RemediationSummary struct {
	Total      int `json:"total"`
	Executed   int `json:"executed"`
	RolledBack int `json:"rolled_back"`
	Failed     int `json:"failed"`
	Rejected   int `json:"rejected"`
	Pending    int `json:"pending"`
}

// RemediationActRow is one remediation request in the activity log.
// Requester/reviewer are resolved to usernames.
type RemediationActRow struct {
	HostName    string     `json:"host_name"`
	RuleID      string     `json:"rule_id"`
	Status      string     `json:"status"`
	Mechanism   string     `json:"mechanism"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	ReviewedBy  string     `json:"reviewed_by"`
	ReviewedAt  *time.Time `json:"reviewed_at"`
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
	// PeriodDays is the look-back window for time-windowed kinds
	// (remediation): the report covers requests in the last PeriodDays. 0
	// defaults to defaultPeriodDays; ignored by point-in-time kinds.
	PeriodDays int
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
