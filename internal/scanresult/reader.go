package scanresult

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/scanruns"
)

// Sentinel errors for the read surface; handlers map these to 404.
var (
	ErrScanNotFound = errors.New("scanresult: scan not found")
	ErrRuleNotFound = errors.New("scanresult: rule not found in scan")
)

// Reader backs the /api/v1/scans surface (scan:read): listing a host's
// scans, a scan's per-rule results, one rule's evidence, and OSCAL
// reconstruction. Read-only; constructed once at boot.
type Reader struct {
	pool *pgxpool.Pool
}

// NewReader wires the reader to the connection pool.
func NewReader(pool *pgxpool.Pool) *Reader { return &Reader{pool: pool} }

// ScanSummary is the scan_runs metadata shown in the list and the scan
// detail header.
type ScanSummary struct {
	ScanID        uuid.UUID
	HostID        uuid.UUID
	Status        string
	TriggerSource string
	QueuedAt      time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
	PolicyVersion string
	RulesPass     int
	RulesFail     int
	RulesSkipped  int
	RulesError    int
}

func summaryFromRun(r *scanruns.Run) ScanSummary {
	s := ScanSummary{
		ScanID:        r.ID,
		HostID:        r.HostID,
		Status:        string(r.Status),
		TriggerSource: string(r.TriggerSource),
		QueuedAt:      r.QueuedAt,
		StartedAt:     r.StartedAt,
		FinishedAt:    r.FinishedAt,
		PolicyVersion: r.PolicyVersion,
	}
	if r.Counts != nil {
		s.RulesPass = r.Counts.Pass
		s.RulesFail = r.Counts.Fail
		s.RulesSkipped = r.Counts.Skipped
		s.RulesError = r.Counts.Error
	}
	return s
}

// RuleResult is one row of the scan-detail list. It deliberately carries
// NO evidence payload (only has_evidence) — the list view stays small and
// the raw check output is fetched on demand via RuleEvidence.
type RuleResult struct {
	RuleID        string
	Status        string
	Severity      string
	FrameworkRefs map[string][]string
	SkipReason    string
	HasEvidence   bool
}

// RuleEvidenceDetail is the per-rule drill-down payload: the stored
// evidenceDoc unwrapped (detail/error/checks) plus result metadata.
type RuleEvidenceDetail struct {
	RuleID        string
	Status        string
	Severity      string
	Detail        string
	Error         string
	Checks        []kensaapi.CheckEvidence
	FrameworkRefs map[string][]string
	SkipReason    string
}

// evidenceDoc mirrors the document the kensa executor writes
// (internal/kensa/scanfunc.go evidenceJSON): the verdict detail, an
// optional error, and the structured per-command checks.
type evidenceDoc struct {
	Detail string                   `json:"detail"`
	Error  string                   `json:"error,omitempty"`
	Checks []kensaapi.CheckEvidence `json:"checks,omitempty"`
}

// ListByHost returns a host's scans newest first, capped at limit. cursor
// is the queued_at of the last row already seen (zero starts at the
// newest). It returns the page plus the next cursor (zero when the host
// has no older scans).
func (rd *Reader) ListByHost(ctx context.Context, hostID uuid.UUID, limit int, cursor time.Time) ([]ScanSummary, time.Time, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := rd.pool.Query(ctx, `
		SELECT id, host_id, trigger_source, status,
		       queued_at, started_at, finished_at,
		       COALESCE(policy_version, ''),
		       rules_pass, rules_fail, rules_skipped, rules_error
		  FROM scan_runs
		 WHERE host_id = $1
		   AND ($2::timestamptz IS NULL OR queued_at < $2)
		 ORDER BY queued_at DESC
		 LIMIT $3`,
		hostID, nullableTime(cursor), limit+1) // +1 to detect a further page.
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("scanresult: list scans: %w", err)
	}
	defer rows.Close()

	var out []ScanSummary
	for rows.Next() {
		var (
			s                           ScanSummary
			pass, fail, skipped, errCnt *int
		)
		if err := rows.Scan(&s.ScanID, &s.HostID, &s.TriggerSource, &s.Status,
			&s.QueuedAt, &s.StartedAt, &s.FinishedAt, &s.PolicyVersion,
			&pass, &fail, &skipped, &errCnt); err != nil {
			return nil, time.Time{}, fmt.Errorf("scanresult: scan scan_runs row: %w", err)
		}
		if pass != nil {
			s.RulesPass, s.RulesFail, s.RulesSkipped, s.RulesError = *pass, *fail, *skipped, *errCnt
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, time.Time{}, fmt.Errorf("scanresult: iterate scans: %w", err)
	}

	var next time.Time
	if len(out) > limit {
		next = out[limit-1].QueuedAt // last row of THIS page is the next cursor.
		out = out[:limit]
	}
	return out, next, nil
}

// GetScan returns a scan's metadata, or ErrScanNotFound.
func (rd *Reader) GetScan(ctx context.Context, scanID uuid.UUID) (ScanSummary, error) {
	run, err := scanruns.Get(ctx, rd.pool, scanID)
	if errors.Is(err, scanruns.ErrNotFound) {
		return ScanSummary{}, ErrScanNotFound
	}
	if err != nil {
		return ScanSummary{}, err
	}
	return summaryFromRun(run), nil
}

// ScanResults returns every rule's verdict for a scan, ordered by
// severity (critical first) then rule_id. Returns an empty slice (not an
// error) for a scan with no recorded results.
func (rd *Reader) ScanResults(ctx context.Context, scanID uuid.UUID) ([]RuleResult, error) {
	rows, err := rd.pool.Query(ctx, `
		SELECT rule_id, status, COALESCE(severity, ''),
		       framework_refs, COALESCE(skip_reason, ''),
		       evidence_hash IS NOT NULL
		  FROM scan_results
		 WHERE scan_id = $1
		 ORDER BY `+severityRankSQL+`, rule_id ASC`,
		scanID)
	if err != nil {
		return nil, fmt.Errorf("scanresult: scan results: %w", err)
	}
	defer rows.Close()

	var out []RuleResult
	for rows.Next() {
		var (
			rr      RuleResult
			refsRaw []byte
		)
		if err := rows.Scan(&rr.RuleID, &rr.Status, &rr.Severity,
			&refsRaw, &rr.SkipReason, &rr.HasEvidence); err != nil {
			return nil, fmt.Errorf("scanresult: scan result row: %w", err)
		}
		rr.FrameworkRefs = decodeRefs(refsRaw)
		out = append(out, rr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanresult: iterate results: %w", err)
	}
	return out, nil
}

// RuleEvidence returns one rule's full drill-down payload (the stored
// evidence unwrapped + metadata), or ErrRuleNotFound when the (scan,
// rule) pair is absent. A rule with no captured evidence returns a detail
// with empty Detail/Checks (not an error).
func (rd *Reader) RuleEvidence(ctx context.Context, scanID uuid.UUID, ruleID string) (RuleEvidenceDetail, error) {
	var (
		d       RuleEvidenceDetail
		refsRaw []byte
		evRaw   []byte // NULL when no evidence captured.
	)
	d.RuleID = ruleID
	err := rd.pool.QueryRow(ctx, `
		SELECT sr.status, COALESCE(sr.severity, ''),
		       sr.framework_refs, COALESCE(sr.skip_reason, ''),
		       se.evidence
		  FROM scan_results sr
		  LEFT JOIN scan_evidence se ON se.evidence_hash = sr.evidence_hash
		 WHERE sr.scan_id = $1 AND sr.rule_id = $2`,
		scanID, ruleID,
	).Scan(&d.Status, &d.Severity, &refsRaw, &d.SkipReason, &evRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return RuleEvidenceDetail{}, ErrRuleNotFound
	}
	if err != nil {
		return RuleEvidenceDetail{}, fmt.Errorf("scanresult: rule evidence: %w", err)
	}
	d.FrameworkRefs = decodeRefs(refsRaw)
	if len(evRaw) > 0 {
		var doc evidenceDoc
		if err := json.Unmarshal(evRaw, &doc); err != nil {
			return RuleEvidenceDetail{}, fmt.Errorf("scanresult: decode evidence rule=%s: %w", ruleID, err)
		}
		d.Detail, d.Error, d.Checks = doc.Detail, doc.Error, doc.Checks
	}
	return d, nil
}

// ReconstructOutcome builds the kensa api.RuleOutcome for one rule, for
// per-rule OSCAL export. Propagates ErrRuleNotFound / ErrScanNotFound.
func (rd *Reader) ReconstructOutcome(ctx context.Context, scanID uuid.UUID, ruleID string) (kensaapi.RuleOutcome, error) {
	d, err := rd.RuleEvidence(ctx, scanID, ruleID)
	if err != nil {
		return kensaapi.RuleOutcome{}, err
	}
	return toKensaOutcome(d), nil
}

// ReconstructScan builds every rule's kensa api.RuleOutcome for a scan,
// for whole-scan OSCAL export. Returns ErrScanNotFound when the scan has
// no recorded results.
func (rd *Reader) ReconstructScan(ctx context.Context, scanID uuid.UUID) ([]kensaapi.RuleOutcome, error) {
	rows, err := rd.pool.Query(ctx, `
		SELECT sr.rule_id, sr.status, COALESCE(sr.severity, ''),
		       sr.framework_refs, COALESCE(sr.skip_reason, ''),
		       se.evidence
		  FROM scan_results sr
		  LEFT JOIN scan_evidence se ON se.evidence_hash = sr.evidence_hash
		 WHERE sr.scan_id = $1
		 ORDER BY `+severityRankSQL+`, sr.rule_id ASC`,
		scanID)
	if err != nil {
		return nil, fmt.Errorf("scanresult: reconstruct scan: %w", err)
	}
	defer rows.Close()

	var outcomes []kensaapi.RuleOutcome
	for rows.Next() {
		var (
			d       RuleEvidenceDetail
			refsRaw []byte
			evRaw   []byte
		)
		if err := rows.Scan(&d.RuleID, &d.Status, &d.Severity,
			&refsRaw, &d.SkipReason, &evRaw); err != nil {
			return nil, fmt.Errorf("scanresult: reconstruct row: %w", err)
		}
		d.FrameworkRefs = decodeRefs(refsRaw)
		if len(evRaw) > 0 {
			var doc evidenceDoc
			if err := json.Unmarshal(evRaw, &doc); err != nil {
				return nil, fmt.Errorf("scanresult: decode evidence rule=%s: %w", d.RuleID, err)
			}
			d.Detail, d.Error, d.Checks = doc.Detail, doc.Error, doc.Checks
		}
		outcomes = append(outcomes, toKensaOutcome(d))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanresult: iterate reconstruct: %w", err)
	}
	if len(outcomes) == 0 {
		return nil, ErrScanNotFound
	}
	return outcomes, nil
}

// toKensaOutcome maps stored result + evidence to the kensa api type the
// OSCAL exporter consumes. Framework refs are flattened to one
// FrameworkRef per control, sorted for deterministic OSCAL output. Err is
// set only when the verdict is an error (kensa's api.RuleOutcome has no
// SkipReason field — skip context lives in Detail).
func toKensaOutcome(d RuleEvidenceDetail) kensaapi.RuleOutcome {
	out := kensaapi.RuleOutcome{
		RuleID:   d.RuleID,
		Status:   kensaapi.ComplianceStatus(d.Status),
		Severity: d.Severity,
		Detail:   d.Detail,
		Evidence: d.Checks,
	}
	frameworks := make([]string, 0, len(d.FrameworkRefs))
	for fw := range d.FrameworkRefs {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)
	for _, fw := range frameworks {
		controls := append([]string(nil), d.FrameworkRefs[fw]...)
		sort.Strings(controls)
		for _, c := range controls {
			out.FrameworkRefs = append(out.FrameworkRefs, kensaapi.FrameworkRef{FrameworkID: fw, ControlID: c})
		}
	}
	if d.Status == string(kensaapi.ComplianceError) && d.Error != "" {
		out.Err = errors.New(d.Error)
	}
	return out
}

// severityRankSQL orders critical→high→medium→low→(unset), matching the
// host-compliance lens ordering so the two surfaces agree.
const severityRankSQL = `CASE severity
	WHEN 'critical' THEN 0
	WHEN 'high' THEN 1
	WHEN 'medium' THEN 2
	WHEN 'low' THEN 3
	ELSE 4 END`

// decodeRefs unmarshals a framework_refs JSONB blob, defaulting to an
// empty map on absent/invalid content (the column is never null, but a
// scan-detail row should degrade rather than fail on a bad blob).
func decodeRefs(raw []byte) map[string][]string {
	refs := map[string][]string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &refs)
	}
	return refs
}

// nullableTime converts a zero time to nil so the cursor predicate skips.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
