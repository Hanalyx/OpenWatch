package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get when no report has the given id.
// Handlers map it to 404.
var ErrNotFound = errors.New("report: not found")

// ErrGroupScopeUnavailable is returned by Generate when a group scope is
// requested but no group resolver was wired (WithGroups). In production
// the resolver is always wired, so this is a programmer/config error.
var ErrGroupScopeUnavailable = errors.New("report: group scope unavailable")

// ErrInvalidKind is returned by Generate for an unknown report kind.
// Handlers map it to 400.
var ErrInvalidKind = errors.New("report: invalid kind")

// topFailingLimit caps how many failing rules the executive summary
// embeds. Small, leadership-facing list (matches the prototype).
const topFailingLimit = 5

// executiveTitle is the fixed title for the executive summary kind.
const executiveTitle = "Fleet Compliance - Executive Summary"

// attestationTitle is the fixed title for the framework attestation kind.
const attestationTitle = "Framework Attestation"

// allHostsLabel is the scope_label when no group scopes the report.
const allHostsLabel = "All hosts"

// GroupScoper resolves a group id to its display name and member host
// ids, so the report service can scope a fleet computation to one group
// without depending on the group package's types. internal/group's
// Service satisfies it via ScopeGroup.
type GroupScoper interface {
	ScopeGroup(ctx context.Context, groupID uuid.UUID) (name string, hostIDs []uuid.UUID, err error)
}

// Service owns the reports library: generating an executive summary
// from current posture, and listing/fetching stored reports.
type Service struct {
	pool   *pgxpool.Pool
	groups GroupScoper // nil until WithGroups; group scoping then 503s
	signer *Signer     // nil until WithSigner; snapshots then go unsigned
	// asyncRender, when true, makes Generate enqueue a report.render job for
	// an attestation (pre-marking its bulk faces 'pending') instead of
	// leaving every face to lazy first-download rendering. Set by
	// WithAsyncRender in production wiring; off in tests that have no worker.
	asyncRender bool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// WithGroups wires the group resolver used for group-scoped reports.
// Returns the receiver for chaining at construction time.
func (s *Service) WithGroups(g GroupScoper) *Service {
	s.groups = g
	return s
}

// WithSigner wires the Ed25519 signer that signs new snapshots over their
// content address. Without it, snapshots are generated unsigned (signature
// + signing_key_id stay null).
func (s *Service) WithSigner(signer *Signer) *Service {
	s.signer = signer
	return s
}

// Signer exposes the wired signer (for the signing-key endpoint), or nil.
func (s *Service) Signer() *Signer { return s.signer }

// WithAsyncRender enables async rendering of attestation bulk faces:
// Generate then marks the faces 'pending' and enqueues a report.render job
// (a RenderProcessor on the in-process worker renders them and publishes
// ReportReady). Enable it only when a worker is running to drain the queue;
// without it Generate stays synchronous and faces render lazily on first
// download.
func (s *Service) WithAsyncRender() *Service {
	s.asyncRender = true
	return s
}

const reportCols = `id, title, kind, scope_label, scope, data_as_of, generated_by, format, content, content_sha256, signature, signing_key_id, created_at`

func scanReport(row pgx.Row) (Report, error) {
	var rep Report
	var scopeRaw []byte
	var sig []byte
	var keyID *string
	err := row.Scan(&rep.ID, &rep.Title, &rep.Kind, &rep.ScopeLabel, &scopeRaw,
		&rep.DataAsOf, &rep.GeneratedBy, &rep.Format, &rep.Content, &rep.ContentSHA256,
		&sig, &keyID, &rep.CreatedAt)
	if err != nil {
		return rep, err
	}
	rep.Signature = sig
	if keyID != nil {
		rep.SigningKeyID = *keyID
	}
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &rep.Scope); err != nil {
			return rep, fmt.Errorf("report: decode scope: %w", err)
		}
	}
	return rep, nil
}

// Generate computes the Fleet Compliance Executive Summary from current
// posture (host_rule_state pass/fail counts + critical, the active host
// count, and the top failing rules) and inserts an immutable report
// row. The optional req scopes the summary to a group's member hosts
// and/or a framework lens; an empty req covers all hosts and all
// frameworks (the pre-A1 behavior). generatedBy is the actor recorded on
// the artifact (an email or "scheduler"). The returned Report carries
// the stored JSON content and the resolved scope.
func (s *Service) Generate(ctx context.Context, generatedBy string, req GenerateRequest) (Report, error) {
	kind := req.Kind
	if kind == "" {
		kind = KindExecutive
	}
	if kind != KindExecutive && kind != KindAttestation {
		return Report{}, ErrInvalidKind
	}

	scope := Scope{Framework: req.Framework}
	var hostIDs []uuid.UUID // nil = all hosts (no host filter)
	if req.GroupID != nil {
		if s.groups == nil {
			return Report{}, ErrGroupScopeUnavailable
		}
		name, ids, err := s.groups.ScopeGroup(ctx, *req.GroupID)
		if err != nil {
			return Report{}, err // group.ErrNotFound propagates; handler maps to 400
		}
		scope.GroupID = req.GroupID
		scope.GroupName = name
		// A resolved group always filters by host id — even an empty
		// group, which must read as zero hosts (not "all hosts").
		hostIDs = ids
		if hostIDs == nil {
			hostIDs = []uuid.UUID{}
		}
	}

	// Compute the kind's frozen content.
	var content any
	title := executiveTitle
	switch kind {
	case KindAttestation:
		c, err := s.computeAttestation(ctx, hostIDs, scope.Framework)
		if err != nil {
			return Report{}, err
		}
		content = c
		title = attestationTitle
	default:
		c, err := s.computeExecutive(ctx, hostIDs, scope.Framework)
		if err != nil {
			return Report{}, err
		}
		content = c
	}

	raw, err := json.Marshal(content)
	if err != nil {
		return Report{}, fmt.Errorf("report: marshal content: %w", err)
	}
	scopeRaw, err := json.Marshal(scope)
	if err != nil {
		return Report{}, fmt.Errorf("report: marshal scope: %w", err)
	}
	// content_sha256 is the snapshot's content address, computed over the
	// canonical marshaled content (the exact bytes stored). Identical
	// content yields an identical hash - the stable identity the signature
	// signs over.
	sum := sha256.Sum256(raw)
	contentSHA := hex.EncodeToString(sum[:])

	// Sign the content address when a signer is wired.
	var signature []byte
	var signingKeyID *string
	if s.signer != nil {
		sig, keyID := s.signer.Sign(contentSHA)
		signature = sig
		signingKeyID = &keyID
	}

	dataAsOf := time.Now().UTC()
	row := s.pool.QueryRow(ctx, `
		INSERT INTO report_snapshots (id, title, kind, scope_label, scope, data_as_of, generated_by, format, content, content_sha256, signature, signing_key_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING `+reportCols,
		uuid.New(), title, kind, scopeLabel(scope), scopeRaw,
		dataAsOf, generatedBy, "json", raw, contentSHA, signature, signingKeyID)
	rep, err := scanReport(row)
	if err != nil {
		return Report{}, fmt.Errorf("report: generate insert: %w", err)
	}

	// Attestation faces (CSV / OSCAL SAR / PDF) are the expensive bulk
	// renders; when async is enabled, queue them so Generate returns fast
	// and the operator is notified (ReportReady) when the bundle is ready.
	// The executive summary is a tiny rollup - it stays synchronous.
	if s.asyncRender && kind == KindAttestation {
		s.enqueueRender(ctx, rep.ID)
	}
	return rep, nil
}

// Frameworks returns the distinct framework_refs keys present anywhere in
// the fleet, each with the count of distinct rules mapped to it,
// most-populated first. Backs the report scope picker's framework lens.
func (s *Service) Frameworks(ctx context.Context) ([]FrameworkCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT k AS framework, count(DISTINCT rule_id)::int AS rule_count
		  FROM host_rule_state, jsonb_object_keys(framework_refs) AS k
		 GROUP BY k
		 ORDER BY rule_count DESC, k ASC`)
	if err != nil {
		return nil, fmt.Errorf("report: frameworks: %w", err)
	}
	defer rows.Close()
	out := []FrameworkCount{}
	for rows.Next() {
		var f FrameworkCount
		if err := rows.Scan(&f.Framework, &f.RuleCount); err != nil {
			return nil, fmt.Errorf("report: frameworks scan: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("report: frameworks iterate: %w", err)
	}
	return out, nil
}

// computeAttestation freezes which completed scan attests each in-scope
// active host (the latest as of now). Point-in-time without copying the
// bulk rows: scan_results are immutable, so the CSV/OSCAL faces
// reconstruct per-(host, rule) outcomes from these frozen scan ids on
// demand. The framework lens narrows the rows in the faces, not which
// hosts are attested (a host is attested if it has any completed scan).
func (s *Service) computeAttestation(ctx context.Context, hostIDs []uuid.UUID, framework string) (AttestationContent, error) {
	c := AttestationContent{Framework: framework, Attested: []AttestedHost{}}

	// Active in-scope host count (whether or not scanned).
	hostQ := `SELECT count(*) FROM hosts WHERE deleted_at IS NULL`
	hostArgs := []any{}
	if hostIDs != nil {
		hostQ += " AND id = ANY($1)"
		hostArgs = append(hostArgs, hostIDs)
	}
	if err := s.pool.QueryRow(ctx, hostQ, hostArgs...).Scan(&c.HostsTotal); err != nil {
		return AttestationContent{}, fmt.Errorf("report: attestation host count: %w", err)
	}

	// Latest completed scan per active in-scope host.
	scanQ := `
		SELECT DISTINCT ON (sr.host_id) sr.host_id, sr.id, sr.finished_at
		  FROM scan_runs sr
		  JOIN hosts h ON h.id = sr.host_id
		 WHERE sr.status = 'completed' AND sr.finished_at IS NOT NULL AND h.deleted_at IS NULL`
	scanArgs := []any{}
	if hostIDs != nil {
		scanQ += " AND sr.host_id = ANY($1)"
		scanArgs = append(scanArgs, hostIDs)
	}
	scanQ += " ORDER BY sr.host_id, sr.finished_at DESC"
	rows, err := s.pool.Query(ctx, scanQ, scanArgs...)
	if err != nil {
		return AttestationContent{}, fmt.Errorf("report: attestation scans: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a AttestedHost
		if err := rows.Scan(&a.HostID, &a.ScanID, &a.ScannedAt); err != nil {
			return AttestationContent{}, fmt.Errorf("report: attestation scan: %w", err)
		}
		c.Attested = append(c.Attested, a)
	}
	if err := rows.Err(); err != nil {
		return AttestationContent{}, fmt.Errorf("report: attestation iterate: %w", err)
	}
	c.HostsAttested = len(c.Attested)
	return c, nil
}

// computeExecutive samples the fleet posture from host_rule_state and
// the hosts table. Same shape as the Groups fleet rollup and
// fleetrollup.TopFailingRules so the numbers agree across the app. When
// hostIDs is non-nil the posture is scoped to those hosts (an empty
// slice yields zero rows); when framework is non-empty only rules whose
// framework_refs contain that key are counted (the same `?` lens as
// fleetrollup.WithFramework).
func (s *Service) computeExecutive(ctx context.Context, hostIDs []uuid.UUID, framework string) (ExecutiveContent, error) {
	var c ExecutiveContent

	// Shared host_rule_state filters, parameterized so the scoped and
	// unscoped paths are one query each.
	var hrsWhere strings.Builder
	args := []any{}
	addArg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if hostIDs != nil {
		hrsWhere.WriteString(" AND host_id = ANY(" + addArg(hostIDs) + ")")
	}
	if framework != "" {
		hrsWhere.WriteString(" AND framework_refs ? " + addArg(framework))
	}

	var passing, failing, critical, evaluated int
	err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE current_status = 'pass'),
		  count(*) FILTER (WHERE current_status = 'fail'),
		  count(*) FILTER (WHERE current_status = 'fail' AND severity ILIKE 'critical'),
		  count(*) FILTER (WHERE current_status IN ('pass','fail'))
		FROM host_rule_state
		WHERE true`+hrsWhere.String(), args...).Scan(&passing, &failing, &critical, &evaluated)
	if err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: posture counts: %w", err)
	}
	c.PassingRules = passing
	c.FailingRules = failing
	c.CriticalIssues = critical
	c.CompliancePct = compliancePct(passing, evaluated)

	// Coverage over the same scope. hosts_total is the active host count
	// (all non-deleted hosts, or the scoped subset), so host_count is
	// derived from it rather than queried twice.
	cov, err := s.computeCoverage(ctx, hostIDs)
	if err != nil {
		return ExecutiveContent{}, err
	}
	c.Coverage = cov
	c.HostCount = cov.HostsTotal

	// Top failing rules reuse the same host_rule_state filters plus the
	// LIMIT as the next placeholder.
	limitPH := fmt.Sprintf("$%d", len(args)+1)
	topArgs := append(append([]any{}, args...), topFailingLimit)
	rows, err := s.pool.Query(ctx, `
		SELECT rule_id, count(*)::int AS failing_host_count
		  FROM host_rule_state
		 WHERE current_status = 'fail'`+hrsWhere.String()+`
		 GROUP BY rule_id
		 ORDER BY failing_host_count DESC, rule_id ASC
		 LIMIT `+limitPH, topArgs...)
	if err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: top failing rules: %w", err)
	}
	defer rows.Close()
	c.TopFailingRules = []TopFailingRule{}
	for rows.Next() {
		var t TopFailingRule
		if err := rows.Scan(&t.RuleID, &t.FailingHostCount); err != nil {
			return ExecutiveContent{}, fmt.Errorf("report: top failing scan: %w", err)
		}
		c.TopFailingRules = append(c.TopFailingRules, t)
	}
	if err := rows.Err(); err != nil {
		return ExecutiveContent{}, fmt.Errorf("report: top failing iterate: %w", err)
	}
	return c, nil
}

// freshnessWindow is how recent a host's last compliance check must be
// for the host to count as "fresh" in the coverage block. A host whose
// newest host_rule_state.last_checked_at is older than this - or which
// has never been scanned - is stale. 24h matches the leadership-facing
// coverage caveat and sits comfortably inside the adaptive scheduler's
// 48h maximum interval, so a host on the slowest cadence still reads as
// fresh right after its scan.
const freshnessWindow = 24 * time.Hour

// computeCoverage describes how much of the in-scope active fleet the
// report actually reflects: of the non-deleted hosts (optionally scoped
// to hostIDs), how many have a host_rule_state check newer than
// freshnessWindow (fresh) versus stale-or-never-scanned, and how many are
// currently unreachable per host_liveness. A host with no liveness row
// counts as neither reachable nor unreachable (unknown != unreachable).
func (s *Service) computeCoverage(ctx context.Context, hostIDs []uuid.UUID) (Coverage, error) {
	cutoff := time.Now().Add(-freshnessWindow)
	args := []any{cutoff}
	hostFilter := ""
	if hostIDs != nil {
		hostFilter = " AND h.id = ANY($2)"
		args = append(args, hostIDs)
	}

	var cov Coverage
	err := s.pool.QueryRow(ctx, `
		WITH scoped AS (
		  SELECT h.id,
		         (SELECT max(hrs.last_checked_at) FROM host_rule_state hrs WHERE hrs.host_id = h.id) AS latest_check,
		         hl.reachability_status AS reach
		    FROM hosts h
		    LEFT JOIN host_liveness hl ON hl.host_id = h.id
		   WHERE h.deleted_at IS NULL`+hostFilter+`
		)
		SELECT
		  count(*),
		  count(*) FILTER (WHERE latest_check IS NOT NULL AND latest_check >= $1),
		  count(*) FILTER (WHERE latest_check IS NULL OR latest_check < $1),
		  count(*) FILTER (WHERE reach = 'unreachable')
		FROM scoped`, args...).
		Scan(&cov.HostsTotal, &cov.HostsFresh, &cov.HostsStale, &cov.HostsUnreachable)
	if err != nil {
		return Coverage{}, fmt.Errorf("report: coverage: %w", err)
	}
	return cov, nil
}

// scopeLabel renders the human scope_label from a resolved scope:
// "<group or All hosts>" optionally suffixed with " · <FRAMEWORK family>"
// (e.g. "Production · CIS", "All hosts · STIG", "Production", "All hosts").
func scopeLabel(sc Scope) string {
	left := allHostsLabel
	if sc.GroupName != "" {
		left = sc.GroupName
	}
	if fw := frameworkFamilyLabel(sc.Framework); fw != "" {
		return left + " · " + fw
	}
	return left
}

// frameworkFamilyLabel shortens a framework_refs key to its family for a
// leadership-facing label: "cis_rhel9_v2.0.0" -> "CIS", "stig_rhel9_v2r7"
// -> "STIG". The family is the token before the first underscore,
// uppercased. Empty in -> empty out (no lens).
func frameworkFamilyLabel(framework string) string {
	if framework == "" {
		return ""
	}
	head := framework
	if i := strings.IndexByte(framework, '_'); i > 0 {
		head = framework[:i]
	}
	return strings.ToUpper(head)
}

// compliancePct rounds passing/evaluated to a whole percent (round half
// up). It returns nil when nothing has been evaluated yet, so the
// executive summary distinguishes "0% compliant" from "never scanned".
// Pure (no DB), so the rounding contract is unit-tested directly.
func compliancePct(passing, evaluated int) *int {
	if evaluated <= 0 {
		return nil
	}
	pct := (passing*100 + evaluated/2) / evaluated
	return &pct
}

// List returns every report, newest first.
func (s *Service) List(ctx context.Context) ([]Report, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reportCols+` FROM report_snapshots ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("report: list: %w", err)
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, fmt.Errorf("report: list scan: %w", err)
		}
		out = append(out, rep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("report: list iterate: %w", err)
	}
	return out, nil
}

// Get returns one report by id, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Report, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+reportCols+` FROM report_snapshots WHERE id = $1`, id)
	rep, err := scanReport(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, fmt.Errorf("report: get: %w", err)
	}
	return rep, nil
}
