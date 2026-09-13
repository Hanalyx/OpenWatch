package report

// Report faces: downloadable renderings of a snapshot. The JSON face is
// the canonical snapshot content served verbatim; the PDF face is the
// bounded one-page executive document (pdf.go), rendered lazily on first
// request and cached in report_faces keyed by (snapshot_id, face) so a
// repeat download re-streams the stored bytes instead of re-rendering.
//
// Spec: api-reports v1.4.0.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Hanalyx/openwatch/internal/compliance"
)

// ErrInvalidFace is returned by Export for an unknown face (or a face that
// does not apply to the report's kind). Handlers map it to 400.
var ErrInvalidFace = errors.New("report: invalid face")

// Face identifiers.
const (
	FaceJSON = "json"
	FacePDF  = "pdf"
	FaceCSV  = "csv"
)

// maxAttestationRows caps the attestation CSV; a capped export appends a
// disclosure row so a truncated bundle is never mistaken for complete.
const maxAttestationRows = 100000

// maxRegisterRows caps the exception register CSV / row list.
const maxRegisterRows = 100000

// Export returns a rendered face of the report (its bytes + media type),
// or ErrNotFound for an unknown id / ErrInvalidFace for a face that does
// not apply to the report's kind. The JSON face is the canonical content
// (any kind); the PDF face is executive-only; the CSV face is
// attestation-only. Rendered faces are cached in report_faces.
func (s *Service) Export(ctx context.Context, id uuid.UUID, face string) ([]byte, string, error) {
	rep, err := s.Get(ctx, id)
	if err != nil {
		return nil, "", err // ErrNotFound propagates
	}
	switch face {
	case FaceJSON:
		return s.canonicalJSON(rep)
	case FacePDF:
		// PDF is the bounded human narrative for every kind, dispatched by
		// kind: the executive summary, the attestation cover, or the
		// exception register summary.
		switch rep.Kind {
		case KindExecutive:
			return s.exportPDF(ctx, rep)
		case KindAttestation:
			return s.exportAttestationPDF(ctx, rep)
		case KindException:
			return s.exportExceptionPDF(ctx, rep)
		case KindRemediation:
			return s.exportRemediationPDF(ctx, rep)
		default:
			return nil, "", ErrInvalidFace
		}
	case FaceCSV:
		// CSV is the bulk row export, dispatched by kind: the attestation
		// evidence extract, the exception register, or the remediation log.
		switch rep.Kind {
		case KindAttestation:
			return s.exportAttestationCSV(ctx, rep)
		case KindException:
			return s.exportExceptionCSV(ctx, rep)
		case KindRemediation:
			return s.exportRemediationCSV(ctx, rep)
		default:
			return nil, "", ErrInvalidFace
		}
	case FaceOSCALSAR:
		if rep.Kind != KindAttestation {
			return nil, "", ErrInvalidFace
		}
		return s.exportFleetOSCALSAR(ctx, rep)
	default:
		return nil, "", ErrInvalidFace
	}
}

// canonicalJSON re-marshals the decoded content into the kind's struct so
// the json face reproduces content_sha256 byte-for-byte (the stored jsonb
// is Postgres-normalized, not identical to the bytes that were hashed and
// signed). This makes a snapshot of either kind offline-verifiable:
// sha256(json face) == content_sha256.
func (s *Service) canonicalJSON(rep Report) ([]byte, string, error) {
	// A legacy artifact is canonicalized through the shape it was SIGNED
	// with. content is JSONB and never preserved the signed bytes, so the
	// canonical face is reconstructed by re-marshaling; re-marshaling a
	// legacy artifact through the current struct would add score_pct, drop a
	// null compliance_pct and reorder the fields, moving its hash and
	// invalidating its signature.
	if err := checkScoreFields(string(rep.Kind), rep.Content); err != nil {
		return nil, "", err
	}
	legacy := isLegacyArtifact(string(rep.Kind), rep.Content)

	// decode unmarshals into whichever shape this artifact was written with
	// and returns it for canonical re-marshaling.
	decode := func(current, old any) (any, error) {
		target := current
		if legacy {
			target = old
		}
		if err := json.Unmarshal(rep.Content, target); err != nil {
			return nil, err
		}
		// Dereferenced, because the canonical bytes must come from the VALUE
		// the original marshaled, not from a pointer to it.
		switch t := target.(type) {
		case *AttestationContent:
			return *t, nil
		case *legacyAttestationContent:
			return *t, nil
		case *ExceptionContent:
			return *t, nil
		case *RemediationContent:
			return *t, nil
		case *ExecutiveContent:
			return *t, nil
		case *legacyExecutiveContent:
			return *t, nil
		}
		return nil, fmt.Errorf("report: unhandled content shape %T", target)
	}

	var (
		v   any
		err error
	)
	switch rep.Kind {
	case KindAttestation:
		v, err = decode(&AttestationContent{}, &legacyAttestationContent{})
	case KindException:
		// The read-model kinds carry no score, and their provenance field is
		// omitempty, so a legacy read model re-marshals to its original bytes
		// through the current struct. They need no frozen shape.
		v, err = decode(&ExceptionContent{}, &ExceptionContent{})
	case KindRemediation:
		v, err = decode(&RemediationContent{}, &RemediationContent{})
	default:
		v, err = decode(&ExecutiveContent{}, &legacyExecutiveContent{})
	}
	if err != nil {
		return nil, "", fmt.Errorf("report: decode %s content: %w", rep.Kind, err)
	}

	canonical, err := json.Marshal(v)
	if err != nil {
		return nil, "", fmt.Errorf("report: marshal canonical json: %w", err)
	}
	return canonical, "application/json", nil
}

// exportPDF returns the cached PDF face if present, else renders the
// executive PDF from the frozen content, caches it in report_faces, and
// returns it.
func (s *Service) exportPDF(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "application/pdf"

	// Cache hit?
	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FacePDF).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: face lookup: %w", err)
	}

	// Render from the frozen content.
	var c ExecutiveContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode content for pdf: %w", err)
	}
	pdfBytes, err := renderExecutivePDF(rep, c)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pdfBytes)
	blobSHA := hex.EncodeToString(sum[:])

	// Cache it (idempotent: a concurrent render just overwrites with the
	// same deterministic bytes).
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FacePDF, mediaType, pdfBytes, len(pdfBytes), blobSHA)
	if err != nil {
		// A cache write failure should not fail the download - the bytes
		// are already rendered.
		return pdfBytes, mediaType, nil
	}
	return pdfBytes, mediaType, nil
}

// ExportFilename builds a download filename for a report face, e.g.
// "openwatch-executive-all-hosts-2026-06-21.pdf" or
// "openwatch-attestation-production-cis-2026-06-21.csv".
func ExportFilename(rep Report, face string) string {
	kind := string(rep.Kind)
	if kind == "" {
		kind = "report"
	}
	// The OSCAL SAR is a JSON document; give it a readable .oscal.json
	// extension rather than the raw face token.
	ext := face
	if face == FaceOSCALSAR {
		ext = "oscal.json"
	}
	return fmt.Sprintf("openwatch-%s-%s-%s.%s", kind, slugify(rep.ScopeLabel), rep.DataAsOf.Format("2006-01-02"), ext)
}

// slugify lowercases and replaces non-alphanumeric runs with single
// hyphens for a filesystem-safe filename fragment.
func slugify(s string) string {
	out := make([]byte, 0, len(s))
	prevHyphen := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
			prevHyphen = false
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			out = append(out, c)
			prevHyphen = false
		default:
			if !prevHyphen {
				out = append(out, '-')
				prevHyphen = true
			}
		}
	}
	res := string(out)
	// trim leading/trailing hyphens
	for len(res) > 0 && res[0] == '-' {
		res = res[1:]
	}
	for len(res) > 0 && res[len(res)-1] == '-' {
		res = res[:len(res)-1]
	}
	if res == "" {
		res = "report"
	}
	return res
}

// exportAttestationCSV returns the cached CSV face if present, else
// renders one row per (host, rule) by reading the IMMUTABLE scan_results
// of the scans the snapshot froze (point-in-time), scoped by the
// snapshot's framework lens, caches it in report_faces, and returns it.
func (s *Service) exportAttestationCSV(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "text/csv"

	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FaceCSV).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: csv face lookup: %w", err)
	}

	var c AttestationContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode attestation content: %w", err)
	}
	scanIDs := make([]uuid.UUID, len(c.Attested))
	for i, a := range c.Attested {
		scanIDs[i] = a.ScanID
	}

	q := `
		SELECT COALESCE(h.hostname, ''), COALESCE(host(h.ip_address), ''),
		       COALESCE(h.os_family, ''), sr.rule_id, sr.status,
		       COALESCE(sr.severity, ''), sr.framework_refs::text,
		       COALESCE(encode(sr.evidence_hash, 'hex'), ''), run.finished_at
		  FROM scan_results sr
		  JOIN scan_runs run ON run.id = sr.scan_id
		  JOIN hosts h ON h.id = sr.host_id
		 WHERE sr.scan_id = ANY($1)`
	args := []any{scanIDs}
	if c.Framework != "" {
		q += " AND sr.framework_refs ? $2"
		args = append(args, c.Framework)
	}
	q += fmt.Sprintf(" ORDER BY h.hostname, sr.rule_id LIMIT $%d", len(args)+1)
	args = append(args, maxAttestationRows+1)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("report: attestation rows: %w", err)
	}
	defer rows.Close()

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"hostname", "ip", "os", "rule_id", "status", "severity",
		"framework_refs", "evidence_sha256", "scanned_at",
	})
	n := 0
	truncated := false
	for rows.Next() {
		if n >= maxAttestationRows {
			truncated = true
			break
		}
		var hostname, ip, os, ruleID, status, sev, fw, ev string
		var scannedAt time.Time
		if err := rows.Scan(&hostname, &ip, &os, &ruleID, &status, &sev, &fw, &ev, &scannedAt); err != nil {
			return nil, "", fmt.Errorf("report: attestation row scan: %w", err)
		}
		_ = w.Write([]string{
			csvSafe(hostname), csvSafe(ip), csvSafe(os), csvSafe(ruleID),
			csvSafe(status), csvSafe(sev), csvSafe(fw), csvSafe(ev),
			scannedAt.UTC().Format(time.RFC3339),
		})
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("report: attestation iterate: %w", err)
	}
	if truncated {
		_ = w.Write([]string{
			"# NOTE", fmt.Sprintf("export capped at %d rows; not complete", maxAttestationRows),
			"", "", "", "", "", "", "",
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", fmt.Errorf("report: write csv: %w", err)
	}
	csvBytes := buf.Bytes()

	sum := sha256.Sum256(csvBytes)
	blobSHA := hex.EncodeToString(sum[:])
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FaceCSV, mediaType, csvBytes, len(csvBytes), blobSHA)
	if err != nil {
		// A cache write failure should not fail the download.
		return csvBytes, mediaType, nil
	}
	return csvBytes, mediaType, nil
}

// exportAttestationPDF returns the cached attestation PDF face if present,
// else renders the one-page cover via renderAttestationPDF and caches it in
// report_faces. The rollup is read from the FROZEN content (computed once
// at generation time and signed), so the PDF, the in-app view, and the
// signature all show the same numbers. A pre-rollup snapshot (generated
// before the rollup was frozen) is handled by recomputing on the fly.
func (s *Service) exportAttestationPDF(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "application/pdf"

	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FacePDF).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: attestation pdf face lookup: %w", err)
	}

	var c AttestationContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode attestation content: %w", err)
	}
	// Back-compat, selected by GENERATION and never by data values.
	//
	// The condition was TotalChecks == 0 && HostsAttested > 0, which reads a
	// count and guesses. That misclassifies a current, correctly signed
	// attestation whose completed scans genuinely produced zero outcomes: it
	// has a frozen rollup saying so, and inferring "legacy" from the zero
	// threw that rollup away and recomputed one. An artifact's generation is
	// the presence or absence of its provenance key, exactly as AC-38
	// requires, and nothing else.
	if isLegacyArtifact(string(rep.Kind), rep.Content) {
		rollup, err := s.legacyRollupFor(ctx, c)
		if err != nil {
			return nil, "", err
		}
		c.Rollup = rollup
	}
	pdfBytes, err := renderAttestationPDF(rep, c)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pdfBytes)
	blobSHA := hex.EncodeToString(sum[:])
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FacePDF, mediaType, pdfBytes, len(pdfBytes), blobSHA)
	if err != nil {
		// A cache write failure should not fail the download.
		return pdfBytes, mediaType, nil
	}
	return pdfBytes, mediaType, nil
}

// scanIDsOf extracts the frozen scan ids from an attestation's attested list.
func scanIDsOf(c AttestationContent) []uuid.UUID {
	ids := make([]uuid.UUID, len(c.Attested))
	for i, a := range c.Attested {
		ids[i] = a.ScanID
	}
	return ids
}

// computeAttestationRollup runs two aggregate queries over the given frozen
// scans (counts by status, and the top failing rules by distinct failing
// host), applying the framework lens. Compliance is passing / (passing +
// failing), rounded half up, nil when nothing was evaluated. Called at
// generation time to FREEZE the rollup into the signed content (and as a
// back-compat fallback when rendering a pre-rollup snapshot).
// frozenPopulation selects the rollup's population directly from a stored
// artifact's own host ids, with no reference to the hosts table.
//
// A recomputed legacy face must not move when the fleet does. Reusing the
// generation query meant it filtered hosts.deleted_at IS NULL, so
// soft-deleting an attested host changed the numbers on an artifact that was
// already signed. What the artifact recorded is the record; the current
// deletion state of a host is not part of it.
const frozenPopulation = "unnest($%d::uuid[]) AS hh(id)"

func (s *Service) computeAttestationRollup(ctx context.Context, q queryer, hostIDs, scanIDs []uuid.UUID, framework string, frozen bool) (AttestationRollup, error) {
	var r AttestationRollup
	r.TopFailing = []TopFailingRule{}

	// One row PER HOST, from the frozen scans, plus the engine each scan run
	// recorded. Grouping by host is what makes the mean equal-host; the
	// replaced query summed every outcome in the attested set and divided
	// once, so an attestation over a 700-rule host and a 50-rule host
	// reported the first one and called it the fleet.
	//
	// The engine comes from the CONTRIBUTING scan runs, never from the
	// process generating the report. In a rolling deployment the API, the
	// rollup and the workers run different builds, so a process describing
	// itself names an engine that never touched the host.
	// The population is EVERY ACTIVE IN-SCOPE HOST, left-joined to the results
	// of its FROZEN scan, not the hosts that happen to have results.
	//
	// Starting from scan_results made a host disappear rather than count: a
	// host with no completed scan, a completed scan that produced zero
	// results, or a scan whose results all fall outside the lens each yielded
	// no row. The participation counts then described only the hosts with
	// results, and the artifact was signed saying so.
	//
	// Joining on host_id AND the frozen scan id together is what binds each
	// host to the scan this attestation froze, rather than to whatever scan it
	// has now. The lens sits in the JOIN condition for the same reason as the
	// executive query: in WHERE it would turn the outer join back into an
	// inner one.
	countArgs := []any{scanIDs}
	next := 2

	// The population source. Generating fresh content asks the hosts table
	// which hosts are active; re-rendering a stored artifact asks the artifact.
	population := "hosts hh"
	if frozen {
		population = fmt.Sprintf(frozenPopulation, next)
		countArgs = append(countArgs, hostIDs)
		next++
	}

	countQ := `
		SELECT hh.id,
		       count(sr.rule_id)::int,
		       count(*) FILTER (WHERE sr.status = 'pass')::int,
		       count(*) FILTER (WHERE sr.status = 'fail')::int,
		       count(*) FILTER (WHERE sr.status = 'skipped')::int,
		       count(*) FILTER (WHERE sr.status = 'error')::int,
		       COALESCE(MIN(run.engine_version), '')
		  FROM ` + population + `
		  LEFT JOIN scan_results sr
		    ON sr.host_id = hh.id
		   AND sr.scan_id = ANY($1)`
	if framework != "" {
		countQ += fmt.Sprintf(" AND sr.framework_refs ? $%d", next)
		countArgs = append(countArgs, framework)
		next++
	}
	countQ += `
		  LEFT JOIN scan_runs run ON run.id = sr.scan_id`
	if !frozen {
		countQ += `
		 WHERE hh.deleted_at IS NULL`
		if hostIDs != nil {
			countQ += fmt.Sprintf(" AND hh.id = ANY($%d)", next)
			countArgs = append(countArgs, hostIDs)
		}
	}
	countQ += " GROUP BY hh.id"
	hostRows, err := q.Query(ctx, countQ, countArgs...)
	if err != nil {
		return AttestationRollup{}, fmt.Errorf("report: attestation rollup counts: %w", err)
	}
	var (
		hostScores []compliance.Score
		engines    []compliance.EngineContributor
		noEngine   int
	)
	for hostRows.Next() {
		var (
			hostID                              uuid.UUID
			total, pass, fail, skipped, errored int
			engine                              string
		)
		if err := hostRows.Scan(&hostID, &total, &pass, &fail, &skipped, &errored,
			&engine); err != nil {
			hostRows.Close()
			return AttestationRollup{}, fmt.Errorf("report: attestation rollup host: %w", err)
		}
		r.TotalChecks += total
		r.Passing += pass
		r.Failing += fail
		r.Skipped += skipped
		r.Errored += errored
		score := compliance.HostScore(compliance.Counts{
			Pass: pass, Fail: fail, Skipped: skipped, Error: errored,
		})
		hostScores = append(hostScores, score)
		if !score.Present() {
			continue
		}
		if engine == "" {
			noEngine++
			continue
		}
		engines = append(engines, compliance.EngineContributor{
			EngineVersion: engine, ContributorsScored: 1,
		})
	}
	if err := hostRows.Err(); err != nil {
		hostRows.Close()
		return AttestationRollup{}, fmt.Errorf("report: attestation rollup iterate: %w", err)
	}
	hostRows.Close()

	agg := compliance.MeanOfHostScores(hostScores)
	r.ScorePct = scorePtr(agg.Score)
	env, err := compliance.ScoreBearingEnvelope(lensName(framework),
		compliance.AggregationEqualHostMean, engines, noEngine, nil,
		agg.HostsScored, agg.HostsScored)
	if err != nil {
		return AttestationRollup{}, fmt.Errorf("report: attestation provenance: %w", err)
	}
	r.Provenance = NewScoreProvenance(env, agg)

	topQ := `
		SELECT sr.rule_id, count(DISTINCT sr.host_id)
		  FROM scan_results sr
		 WHERE sr.scan_id = ANY($1) AND sr.status = 'fail'`
	topArgs := []any{scanIDs}
	if framework != "" {
		topQ += " AND sr.framework_refs ? $2"
		topArgs = append(topArgs, framework)
	}
	topQ += " GROUP BY sr.rule_id ORDER BY count(DISTINCT sr.host_id) DESC, sr.rule_id LIMIT 10"
	rows, err := q.Query(ctx, topQ, topArgs...)
	if err != nil {
		return AttestationRollup{}, fmt.Errorf("report: attestation rollup top-failing: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t TopFailingRule
		if err := rows.Scan(&t.RuleID, &t.FailingHostCount); err != nil {
			return AttestationRollup{}, fmt.Errorf("report: attestation rollup scan: %w", err)
		}
		r.TopFailing = append(r.TopFailing, t)
	}
	if err := rows.Err(); err != nil {
		return AttestationRollup{}, fmt.Errorf("report: attestation rollup iterate: %w", err)
	}
	return r, nil
}

// exportExceptionCSV returns the cached exception-register CSV face if
// present, else writes one row per frozen waiver (the register is stored on
// the snapshot content, so this reads the frozen rows rather than
// re-querying), caches it in report_faces, and returns it.
func (s *Service) exportExceptionCSV(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "text/csv"

	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FaceCSV).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: exception csv face lookup: %w", err)
	}

	var c ExceptionContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode exception content: %w", err)
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"host", "rule_id", "status", "active", "reason",
		"requested_by", "requested_at", "reviewed_by", "reviewed_at", "expires_at",
	})
	for _, r := range c.Exceptions {
		_ = w.Write([]string{
			csvSafe(r.HostName), csvSafe(r.RuleID), csvSafe(r.Status), boolStr(r.Active),
			csvSafe(r.Reason), csvSafe(r.RequestedBy), r.RequestedAt.UTC().Format(time.RFC3339),
			csvSafe(r.ReviewedBy), timePtrStr(r.ReviewedAt), timePtrStr(r.ExpiresAt),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", fmt.Errorf("report: write exception csv: %w", err)
	}
	csvBytes := buf.Bytes()

	sum := sha256.Sum256(csvBytes)
	blobSHA := hex.EncodeToString(sum[:])
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FaceCSV, mediaType, csvBytes, len(csvBytes), blobSHA)
	if err != nil {
		return csvBytes, mediaType, nil
	}
	return csvBytes, mediaType, nil
}

// exportExceptionPDF returns the cached exception-register PDF face if
// present, else renders the bounded one-page summary (counts by state +
// expiring-soon) from the frozen content, caches it, and returns it.
func (s *Service) exportExceptionPDF(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "application/pdf"

	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FacePDF).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: exception pdf face lookup: %w", err)
	}

	var c ExceptionContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode exception content: %w", err)
	}
	pdfBytes, err := renderExceptionPDF(rep, c)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pdfBytes)
	blobSHA := hex.EncodeToString(sum[:])
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FacePDF, mediaType, pdfBytes, len(pdfBytes), blobSHA)
	if err != nil {
		return pdfBytes, mediaType, nil
	}
	return pdfBytes, mediaType, nil
}

// exportRemediationCSV returns the cached remediation-activity CSV face if
// present, else writes one row per frozen request (the log is stored on the
// snapshot content), caches it, and returns it.
func (s *Service) exportRemediationCSV(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "text/csv"

	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FaceCSV).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: remediation csv face lookup: %w", err)
	}

	var c RemediationContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode remediation content: %w", err)
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"host", "rule_id", "status", "mechanism",
		"requested_by", "requested_at", "reviewed_by", "reviewed_at",
	})
	for _, r := range c.Activities {
		_ = w.Write([]string{
			csvSafe(r.HostName), csvSafe(r.RuleID), csvSafe(r.Status), csvSafe(r.Mechanism),
			csvSafe(r.RequestedBy), r.RequestedAt.UTC().Format(time.RFC3339),
			csvSafe(r.ReviewedBy), timePtrStr(r.ReviewedAt),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", fmt.Errorf("report: write remediation csv: %w", err)
	}
	csvBytes := buf.Bytes()

	sum := sha256.Sum256(csvBytes)
	blobSHA := hex.EncodeToString(sum[:])
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FaceCSV, mediaType, csvBytes, len(csvBytes), blobSHA)
	if err != nil {
		return csvBytes, mediaType, nil
	}
	return csvBytes, mediaType, nil
}

// exportRemediationPDF returns the cached remediation-activity PDF face if
// present, else renders the bounded one-page summary from the frozen
// content, caches it, and returns it.
func (s *Service) exportRemediationPDF(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "application/pdf"

	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FacePDF).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: remediation pdf face lookup: %w", err)
	}

	var c RemediationContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode remediation content: %w", err)
	}
	pdfBytes, err := renderRemediationPDF(rep, c)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pdfBytes)
	blobSHA := hex.EncodeToString(sum[:])
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FacePDF, mediaType, pdfBytes, len(pdfBytes), blobSHA)
	if err != nil {
		return pdfBytes, mediaType, nil
	}
	return pdfBytes, mediaType, nil
}

// boolStr renders a bool as "yes"/"no" for CSV legibility.
func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// timePtrStr renders an optional timestamp as RFC3339 or "" when nil.
func timePtrStr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// csvSafe neutralizes spreadsheet formula injection (CWE-1236): a cell
// whose first byte is = + - @ tab or CR is prefixed with a single quote so
// it renders as literal text. (Mirrors the audit export's guard; a shared
// csvutil is a worthwhile follow-up.)
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// hostIDsOf returns the hosts an attestation snapshot froze.
func hostIDsOf(c AttestationContent) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(c.Attested))
	for _, a := range c.Attested {
		out = append(out, a.HostID)
	}
	return out
}

// legacyRollupFor recomputes the rollup for an artifact signed before the
// rollup was part of the content.
//
// The population comes from the artifact's OWN frozen host ids, not from the
// hosts table, and carries no current-deletion filter. Scoping it to today's
// active hosts made a signed artifact's rendered numbers move when a host was
// later soft-deleted, which is the opposite of what freezing content is for.
//
// It is a named function rather than an inline call so the rendering path's
// choice of population is the thing under test, not an argument a test can
// hardcode.
func (s *Service) legacyRollupFor(ctx context.Context, c AttestationContent) (AttestationRollup, error) {
	return s.computeAttestationRollup(
		ctx, s.pool, hostIDsOf(c), scanIDsOf(c), c.Framework, true)
}
