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
		// PDF is the bounded human narrative for BOTH kinds, dispatched by
		// kind: the executive summary or the framework attestation cover.
		switch rep.Kind {
		case KindExecutive:
			return s.exportPDF(ctx, rep)
		case KindAttestation:
			return s.exportAttestationPDF(ctx, rep)
		default:
			return nil, "", ErrInvalidFace
		}
	case FaceCSV:
		if rep.Kind != KindAttestation {
			return nil, "", ErrInvalidFace
		}
		return s.exportAttestationCSV(ctx, rep)
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
	var v any
	switch rep.Kind {
	case KindAttestation:
		var c AttestationContent
		if err := json.Unmarshal(rep.Content, &c); err != nil {
			return nil, "", fmt.Errorf("report: decode attestation content: %w", err)
		}
		v = c
	default:
		var c ExecutiveContent
		if err := json.Unmarshal(rep.Content, &c); err != nil {
			return nil, "", fmt.Errorf("report: decode executive content: %w", err)
		}
		v = c
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

// attestationRollup is the bounded aggregate the attestation PDF renders:
// pass/fail/total counts (and a sampled top-failing list) computed from the
// frozen scans' scan_results, never the per-(host, rule) rows themselves.
type attestationRollup struct {
	TotalChecks   int
	Pass          int
	Fail          int
	Skipped       int
	Errored       int
	CompliancePct *int
	TopFailing    []TopFailingRule
}

// exportAttestationPDF returns the cached attestation PDF face if present,
// else computes the bounded rollup from the frozen scans (aggregate
// queries scoped by the snapshot's framework lens), renders the one-page
// cover via renderAttestationPDF, caches it in report_faces, and returns
// it. The rollup is O(1) in fleet size (aggregates + a small top-N), so
// the PDF stays bounded regardless of host/rule count.
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
	rollup, err := s.computeAttestationRollup(ctx, c)
	if err != nil {
		return nil, "", err
	}
	pdfBytes, err := renderAttestationPDF(rep, c, rollup)
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

// computeAttestationRollup runs two aggregate queries over the frozen
// scans (counts by status, and the top failing rules by distinct failing
// host), applying the snapshot's framework lens. Compliance is passing /
// (passing + failing), rounded half up, nil when nothing was evaluated.
func (s *Service) computeAttestationRollup(ctx context.Context, c AttestationContent) (attestationRollup, error) {
	scanIDs := make([]uuid.UUID, len(c.Attested))
	for i, a := range c.Attested {
		scanIDs[i] = a.ScanID
	}

	var r attestationRollup
	countQ := `
		SELECT count(*),
		       count(*) FILTER (WHERE status = 'pass'),
		       count(*) FILTER (WHERE status = 'fail'),
		       count(*) FILTER (WHERE status = 'skipped'),
		       count(*) FILTER (WHERE status = 'error')
		  FROM scan_results sr
		 WHERE sr.scan_id = ANY($1)`
	countArgs := []any{scanIDs}
	if c.Framework != "" {
		countQ += " AND sr.framework_refs ? $2"
		countArgs = append(countArgs, c.Framework)
	}
	if err := s.pool.QueryRow(ctx, countQ, countArgs...).
		Scan(&r.TotalChecks, &r.Pass, &r.Fail, &r.Skipped, &r.Errored); err != nil {
		return attestationRollup{}, fmt.Errorf("report: attestation rollup counts: %w", err)
	}
	if evaluated := r.Pass + r.Fail; evaluated > 0 {
		pct := int((float64(r.Pass)/float64(evaluated))*100 + 0.5)
		r.CompliancePct = &pct
	}

	topQ := `
		SELECT sr.rule_id, count(DISTINCT sr.host_id)
		  FROM scan_results sr
		 WHERE sr.scan_id = ANY($1) AND sr.status = 'fail'`
	topArgs := []any{scanIDs}
	if c.Framework != "" {
		topQ += " AND sr.framework_refs ? $2"
		topArgs = append(topArgs, c.Framework)
	}
	topQ += " GROUP BY sr.rule_id ORDER BY count(DISTINCT sr.host_id) DESC, sr.rule_id LIMIT 10"
	rows, err := s.pool.Query(ctx, topQ, topArgs...)
	if err != nil {
		return attestationRollup{}, fmt.Errorf("report: attestation rollup top-failing: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t TopFailingRule
		if err := rows.Scan(&t.RuleID, &t.FailingHostCount); err != nil {
			return attestationRollup{}, fmt.Errorf("report: attestation rollup scan: %w", err)
		}
		r.TopFailing = append(r.TopFailing, t)
	}
	if err := rows.Err(); err != nil {
		return attestationRollup{}, fmt.Errorf("report: attestation rollup iterate: %w", err)
	}
	return r, nil
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
