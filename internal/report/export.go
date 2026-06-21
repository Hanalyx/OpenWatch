package report

// Report faces: downloadable renderings of a snapshot. The JSON face is
// the canonical snapshot content served verbatim; the PDF face is the
// bounded one-page executive document (pdf.go), rendered lazily on first
// request and cached in report_faces keyed by (snapshot_id, face) so a
// repeat download re-streams the stored bytes instead of re-rendering.
//
// Spec: api-reports v1.4.0.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrInvalidFace is returned by Export for an unknown face. Handlers map
// it to 400.
var ErrInvalidFace = errors.New("report: invalid face")

// Face identifiers and their media types.
const (
	FaceJSON = "json"
	FacePDF  = "pdf"
)

// Export returns a rendered face of the report (its bytes + media type),
// or ErrNotFound for an unknown id / ErrInvalidFace for an unknown face.
// The JSON face is the canonical content; the PDF face is rendered and
// cached in report_faces on first request.
func (s *Service) Export(ctx context.Context, id uuid.UUID, face string) ([]byte, string, error) {
	rep, err := s.Get(ctx, id)
	if err != nil {
		return nil, "", err // ErrNotFound propagates
	}
	switch face {
	case FaceJSON:
		// The canonical snapshot content IS the json face; no caching.
		return rep.Content, "application/json", nil
	case FacePDF:
		return s.exportPDF(ctx, rep)
	default:
		return nil, "", ErrInvalidFace
	}
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
// "openwatch-executive-all-hosts-2026-06-21.pdf".
func ExportFilename(rep Report, face string) string {
	ext := face
	slug := slugify(rep.ScopeLabel)
	return fmt.Sprintf("openwatch-executive-%s-%s.%s", slug, rep.DataAsOf.Format("2006-01-02"), ext)
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
