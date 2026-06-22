package report

// Fleet OSCAL SAR face: the attestation snapshot rendered as a single
// OSCAL 1.0.6 assessment-results document. Unlike Kensa's per-scan
// exporter (kensapkg.ExportOSCALScan), which inlines each scan's evidence
// as base64 back-matter, the fleet SAR carries one observation + finding
// per (host, rule) with the evidence REFERENCED by sha256 in back-matter
// (an rlink with a SHA-256 hash) - the bytes stay in scan_evidence. That
// hash-referencing shape is what keeps a 100-host x 500-rule attestation
// from becoming the 1000-page problem in OSCAL form (reports_design.md
// Phase B decision 2).
//
// The document is fully deterministic: every uuid is a v5 (SHA-1) name
// UUID derived from stable inputs (the snapshot id, host id, rule id, or
// evidence hash) and every timestamp comes from the frozen snapshot, so a
// re-render produces identical bytes and the report_faces cache is stable
// (the same property the PDF and CSV faces rely on).
//
// Spec: api-reports.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FaceOSCALSAR is the fleet OSCAL assessment-results face (attestation-only).
const FaceOSCALSAR = "oscal_sar"

// oscalNamespace qualifies OpenWatch-specific OSCAL props.
const oscalNamespace = "https://hanalyx.com/openwatch/ns/oscal/v1/"

// oscalNS is the UUID namespace OpenWatch derives its deterministic v5
// assessment UUIDs under (a fixed random base, so the derived ids are
// stable across processes and distinct from Kensa's URL-namespace ids).
var oscalNS = uuid.MustParse("8b9d2f7a-1c34-4e56-9a7b-0f1e2d3c4b5a")

// --- OSCAL 1.0.6 assessment-results shapes (the subset the fleet SAR
// emits; field names + nesting mirror Kensa's per-scan emitter so the
// fleet document is shape-consistent with a single-scan export). ---

type oscalDoc struct {
	AssessmentResults oscalARBody `json:"assessment-results"`
}

type oscalARBody struct {
	UUID       string           `json:"uuid"`
	Metadata   oscalMetadata    `json:"metadata"`
	ImportAP   oscalImportAP    `json:"import-ap"`
	Results    []oscalResult    `json:"results"`
	BackMatter *oscalBackMatter `json:"back-matter,omitempty"`
}

type oscalMetadata struct {
	Title        string      `json:"title"`
	LastModified string      `json:"last-modified"`
	Version      string      `json:"version"`
	OSCALVersion string      `json:"oscal-version"`
	Props        []oscalProp `json:"props,omitempty"`
}

type oscalImportAP struct {
	Href string `json:"href"`
}

type oscalResult struct {
	UUID             string                `json:"uuid"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Start            string                `json:"start"`
	End              string                `json:"end"`
	ReviewedControls oscalReviewedControls `json:"reviewed-controls"`
	Findings         []oscalFinding        `json:"findings"`
	Observations     []oscalObservation    `json:"observations"`
}

type oscalReviewedControls struct {
	ControlSelections []oscalControlSelection `json:"control-selections"`
}

type oscalControlSelection struct {
	IncludeAll      *oscalIncludeAll  `json:"include-all,omitempty"`
	IncludeControls []oscalControlRef `json:"include-controls,omitempty"`
}

type oscalIncludeAll struct{}

type oscalControlRef struct {
	ControlID string `json:"control-id"`
}

type oscalFinding struct {
	UUID                string                    `json:"uuid"`
	Title               string                    `json:"title"`
	Description         string                    `json:"description"`
	Target              oscalFindingTarget        `json:"target"`
	RelatedObservations []oscalRelatedObservation `json:"related-observations"`
}

type oscalFindingTarget struct {
	Type     string            `json:"type"`
	TargetID string            `json:"target-id"`
	Status   oscalTargetStatus `json:"status"`
}

type oscalTargetStatus struct {
	State string `json:"state"`
}

type oscalRelatedObservation struct {
	ObservationUUID string `json:"observation-uuid"`
}

type oscalObservation struct {
	UUID             string                  `json:"uuid"`
	Description      string                  `json:"description"`
	Methods          []string                `json:"methods"`
	Subjects         []oscalSubject          `json:"subjects,omitempty"`
	Collected        string                  `json:"collected"`
	RelevantEvidence []oscalRelevantEvidence `json:"relevant-evidence,omitempty"`
}

type oscalSubject struct {
	SubjectUUID string `json:"subject-uuid"`
	Type        string `json:"type"`
}

type oscalRelevantEvidence struct {
	Description string      `json:"description"`
	Href        string      `json:"href,omitempty"`
	Props       []oscalProp `json:"props,omitempty"`
}

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	NS    string `json:"ns,omitempty"`
}

type oscalBackMatter struct {
	Resources []oscalResource `json:"resources"`
}

type oscalResource struct {
	UUID   string       `json:"uuid"`
	Title  string       `json:"title,omitempty"`
	RLinks []oscalRLink `json:"rlinks,omitempty"`
}

type oscalRLink struct {
	Href      string      `json:"href"`
	MediaType string      `json:"media-type,omitempty"`
	Hashes    []oscalHash `json:"hashes,omitempty"`
}

type oscalHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// exportFleetOSCALSAR returns the cached OSCAL SAR face if present, else
// assembles one from the IMMUTABLE scan_results of the scans the snapshot
// froze (point-in-time), scoped by the snapshot's framework lens, caches
// it in report_faces, and returns it.
func (s *Service) exportFleetOSCALSAR(ctx context.Context, rep Report) ([]byte, string, error) {
	const mediaType = "application/json"

	var cached []byte
	err := s.pool.QueryRow(ctx,
		`SELECT content FROM report_faces WHERE snapshot_id = $1 AND face = $2 AND status = 'ready'`,
		rep.ID, FaceOSCALSAR).Scan(&cached)
	if err == nil && len(cached) > 0 {
		return cached, mediaType, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("report: oscal face lookup: %w", err)
	}

	var c AttestationContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		return nil, "", fmt.Errorf("report: decode attestation content: %w", err)
	}
	scanIDs := make([]uuid.UUID, len(c.Attested))
	for i, a := range c.Attested {
		scanIDs[i] = a.ScanID
	}

	doc, err := s.assembleFleetSAR(ctx, rep, c, scanIDs)
	if err != nil {
		return nil, "", err
	}
	sarBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, "", fmt.Errorf("report: marshal oscal sar: %w", err)
	}

	sum := sha256.Sum256(sarBytes)
	blobSHA := hex.EncodeToString(sum[:])
	_, err = s.pool.Exec(ctx, `
		INSERT INTO report_faces (snapshot_id, face, media_type, content, size_bytes, blob_sha256, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ready')
		ON CONFLICT (snapshot_id, face)
		DO UPDATE SET content = EXCLUDED.content, media_type = EXCLUDED.media_type,
		              size_bytes = EXCLUDED.size_bytes, blob_sha256 = EXCLUDED.blob_sha256,
		              status = 'ready'`,
		rep.ID, FaceOSCALSAR, mediaType, sarBytes, len(sarBytes), blobSHA)
	if err != nil {
		// A cache write failure should not fail the download.
		return sarBytes, mediaType, nil
	}
	return sarBytes, mediaType, nil
}

// assembleFleetSAR builds the single assessment-results document: one
// observation + finding per (host, rule), control selections aggregated
// across the in-scope framework refs, and evidence referenced by sha256
// in back-matter. The row set is bounded by maxAttestationRows (the same
// cap the CSV face uses); a truncated document records the cap as a
// metadata prop so a partial bundle is never mistaken for complete.
func (s *Service) assembleFleetSAR(ctx context.Context, rep Report, c AttestationContent, scanIDs []uuid.UUID) (oscalDoc, error) {
	q := `
		SELECT sr.host_id, COALESCE(h.hostname, ''), sr.rule_id, sr.status,
		       sr.framework_refs::text, COALESCE(encode(sr.evidence_hash, 'hex'), ''),
		       run.finished_at
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
		return oscalDoc{}, fmt.Errorf("report: oscal rows: %w", err)
	}
	defer rows.Close()

	findings := make([]oscalFinding, 0)
	observations := make([]oscalObservation, 0)
	controlSet := map[string]struct{}{}
	resourceByHash := map[string]oscalResource{}
	n := 0
	truncated := false
	for rows.Next() {
		if n >= maxAttestationRows {
			truncated = true
			break
		}
		var hostID uuid.UUID
		var hostname, ruleID, status, fwJSON, evHex string
		var finishedAt time.Time
		if err := rows.Scan(&hostID, &hostname, &ruleID, &status, &fwJSON, &evHex, &finishedAt); err != nil {
			return oscalDoc{}, fmt.Errorf("report: oscal row scan: %w", err)
		}

		obsUUID := derivedUUID("obs", rep.ID, hostID, ruleID)
		evHref := ""
		if evHex != "" {
			res := evidenceResource(evHex)
			resourceByHash[evHex] = res
			evHref = "#" + res.UUID
		}
		obs := oscalObservation{
			UUID:        obsUUID,
			Description: fmt.Sprintf("Compliance check %s on host %s: %s", ruleID, hostname, status),
			Methods:     []string{"TEST"},
			Subjects: []oscalSubject{
				{SubjectUUID: hostSubjectUUID(hostID), Type: "inventory-item"},
			},
			Collected: finishedAt.UTC().Format(time.RFC3339),
		}
		if evHref != "" {
			obs.RelevantEvidence = []oscalRelevantEvidence{{
				Description: "Scan evidence, referenced by content hash",
				Href:        evHref,
				Props:       []oscalProp{{Name: "sha256", Value: evHex, NS: oscalNamespace}},
			}}
		}
		observations = append(observations, obs)

		findings = append(findings, oscalFinding{
			UUID:        derivedUUID("finding", rep.ID, hostID, ruleID),
			Title:       ruleID,
			Description: fmt.Sprintf("Host %s: %s", hostname, status),
			Target: oscalFindingTarget{
				Type:     "objective-id",
				TargetID: ruleID,
				Status:   oscalTargetStatus{State: complianceState(status)},
			},
			RelatedObservations: []oscalRelatedObservation{{ObservationUUID: obsUUID}},
		})

		for _, ctrl := range controlIDsFromRefs(fwJSON, c.Framework) {
			controlSet[ctrl] = struct{}{}
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return oscalDoc{}, fmt.Errorf("report: oscal iterate: %w", err)
	}

	lastMod := rep.DataAsOf.UTC().Format(time.RFC3339)
	meta := oscalMetadata{
		Title:        "OpenWatch Fleet Attestation: " + rep.ScopeLabel,
		LastModified: lastMod,
		Version:      "1.0.0",
		OSCALVersion: "1.0.6",
	}
	if truncated {
		meta.Props = append(meta.Props, oscalProp{
			Name:  "truncated",
			Value: fmt.Sprintf("findings capped at %d; document is not complete", maxAttestationRows),
			NS:    oscalNamespace,
		})
	}

	result := oscalResult{
		UUID:        derivedUUID("result", rep.ID, uuid.Nil, ""),
		Title:       "Fleet Framework Attestation",
		Description: "Point-in-time compliance attestation over the latest completed scan per in-scope host.",
		Start:       lastMod,
		End:         lastMod,
		ReviewedControls: oscalReviewedControls{
			ControlSelections: []oscalControlSelection{controlSelection(controlSet)},
		},
		Findings:     findings,
		Observations: observations,
	}

	doc := oscalDoc{AssessmentResults: oscalARBody{
		UUID:     derivedUUID("doc", rep.ID, uuid.Nil, ""),
		Metadata: meta,
		ImportAP: oscalImportAP{Href: "#"},
		Results:  []oscalResult{result},
	}}
	if len(resourceByHash) > 0 {
		doc.AssessmentResults.BackMatter = &oscalBackMatter{Resources: sortedResources(resourceByHash)}
	}
	return doc, nil
}

// controlSelection turns the aggregated control-id set into one
// include-controls selection (sorted for determinism); an empty set means
// no framework refs were present, rendered as include-all.
func controlSelection(set map[string]struct{}) oscalControlSelection {
	if len(set) == 0 {
		return oscalControlSelection{IncludeAll: &oscalIncludeAll{}}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	refs := make([]oscalControlRef, len(ids))
	for i, id := range ids {
		refs[i] = oscalControlRef{ControlID: id}
	}
	return oscalControlSelection{IncludeControls: refs}
}

// controlIDsFromRefs decodes a scan_results.framework_refs JSON object
// ({framework_id: [control_ids]}) into OSCAL control-id tokens. When lens
// is non-empty only that framework's controls are emitted; otherwise every
// framework's controls are. Malformed JSON yields no controls (the row
// still contributes its finding).
func controlIDsFromRefs(fwJSON, lens string) []string {
	if fwJSON == "" {
		return nil
	}
	var refs map[string][]string
	if err := json.Unmarshal([]byte(fwJSON), &refs); err != nil {
		return nil
	}
	var out []string
	for fw, controls := range refs {
		if lens != "" && fw != lens {
			continue
		}
		for _, ctrl := range controls {
			out = append(out, oscalControlID(fw, ctrl))
		}
	}
	return out
}

// evidenceResource builds the back-matter resource for an evidence blob,
// referencing it by sha256 (an rlink with a SHA-256 hash) rather than
// inlining the bytes. The resource uuid is derived from the hash so the
// same evidence yields the same resource across the document (dedup) and
// across re-renders (stable cache).
func evidenceResource(evHex string) oscalResource {
	return oscalResource{
		UUID:  uuid.NewSHA1(oscalNS, []byte("evidence:"+evHex)).String(),
		Title: "Scan evidence sha256:" + evHex,
		RLinks: []oscalRLink{{
			Href:      "urn:openwatch:evidence:sha256:" + evHex,
			MediaType: "application/json",
			Hashes:    []oscalHash{{Algorithm: "SHA-256", Value: evHex}},
		}},
	}
}

// sortedResources returns the back-matter resources sorted by uuid so the
// assembled document is deterministic regardless of map iteration order.
func sortedResources(byHash map[string]oscalResource) []oscalResource {
	out := make([]oscalResource, 0, len(byHash))
	for _, r := range byHash {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UUID < out[j].UUID })
	return out
}

// derivedUUID builds a deterministic v5 UUID from a kind tag plus the
// snapshot id, host id, and rule id, so every assessment id is stable
// across re-renders (the cache invariant) while distinct per element.
func derivedUUID(kind string, snapshotID, hostID uuid.UUID, ruleID string) string {
	name := kind + ":" + snapshotID.String() + ":" + hostID.String() + ":" + ruleID
	return uuid.NewSHA1(oscalNS, []byte(name)).String()
}

// hostSubjectUUID derives a stable subject UUID for a host id (v5), so a
// host's inventory-item subject is consistent across observations and
// re-renders.
func hostSubjectUUID(hostID uuid.UUID) string {
	return uuid.NewSHA1(oscalNS, []byte("host:"+hostID.String())).String()
}

// complianceState maps a scan_results.status to an OSCAL finding state:
// "satisfied" only for a pass; "not-satisfied" for fail/skipped/error so a
// non-pass never reads as compliant.
func complianceState(status string) string {
	if status == "pass" {
		return "satisfied"
	}
	return "not-satisfied"
}

// oscalControlID renders a (framework, control) reference as a valid OSCAL
// control-id token. OSCAL control-id must match
// `^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$`; native ids like CIS "3.3.1" start
// with a digit, so the framework id (which starts with a letter) is
// prefixed - which also disambiguates which framework a control belongs to
// in one include-controls list. (Mirrors Kensa's per-scan emitter.)
func oscalControlID(framework, control string) string {
	raw := control
	if framework != "" {
		raw = framework + "-" + control
	}
	return sanitizeOSCALToken(raw)
}

// sanitizeOSCALToken coerces s into a valid OSCAL token: legal runes pass
// through; '(' becomes '.' and ')' is dropped (so NIST "AU-5(2)" reads as
// the OSCAL-idiomatic "AU-5.2"); any other illegal rune becomes '_'. A
// result that is empty or does not start with a letter/underscore is
// prefixed with '_' so the first-char constraint holds.
func sanitizeOSCALToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		case r == '(':
			b.WriteRune('.')
		case r == ')':
			// dropped - the '(' already became the dot separator
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "_"
	}
	if first := []rune(out)[0]; !unicode.IsLetter(first) && first != '_' {
		out = "_" + out
	}
	return out
}
