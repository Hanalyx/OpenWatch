package scanresult

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Writer persists PersistBatch values to scan_results + scan_evidence.
// Constructed once at boot via NewWriter; held for the process lifetime.
//
// It does NOT emit audit events: the transaction log already emits
// finding.persisted for every state change in the same scan, and a
// second emission here would double-count. The durable store is a record,
// not an event source.
type Writer struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

// NewWriter wires the writer to the connection pool.
func NewWriter(pool *pgxpool.Pool) *Writer {
	return &Writer{pool: pool, clock: time.Now}
}

// Persist records every result in batch to scan_results, deduping
// evidence into scan_evidence by content hash. Atomic per scan.
//
// Steps:
//  1. Pre-flight validate (status enum + 256 KiB cap). Reject the whole
//     batch before any INSERT — no partial writes.
//  2. Idempotency gate: if any scan_results row already exists with this
//     scan_id, the scan was already persisted — no-op.
//  3. BEGIN tx.
//  4. Per result: hash the RAW evidence bytes; when non-empty, INSERT the
//     blob ON CONFLICT (evidence_hash) DO NOTHING (dedup, preserving the
//     original first_seen_at); then INSERT the scan_results row
//     ON CONFLICT (scan_id, rule_id) DO NOTHING, referencing the hash
//     (or NULL when the check captured no evidence).
//  5. COMMIT.
//
// Idempotency mirrors transactionlog.Apply so the two writers stay
// consistent under the worker's transient-retry path: a scan that
// half-persisted (impossible inside one tx, but cheap to guard) self-heals
// on retry because both the gate and the per-row ON CONFLICT are no-ops.
func (w *Writer) Persist(ctx context.Context, batch PersistBatch) error {
	// Step 1: pre-flight validation (atomic batch — reject before INSERT).
	for _, r := range batch.Results {
		if err := validateResult(r); err != nil {
			return fmt.Errorf("scanresult: validate result rule=%s: %w", r.RuleID, err)
		}
	}

	// Step 2: idempotency gate on scan_id.
	var exists bool
	if err := w.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM scan_results WHERE scan_id = $1)`,
		batch.ScanID).Scan(&exists); err != nil {
		return fmt.Errorf("scanresult: idempotency check: %w", err)
	}
	if exists {
		return nil // already persisted; no-op.
	}

	now := w.clock()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("scanresult: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit.

	for _, r := range batch.Results {
		// Hash the RAW evidence bytes exactly as produced by the kensa
		// executor, BEFORE any JSONB normalization. Postgres re-serializes
		// JSONB (key reorder, whitespace strip), so a hash taken after the
		// cast would never match a Go-side hash and dedup would break.
		var hash []byte
		if len(r.Evidence) > 0 {
			sum := sha256.Sum256(r.Evidence)
			hash = sum[:]
			if _, err = tx.Exec(ctx, `
				INSERT INTO scan_evidence (evidence_hash, evidence, byte_size)
				VALUES ($1, $2::jsonb, $3)
				ON CONFLICT (evidence_hash) DO NOTHING`,
				hash, r.Evidence, len(r.Evidence),
			); err != nil {
				return fmt.Errorf("scanresult: insert evidence rule=%s: %w", r.RuleID, err)
			}
		}

		if _, err = tx.Exec(ctx, `
			INSERT INTO scan_results
				(scan_id, host_id, rule_id, status, severity,
				 evidence_hash, framework_refs, skip_reason, recorded_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
			ON CONFLICT (scan_id, rule_id) DO NOTHING`,
			batch.ScanID, batch.HostID, r.RuleID, string(r.Status),
			nullableString(r.Severity), nullableBytes(hash),
			frameworkRefsJSON(r.FrameworkRefs), nullableString(r.SkipReason), now,
		); err != nil {
			return fmt.Errorf("scanresult: insert result rule=%s: %w", r.RuleID, err)
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("scanresult: commit: %w", err)
	}
	return nil
}

// validateResult checks status validity and the evidence size cap. The
// cap is the shared transactionlog cap (see MaxEvidenceBytes); empty
// evidence is allowed (it maps to a NULL evidence_hash at insert time).
func validateResult(r Result) error {
	switch r.Status {
	case StatusPass, StatusFail, StatusSkipped, StatusError:
	default:
		return fmt.Errorf("%w: %q", ErrInvalidStatus, r.Status)
	}
	if len(r.Evidence) > MaxEvidenceBytes {
		return fmt.Errorf("%w: rule_id=%s size=%d > cap=%d",
			ErrEvidenceOversize, r.RuleID, len(r.Evidence), MaxEvidenceBytes)
	}
	return nil
}

// frameworkRefsJSON marshals the framework refs map, defaulting a nil map
// to an empty JSON object (matching the column default) rather than null.
func frameworkRefsJSON(refs map[string][]string) []byte {
	if len(refs) == 0 {
		return []byte("{}")
	}
	b, _ := json.Marshal(refs) // map[string][]string never fails to marshal.
	return b
}

// nullableString converts an empty string to nil (NULL in DB).
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableBytes converts an empty/zero hash to nil (NULL evidence_hash).
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
