-- 0042_report_snapshots.sql
--
-- Reports A3a (snapshot/faces model). Promotes the reports table to the
-- content-addressed, signable "snapshot" the reports design is built on,
-- and adds the report_faces table that later rendered projections hang
-- off (PDF in A3b, CSV/OSCAL later).
--
-- WHY a rename rather than a new table + data copy: the existing reports
-- rows ARE snapshots already (immutable, point-in-time, scope + content),
-- so RENAME preserves them and the 0041 scope column with no copy and no
-- downtime.
--
-- content_sha256 is the snapshot's content address: the hex SHA-256 of the
-- canonical (service-marshaled) content. It is the stable identity a later
-- Ed25519 signature (A4) signs over, so identical content yields an
-- identical hash. signature + signing_key_id are reserved now (nullable,
-- unset until A4) so signing is a pure write, not another migration.
-- NOTE for A4: a verifier must recompute this hash over the SAME canonical
-- bytes the service hashed, NOT over the jsonb column re-serialized by
-- Postgres (jsonb normalizes whitespace/key order on store). Settle the
-- canonical-bytes contract when signing lands. Existing rows are
-- backfilled here with Postgres sha256(content::text) as a deterministic
-- stand-in; they predate signing and are never signed retroactively.
--
-- report_faces is created here but gets its first writer in A3b (the PDF
-- face). The executive JSON is served directly from the snapshot content
-- (the canonical "json face"), so it is NOT duplicated into report_faces.
--
-- Spec: api-reports v1.3.0.

-- +goose Up
ALTER TABLE reports RENAME TO report_snapshots;
ALTER INDEX reports_created_at RENAME TO report_snapshots_created_at;

ALTER TABLE report_snapshots ADD COLUMN content_sha256 TEXT;
UPDATE report_snapshots
   SET content_sha256 = encode(sha256(convert_to(content::text, 'UTF8')), 'hex')
 WHERE content_sha256 IS NULL;
ALTER TABLE report_snapshots ALTER COLUMN content_sha256 SET NOT NULL;

ALTER TABLE report_snapshots ADD COLUMN signature      BYTEA;
ALTER TABLE report_snapshots ADD COLUMN signing_key_id TEXT;

CREATE TABLE report_faces (
    snapshot_id  UUID NOT NULL REFERENCES report_snapshots(id) ON DELETE CASCADE,
    face         TEXT NOT NULL,            -- json | pdf | csv | oscal_sar | oscal_poam
    media_type   TEXT NOT NULL,
    content      BYTEA,                    -- inline rendered bytes (small faces)
    size_bytes   BIGINT NOT NULL DEFAULT 0,
    blob_sha256  TEXT,                     -- content address of the rendered face
    status       TEXT NOT NULL DEFAULT 'ready'
                 CHECK (status IN ('pending', 'ready', 'failed')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (snapshot_id, face)
);

-- +goose Down
DROP TABLE IF EXISTS report_faces;
ALTER TABLE report_snapshots DROP COLUMN IF EXISTS signing_key_id;
ALTER TABLE report_snapshots DROP COLUMN IF EXISTS signature;
ALTER TABLE report_snapshots DROP COLUMN IF EXISTS content_sha256;
ALTER INDEX report_snapshots_created_at RENAME TO reports_created_at;
ALTER TABLE report_snapshots RENAME TO reports;
