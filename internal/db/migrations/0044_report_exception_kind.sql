-- 0044_report_exception_kind.sql
--
-- Reports C1: admit the 'exception' kind. The report_snapshots.kind CHECK
-- previously admitted 'executive' and 'attestation' (0043); the Exception
-- Register kind (Compliance/GRC read-model over compliance_exceptions:
-- CSV register + bounded PDF summary) extends it.
--
-- Spec: api-reports v1.12.0.

-- +goose Up
ALTER TABLE report_snapshots DROP CONSTRAINT IF EXISTS report_snapshots_kind_check;
ALTER TABLE report_snapshots
    ADD CONSTRAINT report_snapshots_kind_check
    CHECK (kind IN ('executive', 'attestation', 'exception'));

-- +goose Down
ALTER TABLE report_snapshots DROP CONSTRAINT IF EXISTS report_snapshots_kind_check;
ALTER TABLE report_snapshots
    ADD CONSTRAINT report_snapshots_kind_check
    CHECK (kind IN ('executive', 'attestation'));
