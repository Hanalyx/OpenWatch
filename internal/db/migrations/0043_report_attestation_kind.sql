-- 0043_report_attestation_kind.sql
--
-- Reports B1: admit the 'attestation' kind. The report_snapshots.kind
-- CHECK (still named reports_kind_check from before the 0042 table rename)
-- previously admitted only 'executive'; the Framework Attestation kind
-- (auditor/GRC bulk faces: CSV now, OSCAL SAR next) extends it.
--
-- Spec: api-reports v1.7.0.

-- +goose Up
ALTER TABLE report_snapshots DROP CONSTRAINT IF EXISTS reports_kind_check;
ALTER TABLE report_snapshots
    ADD CONSTRAINT report_snapshots_kind_check
    CHECK (kind IN ('executive', 'attestation'));

-- +goose Down
ALTER TABLE report_snapshots DROP CONSTRAINT IF EXISTS report_snapshots_kind_check;
ALTER TABLE report_snapshots
    ADD CONSTRAINT reports_kind_check
    CHECK (kind IN ('executive'));
