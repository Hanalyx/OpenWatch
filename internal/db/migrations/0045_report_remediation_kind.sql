-- 0045_report_remediation_kind.sql
--
-- Reports C2: admit the 'remediation' kind. The report_snapshots.kind CHECK
-- previously admitted 'executive', 'attestation', 'exception' (0044); the
-- Remediation Activity kind (Operations read-model of remediation
-- execute/rollback events over a period: CSV log + bounded PDF summary)
-- extends it.
--
-- Spec: api-reports v1.13.0.

-- +goose Up
ALTER TABLE report_snapshots DROP CONSTRAINT IF EXISTS report_snapshots_kind_check;
ALTER TABLE report_snapshots
    ADD CONSTRAINT report_snapshots_kind_check
    CHECK (kind IN ('executive', 'attestation', 'exception', 'remediation'));

-- +goose Down
ALTER TABLE report_snapshots DROP CONSTRAINT IF EXISTS report_snapshots_kind_check;
ALTER TABLE report_snapshots
    ADD CONSTRAINT report_snapshots_kind_check
    CHECK (kind IN ('executive', 'attestation', 'exception'));
