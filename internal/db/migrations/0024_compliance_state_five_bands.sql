-- 0024_compliance_state_five_bands.sql
--
-- Scan plan Phase 4, decision #5 (RESOLVED 2026-06-12): the compliance
-- state ladder gains a fifth score band, mostly_compliant (70-89), to
-- match the prototype's five bands:
--
--   critical <20 | non_compliant 20-49 | partial 50-69 |
--   mostly_compliant 70-89 | compliant >=90   (+ unknown, never scanned)
--
-- Also seeds host_compliance_schedule for every existing live host so
-- the adaptive scheduler (booted for the first time alongside this
-- migration) finds them. next_scheduled_scan defaults to now(): every
-- unseeded host is immediately due, and the dispatcher's rate limit
-- paces the initial sweep. Host creation seeds new rows from now on.
--
-- Spec: system-scheduler v3.0.0.

-- +goose Up
ALTER TABLE host_compliance_schedule
  DROP CONSTRAINT host_compliance_schedule_compliance_state_check;

ALTER TABLE host_compliance_schedule
  ADD CONSTRAINT host_compliance_schedule_compliance_state_check
  CHECK (compliance_state IN
    ('compliant','mostly_compliant','partial','non_compliant','critical','unknown'));

INSERT INTO host_compliance_schedule (host_id)
SELECT id FROM hosts WHERE deleted_at IS NULL
ON CONFLICT (host_id) DO NOTHING;

-- +goose Down
ALTER TABLE host_compliance_schedule
  DROP CONSTRAINT host_compliance_schedule_compliance_state_check;

UPDATE host_compliance_schedule
   SET compliance_state = 'compliant'
 WHERE compliance_state = 'mostly_compliant';

ALTER TABLE host_compliance_schedule
  ADD CONSTRAINT host_compliance_schedule_compliance_state_check
  CHECK (compliance_state IN
    ('compliant','partial','non_compliant','critical','unknown'));
