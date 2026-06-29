-- 0037_remediation.sql
--
-- Remediation governance (scan plan Phase 7, remediation half). The free
-- (Apache 2.0 core) see-and-govern loop: an operator's intent to fix a failing
-- rule on a host, with a request -> approve | reject lifecycle, mirroring the
-- exception governance overlay (0026_compliance_exceptions).
--
-- FREE-PATH INVARIANT: the free service (Request/Approve/Reject + the
-- read-only ProjectLift) NEVER contacts a host and NEVER writes host_rule_state
-- or transactions. remediation_transactions (the per-step Kensa journal) is
-- written only by the OpenWatch+ licensed execute path; in the free build the
-- table exists but stays empty.
--
-- Lifecycle: pending_approval -> approved | rejected. The approved -> executed
-- -> rolled_back states are driven by the licensed execution track
-- (remediation_execution). Separation of duties (auth/permissions.yaml):
-- remediation:request is distinct from remediation:approve; remediation:execute
-- and remediation:rollback are dangerous and license-gated to
-- remediation_execution.
--
-- Spec: api-remediation v1.0.0. Plan: docs/engineering/remediation_core_plan.md.

-- +goose Up
CREATE TABLE remediation_requests (
    id              UUID PRIMARY KEY,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    scan_run_id     UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    status          TEXT NOT NULL DEFAULT 'pending_approval'
                    CHECK (status IN ('pending_approval','approved','rejected',
                                      'dry_run_complete','executing','executed',
                                      'rolled_back','failed')),
    requested_by    UUID NOT NULL REFERENCES users(id),
    reviewed_by     UUID REFERENCES users(id),
    review_note     TEXT,
    -- Remediation shape, captured at request time from the rule's Kensa
    -- metadata (best-effort; empty/false when unknown in the free path).
    mechanism       TEXT,
    reboot_required BOOLEAN NOT NULL DEFAULT false,
    transactional   BOOLEAN NOT NULL DEFAULT true,
    -- Projected per-framework score lift (percentage points) if the rule
    -- flips to pass; a NULL means that framework's data was unavailable.
    projected_cis   DOUBLE PRECISION,
    projected_stig  DOUBLE PRECISION,
    projected_nist  DOUBLE PRECISION,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most ONE open remediation request per host+rule, so a duplicate request
-- cannot stack while one is in flight. Terminal rows (rejected / executed /
-- rolled_back / failed) are historical and do not block a fresh request.
CREATE UNIQUE INDEX remediation_requests_one_open
    ON remediation_requests (host_id, rule_id)
    WHERE status IN ('pending_approval','approved','dry_run_complete','executing');

-- Per-host listing (Compliance tab annotation) and fleet queue scans by state.
CREATE INDEX remediation_requests_host   ON remediation_requests (host_id);
CREATE INDEX remediation_requests_status ON remediation_requests (status);

-- Per-step Kensa transaction journal (Capture/Apply/Validate/Commit). Written
-- only by the OpenWatch+ licensed execute path; the durable rollback point and
-- signed-evidence record. Empty in the free build.
CREATE TABLE remediation_transactions (
    id           UUID PRIMARY KEY,
    request_id   UUID NOT NULL REFERENCES remediation_requests(id) ON DELETE CASCADE,
    ordinal      INTEGER NOT NULL DEFAULT 0,
    rule_id      TEXT NOT NULL,
    kensa_txn_id TEXT,
    mechanism    TEXT,
    phase_result TEXT CHECK (phase_result IS NULL OR
                            phase_result IN ('committed','rolled_back','skipped')),
    pre_state    JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence     JSONB NOT NULL DEFAULT '{}'::jsonb,
    dry_run      BOOLEAN NOT NULL DEFAULT false,
    applied_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX remediation_transactions_request ON remediation_transactions (request_id, ordinal);

-- +goose Down
DROP TABLE IF EXISTS remediation_transactions;
DROP TABLE IF EXISTS remediation_requests;
