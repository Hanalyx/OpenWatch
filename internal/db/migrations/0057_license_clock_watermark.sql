-- +goose Up
-- Persist the clock-rollback watermark so it survives a restart.
--
-- License verification is offline: Ed25519, public key embedded in the binary,
-- nothing phones home. Revocation is therefore impossible and expiry is the
-- only control left once a license is issued. The one way to run past expiry is
-- to wind the machine clock back, and the adversary is a customer with root on
-- their own hardware.
--
-- Until now the watermark lived only in the in-process atomic State, and both
-- boot paths loaded with a zero VerifyOptions (cmd/openwatch/main.go,
-- cmd/openwatch/worker.go). Zero skips the check, so the guard only ever fired
-- inside one process lifetime. Reboot with a wound-back clock, which is the
-- practical attack, was undetectable. Spec system-license-validation C-07
-- already required this row; the code did not have it.
--
-- One row, enforced by the singleton primary key. This is deployment state, not
-- license state: it records the highest wall-clock time this deployment has
-- observed, independent of which license is installed, and it must survive a
-- license being replaced or removed. That is why it is not a column on the
-- licenses table that OW-005 item 5 will add.
CREATE TABLE license_clock_watermark (
    -- Singleton guard. One deployment, one watermark.
    id              BOOLEAN     PRIMARY KEY DEFAULT TRUE,
    observed_at     TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT license_clock_watermark_singleton CHECK (id)
);

COMMENT ON TABLE license_clock_watermark IS
    'Highest wall-clock time this deployment has observed. Monotonic: a write must never move observed_at backwards. See specs/system/license-validation.spec.yaml C-07 and C-13.';

-- +goose Down
DROP TABLE IF EXISTS license_clock_watermark;
