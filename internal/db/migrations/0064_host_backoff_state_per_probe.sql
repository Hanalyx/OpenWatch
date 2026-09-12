-- +goose Up
-- One backoff row per host PER PROBE, not one per host.
--
-- host_backoff_state was created with `host_id UUID PRIMARY KEY` and a
-- probe_type column constrained to ('scan','intel'). The column says the table
-- tracks two independent probes. The key says a host may have exactly one row.
-- Both cannot be true, and the code built on top of the column has been losing
-- writes ever since.
--
-- What the single key does today:
--
--   * The intelligence scheduler UPSERTs with `ON CONFLICT (host_id) DO UPDATE
--     ... WHERE host_backoff_state.probe_type = 'intel'`. When a scan row
--     already exists the conflict fires, the WHERE excludes the row, and the
--     update is skipped. The intelligence failure is silently discarded and no
--     intelligence backoff is ever recorded for that host.
--
--   * The scan writer UPSERTs with `ON CONFLICT (host_id) DO UPDATE` and no
--     probe_type guard. When an intel row already exists the scan failure
--     overwrites its counters while LEAVING probe_type = 'intel', producing a
--     row labeled intelligence that carries scan state. Nothing detects it.
--
--   * Scan success resets `WHERE host_id = $1` with no probe_type, so a
--     successful scan clears an intelligence suppression it knows nothing
--     about.
--
-- The composite key ends all three. Each probe gets its own row, every writer
-- addresses its own row by name, and neither can reach the other's.
--
-- Existing rows keep the probe_type they already carry. The column is NOT NULL
-- with DEFAULT 'scan', so every row already has a value, and rows written by
-- the scan path are already 'scan'. Relabeling a stored 'intel' row as 'scan'
-- would invent a scan suppression that no scan failure produced, which is the
-- opposite of preserving them.
--
-- Duplicates cannot exist yet: the old primary key made them impossible. So
-- the key swap needs no deduplication pass.
--
-- CP bugs/OW-032.

ALTER TABLE host_backoff_state
  DROP CONSTRAINT host_backoff_state_pkey;

ALTER TABLE host_backoff_state
  ADD CONSTRAINT host_backoff_state_pkey PRIMARY KEY (host_id, probe_type);

-- +goose Down
-- Reverting needs one row per host again. Keep the scan row, which is the one
-- the scheduler and liveness read, and drop any intelligence row that would
-- collide with it.
DELETE FROM host_backoff_state b
 WHERE b.probe_type <> 'scan'
   AND EXISTS (SELECT 1 FROM host_backoff_state s
                WHERE s.host_id = b.host_id AND s.probe_type = 'scan');

ALTER TABLE host_backoff_state
  DROP CONSTRAINT host_backoff_state_pkey;

ALTER TABLE host_backoff_state
  ADD CONSTRAINT host_backoff_state_pkey PRIMARY KEY (host_id);
