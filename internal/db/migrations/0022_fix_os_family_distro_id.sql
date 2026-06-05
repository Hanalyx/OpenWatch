-- system-host-discovery v1.3.0 AC-22 — hosts.os_family now stores the
-- distro ID (lower-cased) from /etc/os-release rather than the family
-- rollup. Pre-fix Discoveries persisted Ubuntu / Rocky / CentOS /
-- AlmaLinux all collapsed under "debian" or "rhel", which made the
-- list-page osDisplayLabel mapping render the wrong distribution name.
--
-- host_system_info.os_id was always persisted with the canonical
-- distro ID, so the fix is a one-shot UPDATE that copies it into
-- hosts.os_family + host_system_info.os_family whenever the two
-- disagree. Idempotent: re-runs are a no-op once the values match.

-- +goose Up
UPDATE hosts h
SET    os_family = lower(trim(hsi.os_id))
FROM   host_system_info hsi
WHERE  h.id = hsi.host_id
  AND  hsi.os_id IS NOT NULL
  AND  trim(hsi.os_id) <> ''
  AND  lower(trim(hsi.os_id)) <> COALESCE(h.os_family, '');

UPDATE host_system_info
SET    os_family = lower(trim(os_id))
WHERE  os_id IS NOT NULL
  AND  trim(os_id) <> ''
  AND  lower(trim(os_id)) <> COALESCE(os_family, '');

-- +goose Down
-- No down migration: the old rollup-only values were less specific.
-- Down would re-introduce the regression. If a roll-back of v1.3.0 is
-- ever required, re-run Discovery on the affected hosts under the
-- old binary instead.
SELECT 1;
