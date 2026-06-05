-- sqlc input. Day 5 wires `make generate` to run sqlc against this file
-- and emit the typed Go in internal/db/audit_queries.gen.go.
--
-- Day 3 ships a hand-written equivalent at internal/db/audit_queries.go;
-- when sqlc lands, that file is replaced with the generated one (same
-- function signatures so callers don't change).

-- name: InsertAuditEvent :one
INSERT INTO audit_events (
    id, correlation_id, actor_type, actor_id, action,
    resource_type, resource_id, detail
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING *;

-- name: ListAuditEvents :many
SELECT *
FROM audit_events
WHERE ($1::timestamptz IS NULL OR occurred_at < $1)
ORDER BY occurred_at DESC, id DESC
LIMIT $2;

-- name: GetAuditEventByID :one
SELECT *
FROM audit_events
WHERE id = $1;

-- name: CountAuditEvents :one
SELECT COUNT(*) FROM audit_events;
