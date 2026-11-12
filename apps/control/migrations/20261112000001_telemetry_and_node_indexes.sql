-- Indexes for the two largest telemetry tables, plus node-name uniqueness.
--
-- The dashboard's default views filter on columns these tables have no index
-- for, so every request did a full window scan:
--
-- * `/access-logs?status_class=5xx` filters `status >= $1 AND status < $2`.
--   `idx_access_logs_ts` narrows by time, then filters every row in the window.
-- * `/waf/stats` and `/cc/stats` run six aggregations over the same
--   `ts >= NOW() - interval` window, each grouping by `action` or `category`.
--
-- `edge_nodes.name` is the de-facto primary key: heartbeats, token resolution
-- and the purge/report retry joins all match on it. It had neither a unique
-- constraint nor an index, so concurrent `POST /nodes` could create two rows with
-- the same name and heartbeats would then update an arbitrary one.

-- ---------------------------------------------------------------- access_logs
--
-- Leading `status` lets a status-class filter use the index directly; `ts DESC`
-- supplies the ordering the list endpoint asks for.
-- NOTE: this runs inside sqlx's per-migration transaction, so CONCURRENTLY is not
-- available. On a large existing table the build holds a lock; schedule the
-- upgrade accordingly, or create it by hand beforehand with CONCURRENTLY (the
-- `IF NOT EXISTS` below then makes this a no-op).
CREATE INDEX IF NOT EXISTS idx_access_logs_status_ts
    ON access_logs (status, ts DESC);

-- ---------------------------------------------------------------- waf_events
--
-- Same shape for the per-action aggregations.
CREATE INDEX IF NOT EXISTS idx_waf_events_action_ts
    ON waf_events (action, ts DESC);

-- ---------------------------------------------------------------- edge_nodes
--
-- Rename pre-existing duplicates before adding the constraint instead of
-- aborting the migration: a node row carries its token and heartbeat history,
-- so dropping one silently would strand a live edge. The first row (oldest)
-- keeps the name; later duplicates get a `~<n>` suffix that an operator can see
-- and clean up.
WITH ranked AS (
    SELECT id,
           name,
           row_number() OVER (PARTITION BY name ORDER BY created_at, id) AS rn
    FROM edge_nodes
)
UPDATE edge_nodes n
SET name = ranked.name || '~' || ranked.rn
FROM ranked
WHERE n.id = ranked.id
  AND ranked.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_edge_nodes_name ON edge_nodes (name);
