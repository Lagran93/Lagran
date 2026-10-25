-- Node management: resource telemetry + lifecycle metadata

ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS cpu_usage DOUBLE PRECISION;
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS memory_usage DOUBLE PRECISION;
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS active_connections BIGINT;
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Per-node agent tokens (column already added by 20241024000007).
CREATE INDEX IF NOT EXISTS idx_edge_nodes_token ON edge_nodes(auth_token);

COMMENT ON COLUMN edge_nodes.status IS 'pending | online | offline | disabled';
