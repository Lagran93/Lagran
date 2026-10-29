-- P0 query-path indexes. All are additive and safe for existing data.

-- Per-domain timeseries / project-scoped cache metrics.
CREATE INDEX IF NOT EXISTS idx_edge_metrics_domain_reported
    ON edge_metrics(domain, reported_at DESC);

-- Certificate expiry alert evaluator.
CREATE INDEX IF NOT EXISTS idx_certificates_status_not_after
    ON certificates(status, not_after);

-- Node-offline detection.
CREATE INDEX IF NOT EXISTS idx_edge_nodes_status_heartbeat
    ON edge_nodes(status, last_heartbeat);
