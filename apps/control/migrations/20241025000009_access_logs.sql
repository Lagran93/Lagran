CREATE TABLE IF NOT EXISTS access_logs (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    node_id      TEXT NOT NULL DEFAULT '',
    client_ip    TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT '',
    host         TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    status       INT NOT NULL DEFAULT 0,
    bytes        BIGINT NOT NULL DEFAULT 0,
    latency_ms   INT NOT NULL DEFAULT 0,
    cache_status TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    referer      TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_access_logs_ts ON access_logs(ts DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_host ON access_logs(host);
CREATE INDEX IF NOT EXISTS idx_access_logs_node ON access_logs(node_id);
