-- Durable purge retries for offline/failed edge nodes.
CREATE TABLE IF NOT EXISTS purge_retries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     TEXT NOT NULL,
    agent_url   TEXT NOT NULL,
    payload     JSONB NOT NULL,
    attempts    INT NOT NULL DEFAULT 0,
    next_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_purge_retries_due
    ON purge_retries (next_at, attempts);
