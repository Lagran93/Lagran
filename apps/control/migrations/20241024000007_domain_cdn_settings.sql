-- Per-domain CDN advanced settings
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ignore_query_string BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS cors_origins TEXT NOT NULL DEFAULT ''; -- comma-separated or *
ALTER TABLE domains ADD COLUMN IF NOT EXISTS hotlink_allow_referers TEXT NOT NULL DEFAULT ''; -- empty = off
ALTER TABLE domains ADD COLUMN IF NOT EXISTS origin_timeout_ms INT NOT NULL DEFAULT 10000;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS custom_headers TEXT NOT NULL DEFAULT ''; -- "X-Foo:bar\nX-Bar:baz"

-- Edge agent shared secret (optional auth for edge→control and control→edge)
-- Stored as env on both sides; this table records per-node token override optional
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS auth_token TEXT NOT NULL DEFAULT '';

-- Prefetch / warm tasks (simple queue)
CREATE TABLE IF NOT EXISTS prefetch_tasks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain      TEXT NOT NULL,
    url_path    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending', -- pending|done|failed
    message     TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_prefetch_status ON prefetch_tasks(status);
