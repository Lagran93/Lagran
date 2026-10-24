-- Project membership (multi-tenant)
CREATE TABLE IF NOT EXISTS project_members (
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'member', -- owner|admin|member
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);

-- Per-domain rate limit (requests per second, 0 = unlimited)
ALTER TABLE domains ADD COLUMN IF NOT EXISTS rate_limit_rps INT NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS rate_limit_burst INT NOT NULL DEFAULT 0;

-- Origin health tracking (updated by edge reports or control probes)
CREATE TABLE IF NOT EXISTS origin_health (
    domain_name     TEXT PRIMARY KEY,
    origin_url      TEXT NOT NULL DEFAULT '',
    healthy         BOOLEAN NOT NULL DEFAULT TRUE,
    latency_ms      INT NOT NULL DEFAULT 0,
    last_check_at   TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    consecutive_fails INT NOT NULL DEFAULT 0
);
