-- Versioned edge configuration + staged releases.
CREATE TABLE IF NOT EXISTS config_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL,
    domain_name TEXT NOT NULL,
    version     INT NOT NULL,
    snapshot    JSONB NOT NULL,
    diff        JSONB NOT NULL DEFAULT '[]'::jsonb,
    action      TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, version)
);
CREATE INDEX IF NOT EXISTS idx_config_versions_domain
    ON config_versions (domain_id, created_at DESC);

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS published_version_id UUID;

-- versions maps domain name -> config_versions.id. Empty target_nodes means all
-- online nodes; non-empty nodes are the canary set.
CREATE TABLE IF NOT EXISTS config_releases (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status         TEXT NOT NULL DEFAULT 'pending_approval',
    versions       JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_versions JSONB NOT NULL DEFAULT '{}'::jsonb,
    target_nodes   JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    note           TEXT NOT NULL DEFAULT '',
    created_by     TEXT NOT NULL DEFAULT '',
    approved_by    TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at    TIMESTAMPTZ,
    published_at   TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_config_releases_status
    ON config_releases (status, created_at DESC);

CREATE TABLE IF NOT EXISTS config_release_reports (
    release_id  UUID NOT NULL REFERENCES config_releases(id) ON DELETE CASCADE,
    node_id     TEXT NOT NULL,
    success     BOOLEAN NOT NULL,
    error       TEXT NOT NULL DEFAULT '',
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (release_id, node_id)
);
