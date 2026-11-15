-- Administrator-managed Origin Shield endpoints.
--
-- Domain shield_url values may only reference rows in this table. Keeping the
-- allowlist in the control plane prevents ordinary domain owners from pointing
-- Edge origins at arbitrary internal endpoints.
CREATE TABLE IF NOT EXISTS shield_nodes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    url         TEXT NOT NULL UNIQUE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS shield_nodes_enabled_idx
    ON shield_nodes (enabled, name);
