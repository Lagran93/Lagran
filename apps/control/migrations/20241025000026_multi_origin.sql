-- Multi-origin pools and per-origin health.

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS origins JSONB NOT NULL DEFAULT '[]'::jsonb;

-- origin_health used a single row per domain. Move to one row per origin so the
-- edge can make health-aware weighted decisions.
ALTER TABLE origin_health
    DROP CONSTRAINT IF EXISTS origin_health_pkey;

ALTER TABLE origin_health
    ADD PRIMARY KEY (domain_name, origin_url);
