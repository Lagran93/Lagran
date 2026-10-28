-- Alert channels, rules and incident history.

CREATE TABLE IF NOT EXISTS alert_channels (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('email', 'webhook', 'telegram')),
    config      JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT NOT NULL,
    metric            TEXT NOT NULL,
    threshold         DOUBLE PRECISION NOT NULL DEFAULT 0,
    window_minutes    INT NOT NULL DEFAULT 5,
    channel_ids       JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    cooldown_seconds  INT NOT NULL DEFAULT 900,
    last_triggered_at TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_events (
    id          BIGSERIAL PRIMARY KEY,
    rule_id     UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
    rule_name   TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'warning',
    status      TEXT NOT NULL DEFAULT 'firing',
    value       DOUBLE PRECISION NOT NULL DEFAULT 0,
    message     TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    notified    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_events_firing
    ON alert_events (rule_id, fingerprint)
    WHERE status = 'firing';

CREATE INDEX IF NOT EXISTS idx_alert_events_started
    ON alert_events (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_events_rule
    ON alert_events (rule_id, started_at DESC);
