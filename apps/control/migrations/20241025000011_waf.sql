-- WAF: per-domain settings, custom rules, IP lists and event log

CREATE TABLE IF NOT EXISTS waf_settings (
    domain_id   UUID PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    mode        TEXT NOT NULL DEFAULT 'block', -- block | monitor
    sqli        BOOLEAN NOT NULL DEFAULT TRUE,
    xss         BOOLEAN NOT NULL DEFAULT TRUE,
    traversal   BOOLEAN NOT NULL DEFAULT TRUE,
    scanners    BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    field       TEXT NOT NULL DEFAULT 'path',    -- path|query|user_agent|referer|method|ip
    operator    TEXT NOT NULL DEFAULT 'contains',-- contains|equals|prefix|suffix
    value       TEXT NOT NULL,
    action      TEXT NOT NULL DEFAULT 'block',   -- block|allow|log
    priority    INT NOT NULL DEFAULT 0,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_rules_domain ON waf_rules(domain_id);

CREATE TABLE IF NOT EXISTS waf_ip_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,                   -- allow | deny
    ip          TEXT NOT NULL,                   -- IP or CIDR
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_ip_rules_domain ON waf_ip_rules(domain_id);

CREATE TABLE IF NOT EXISTS waf_events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    domain      TEXT NOT NULL,
    node_id     TEXT NOT NULL DEFAULT '',
    client_ip   TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,                   -- block | monitor | log
    category    TEXT NOT NULL DEFAULT '',        -- sqli|xss|traversal|scanners|ip_deny|custom
    rule_name   TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'block'    -- block | monitor
);

CREATE INDEX IF NOT EXISTS idx_waf_events_domain_ts ON waf_events(domain, ts DESC);
CREATE INDEX IF NOT EXISTS idx_waf_events_ts ON waf_events(ts DESC);
