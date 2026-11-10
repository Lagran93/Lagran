-- WAF: per-domain Geo/ASN allow/deny lists evaluated on the Edge with
-- MaxMind GeoLite2-Country and GeoLite2-ASN databases.

CREATE TABLE IF NOT EXISTS waf_geo_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,                   -- country_allow | country_deny | asn_allow | asn_deny
    value       TEXT NOT NULL,                   -- ISO 3166-1 alpha-2, or decimal ASN
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT waf_geo_rules_kind_check CHECK (
        kind IN ('country_allow', 'country_deny', 'asn_allow', 'asn_deny')
    )
);

CREATE INDEX IF NOT EXISTS idx_waf_geo_rules_domain ON waf_geo_rules(domain_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_waf_geo_rules_unique
    ON waf_geo_rules(domain_id, kind, value);
