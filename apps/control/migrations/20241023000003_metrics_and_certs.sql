-- Edge metrics aggregates (simple counters per node/domain)
CREATE TABLE IF NOT EXISTS edge_metrics (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_name       TEXT NOT NULL,
    domain          TEXT NOT NULL DEFAULT '',
    requests        BIGINT NOT NULL DEFAULT 0,
    cache_hits      BIGINT NOT NULL DEFAULT 0,
    cache_misses    BIGINT NOT NULL DEFAULT 0,
    bytes_sent      BIGINT NOT NULL DEFAULT 0,
    reported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_edge_metrics_reported ON edge_metrics(reported_at DESC);
CREATE INDEX IF NOT EXISTS idx_edge_metrics_node ON edge_metrics(node_name);

-- TLS certificates for domains
CREATE TABLE IF NOT EXISTS certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    domain_name     TEXT NOT NULL,
    cert_pem        TEXT NOT NULL DEFAULT '',
    key_pem         TEXT NOT NULL DEFAULT '',
    issuer          TEXT NOT NULL DEFAULT '',
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'pending', -- pending|active|expired|error
    auto_renew      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain_name);
