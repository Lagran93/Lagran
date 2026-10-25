-- Tenancy roles + richer cache rules

-- Global role: 'admin' sees every project/domain; 'user' only their projects.
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
UPDATE users SET role = 'admin' WHERE email = 'demo@lagran.dev';

-- Cache rules: action + stale-while-revalidate window
ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'cache';
ALTER TABLE cache_rules ADD COLUMN IF NOT EXISTS swr_seconds BIGINT NOT NULL DEFAULT 0;

-- Hot-path lookups for tenancy scoping
CREATE INDEX IF NOT EXISTS idx_domains_project ON domains(project_id);
CREATE INDEX IF NOT EXISTS idx_cache_rules_domain ON cache_rules(domain_id);
CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain_name);
CREATE INDEX IF NOT EXISTS idx_access_logs_host_ts ON access_logs(host, ts DESC);
