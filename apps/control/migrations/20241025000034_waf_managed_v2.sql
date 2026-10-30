-- Expanded managed WAF rules. New categories default to enabled because they
-- are opt-out protections; operators can disable false-positive-prone groups
-- per domain from the console.
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS ssti BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS nosql BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS ldap BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS java BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS webshell BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS protocol BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN waf_settings.ssti IS 'Server-side template injection signatures';
COMMENT ON COLUMN waf_settings.nosql IS 'NoSQL operator injection signatures';
COMMENT ON COLUMN waf_settings.ldap IS 'LDAP filter injection signatures';
COMMENT ON COLUMN waf_settings.java IS 'Java deserialization / OGNL / Spring4Shell signatures';
COMMENT ON COLUMN waf_settings.webshell IS 'PHP webshell and code injection signatures';
COMMENT ON COLUMN waf_settings.protocol IS 'Null byte, overlong path/query and protocol anomalies';
