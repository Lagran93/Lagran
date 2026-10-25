-- WAF: security level + expanded managed categories

ALTER TABLE waf_settings ADD COLUMN IF NOT EXISTS security_level TEXT NOT NULL DEFAULT 'off';
ALTER TABLE waf_settings ADD COLUMN IF NOT EXISTS rce BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings ADD COLUMN IF NOT EXISTS ssrf BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings ADD COLUMN IF NOT EXISTS xxe BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings ADD COLUMN IF NOT EXISTS log4shell BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE waf_settings ADD COLUMN IF NOT EXISTS crlf BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN waf_settings.security_level IS 'off | low | medium | high | under_attack';
COMMENT ON COLUMN waf_settings.rce IS 'Command injection / RCE signatures';
COMMENT ON COLUMN waf_settings.ssrf IS 'SSRF and cloud metadata endpoints';
COMMENT ON COLUMN waf_settings.xxe IS 'XML external entity signatures';
COMMENT ON COLUMN waf_settings.log4shell IS 'Log4Shell JNDI signatures';
COMMENT ON COLUMN waf_settings.crlf IS 'CRLF / header injection';
