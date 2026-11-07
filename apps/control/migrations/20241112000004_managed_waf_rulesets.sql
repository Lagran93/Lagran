-- Managed WAF rulesets selected per domain (comma-separated catalog ids).
ALTER TABLE waf_settings
  ADD COLUMN IF NOT EXISTS managed_rulesets TEXT NOT NULL DEFAULT '';
