-- Optional boolean DSL expression for custom WAF rules.
ALTER TABLE waf_rules
  ADD COLUMN IF NOT EXISTS expr TEXT NOT NULL DEFAULT '';
