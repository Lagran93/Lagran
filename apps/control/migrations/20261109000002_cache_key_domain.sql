-- Domain/rule cache-key header policy. Values are comma-separated header
-- names, currently limited to `origin` and `accept-language`.
ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS cache_key_ignore_headers TEXT NOT NULL DEFAULT '';

-- NULL means inherit the domain. '' means explicitly ignore none.
ALTER TABLE cache_rules
    ADD COLUMN IF NOT EXISTS ignore_key_headers TEXT;
