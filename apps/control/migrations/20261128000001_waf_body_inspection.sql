-- Bounded WAF request-body inspection (P2).
--
-- These fields are per-domain policy. The Edge enforces a hard 64 KiB ceiling
-- (Pingora's retry-buffer limit); max_bytes is clamped to 1024..=65536 on the
-- API side and again on the Edge.
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS body_inspection BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS body_max_bytes INT NOT NULL DEFAULT 32768,
    ADD COLUMN IF NOT EXISTS body_methods TEXT NOT NULL DEFAULT 'POST,PUT,PATCH',
    ADD COLUMN IF NOT EXISTS body_content_types TEXT NOT NULL
        DEFAULT 'application/json,application/x-www-form-urlencoded,text/*',
    ADD COLUMN IF NOT EXISTS body_oversize_policy TEXT NOT NULL DEFAULT 'log',
    ADD COLUMN IF NOT EXISTS body_uninspectable_policy TEXT NOT NULL DEFAULT 'log',
    ADD COLUMN IF NOT EXISTS body_timeout_ms INT NOT NULL DEFAULT 1000;

COMMENT ON COLUMN waf_settings.body_inspection IS
    'Inspect POST/PUT/PATCH bodies within body_max_bytes';
COMMENT ON COLUMN waf_settings.body_max_bytes IS
    'Body inspection ceiling, 1024..=65536 (Pingora retry buffer hard cap)';
COMMENT ON COLUMN waf_settings.body_methods IS
    'Comma-separated methods whose bodies are inspected';
COMMENT ON COLUMN waf_settings.body_content_types IS
    'Comma-separated media types; text/* and */* wildcards supported by the Edge';
COMMENT ON COLUMN waf_settings.body_oversize_policy IS
    'log | block | allow when Content-Length exceeds body_max_bytes';
COMMENT ON COLUMN waf_settings.body_uninspectable_policy IS
    'log | block | allow for chunked/compressed/Expect/multipart bodies';
COMMENT ON COLUMN waf_settings.body_timeout_ms IS
    'Total body read timeout, 100..=5000 ms';
