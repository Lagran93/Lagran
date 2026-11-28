-- Brotli request-body decompression for WAF inspection.
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS body_decompress_brotli BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN waf_settings.body_decompress_brotli IS
    'Decompress Content-Encoding: br before WAF scanning (bounded to 256 KiB decoded)';
