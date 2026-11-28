-- WAF body inspection protocol support (P3).
--
-- inspect_unknown_length: inspect chunked / HTTP/2 bodies without Content-Length
-- by reading up to body_max_bytes; bodies over the cap are rejected with 413
-- because they can no longer be replayed from Pingora's retry buffer.
--
-- decompress_gzip: decode Content-Encoding: gzip (bounded) before scanning.
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS body_inspect_unknown_length BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS body_decompress_gzip BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN waf_settings.body_inspect_unknown_length IS
    'Read chunked/no-Content-Length bodies up to body_max_bytes; oversized => 413';
COMMENT ON COLUMN waf_settings.body_decompress_gzip IS
    'Decompress Content-Encoding: gzip before WAF scanning (bounded to 256 KiB decoded)';
