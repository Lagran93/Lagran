-- zstd / deflate request-body decompression for WAF inspection.
ALTER TABLE waf_settings
    ADD COLUMN IF NOT EXISTS body_decompress_zstd BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS body_decompress_deflate BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN waf_settings.body_decompress_zstd IS
    'Decompress Content-Encoding: zstd before WAF scanning (bounded to 256 KiB decoded)';
COMMENT ON COLUMN waf_settings.body_decompress_deflate IS
    'Decompress Content-Encoding: deflate (zlib) before WAF scanning (bounded to 256 KiB decoded)';
