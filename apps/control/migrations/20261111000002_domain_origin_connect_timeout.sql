-- `origin_timeout_ms` changes meaning from "hard-coded default 10000" to a
-- per-domain override of the edge-wide ORIGIN_CONNECT_TIMEOUT_MS.
--
--   0     -> inherit the cluster default (resolved by the edge at runtime)
--   > 0   -> override the TCP connect timeout for this domain only
--
-- The previous default of 10000 was never a deliberate per-domain choice (the
-- console and the edge substituted it automatically), so existing rows that
-- still carry it are reset to "inherit" to pick up the new cluster default.
ALTER TABLE domains ALTER COLUMN origin_timeout_ms SET DEFAULT 0;

UPDATE domains SET origin_timeout_ms = 0 WHERE origin_timeout_ms = 10000;
