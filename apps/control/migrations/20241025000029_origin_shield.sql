-- Optional Origin Shield endpoint. Requests still carry the public domain Host
-- header, so an upstream edge can cache/serve the origin response.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS shield_url TEXT NOT NULL DEFAULT '';
