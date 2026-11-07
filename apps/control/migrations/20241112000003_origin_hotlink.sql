-- Origin authentication and hotlink signature.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS origin_auth_header TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS origin_auth_value TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS hotlink_signature_enabled BOOLEAN NOT NULL DEFAULT FALSE;
