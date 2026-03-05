ALTER TABLE controller_links
  ADD COLUMN IF NOT EXISTS last_handshake_at TIMESTAMPTZ;

UPDATE controller_links
SET last_handshake_at = COALESCE(last_handshake_at, updated_at, created_at)
WHERE last_handshake_at IS NULL;
