CREATE TABLE IF NOT EXISTS controller_slave_grants (
  id UUID PRIMARY KEY,
  controller_id TEXT NOT NULL REFERENCES controller_registry(controller_id) ON DELETE CASCADE,
  slave_endpoint TEXT NOT NULL,
  grant_token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS controller_slave_grants_controller_expiry_idx
  ON controller_slave_grants(controller_id, expires_at DESC);
