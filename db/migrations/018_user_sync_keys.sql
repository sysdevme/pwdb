CREATE TABLE IF NOT EXISTS user_sync_keys (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  server_wrapped_key BYTEA NOT NULL,
  master_wrapped_key BYTEA NOT NULL,
  key_fingerprint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
