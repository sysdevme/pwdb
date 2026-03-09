CREATE TABLE IF NOT EXISTS pending_sync_bundles (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  master_server_id TEXT NOT NULL,
  master_server_url TEXT,
  bundle_type TEXT NOT NULL DEFAULT 'user_snapshot'
    CHECK (bundle_type IN ('user_snapshot')),
  payload_hash TEXT NOT NULL,
  ciphertext BYTEA NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'applied', 'failed')),
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  applied_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS pending_sync_bundles_user_status_idx
  ON pending_sync_bundles(user_id, status, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS pending_sync_bundles_user_payload_status_idx
  ON pending_sync_bundles(user_id, payload_hash, status);
