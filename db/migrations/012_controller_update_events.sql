CREATE TABLE IF NOT EXISTS controller_update_events (
  event_id TEXT PRIMARY KEY,
  master_server_id TEXT NOT NULL,
  vault_version BIGINT NOT NULL,
  payload_hash TEXT,
  status TEXT NOT NULL DEFAULT 'applied' CHECK (status IN ('applied', 'acked', 'error')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
