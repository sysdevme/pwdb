CREATE TABLE IF NOT EXISTS server_profile (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
  server_mode TEXT NOT NULL CHECK (server_mode IN ('AS-M', 'AS-S')),
  sync_status TEXT NOT NULL DEFAULT 'standalone' CHECK (sync_status IN ('standalone', 'await_updates', 'syncing', 'error')),
  linked_master_id TEXT,
  linked_master_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (singleton)
);
