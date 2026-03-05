CREATE TABLE IF NOT EXISTS controller_links (
  id UUID PRIMARY KEY,
  slave_server_id TEXT NOT NULL UNIQUE,
  slave_endpoint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
