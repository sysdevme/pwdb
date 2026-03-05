CREATE TABLE IF NOT EXISTS password_share_links (
  token TEXT PRIMARY KEY,
  entry_id UUID NOT NULL REFERENCES password_entries(id) ON DELETE CASCADE,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS password_share_links_entry_id_idx
  ON password_share_links(entry_id);

CREATE INDEX IF NOT EXISTS password_share_links_expires_at_idx
  ON password_share_links(expires_at);
