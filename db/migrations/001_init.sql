CREATE TABLE IF NOT EXISTS password_entries (
  id UUID PRIMARY KEY,
  title TEXT NOT NULL,
  username TEXT,
  password_enc BYTEA NOT NULL,
  url TEXT,
  notes_enc BYTEA,
  import_source TEXT,
  import_raw JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tags (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS entry_tags (
  entry_id UUID NOT NULL REFERENCES password_entries(id) ON DELETE CASCADE,
  tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (entry_id, tag_id)
);

CREATE TABLE IF NOT EXISTS groups (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS group_entries (
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  entry_id UUID NOT NULL REFERENCES password_entries(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, entry_id)
);

CREATE TABLE IF NOT EXISTS secure_notes (
  id UUID PRIMARY KEY,
  title TEXT NOT NULL,
  body_enc BYTEA NOT NULL,
  import_source TEXT,
  import_raw JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
