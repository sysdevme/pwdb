ALTER TABLE password_entries
  ADD COLUMN IF NOT EXISTS import_source TEXT,
  ADD COLUMN IF NOT EXISTS import_raw JSONB;

ALTER TABLE secure_notes
  ADD COLUMN IF NOT EXISTS import_source TEXT,
  ADD COLUMN IF NOT EXISTS import_raw JSONB;

CREATE TABLE IF NOT EXISTS import_runs (
  id UUID PRIMARY KEY,
  filename TEXT NOT NULL,
  file_size BIGINT NOT NULL,
  imported_passwords INT NOT NULL,
  imported_notes INT NOT NULL,
  existing_count INT NOT NULL,
  new_count INT NOT NULL,
  skipped_count INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
