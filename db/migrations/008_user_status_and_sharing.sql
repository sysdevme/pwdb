ALTER TABLE users
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

UPDATE users
SET status = 'active'
WHERE status IS NULL OR BTRIM(status) = '';

CREATE TABLE IF NOT EXISTS password_entry_shares (
  entry_id UUID NOT NULL REFERENCES password_entries(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (entry_id, user_id)
);

CREATE TABLE IF NOT EXISTS secure_note_shares (
  note_id UUID NOT NULL REFERENCES secure_notes(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (note_id, user_id)
);
