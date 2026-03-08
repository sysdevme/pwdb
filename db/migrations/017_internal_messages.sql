CREATE TABLE IF NOT EXISTS internal_messages (
  id UUID PRIMARY KEY,
  from_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  read_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT internal_messages_body_not_empty CHECK (length(trim(body)) > 0),
  CONSTRAINT internal_messages_body_len CHECK (length(body) <= 300),
  CONSTRAINT internal_messages_distinct_users CHECK (from_user_id <> to_user_id)
);

CREATE INDEX IF NOT EXISTS internal_messages_to_user_idx
  ON internal_messages(to_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS internal_messages_from_user_idx
  ON internal_messages(from_user_id, created_at DESC);
