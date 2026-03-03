CREATE TABLE IF NOT EXISTS note_tags (
  note_id UUID NOT NULL REFERENCES secure_notes(id) ON DELETE CASCADE,
  tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (note_id, tag_id)
);

CREATE TABLE IF NOT EXISTS note_group_entries (
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  note_id UUID NOT NULL REFERENCES secure_notes(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, note_id)
);
