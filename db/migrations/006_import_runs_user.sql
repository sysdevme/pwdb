ALTER TABLE import_runs
  ADD COLUMN IF NOT EXISTS user_id UUID;

UPDATE import_runs
SET user_id = u.id
FROM (SELECT id FROM users ORDER BY created_at ASC LIMIT 1) u
WHERE import_runs.user_id IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'import_runs_user_id_fkey'
  ) THEN
    ALTER TABLE import_runs
      ADD CONSTRAINT import_runs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_import_runs_user_id ON import_runs(user_id);
