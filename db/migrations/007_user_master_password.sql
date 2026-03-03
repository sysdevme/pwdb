ALTER TABLE users
  ADD COLUMN IF NOT EXISTS master_password_hash TEXT;

UPDATE users
SET master_password_hash = password_hash
WHERE master_password_hash IS NULL;

ALTER TABLE users
  ALTER COLUMN master_password_hash SET NOT NULL;
