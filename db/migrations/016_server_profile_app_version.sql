ALTER TABLE server_profile
ADD COLUMN IF NOT EXISTS app_version TEXT;

UPDATE server_profile
SET app_version = '4.0.9'
WHERE app_version IS NULL OR btrim(app_version) = '';

ALTER TABLE server_profile
ALTER COLUMN app_version SET DEFAULT '4.0.9';
