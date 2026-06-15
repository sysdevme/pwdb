UPDATE server_profile
SET app_version = '4.1.1'
WHERE app_version IS NULL OR btrim(app_version) = '' OR app_version IN ('4.0.9', '4.1.0');

ALTER TABLE server_profile
ALTER COLUMN app_version SET DEFAULT '4.1.1';
