CREATE TABLE IF NOT EXISTS import_issues (
  id UUID PRIMARY KEY,
  import_run_id UUID NULL REFERENCES import_runs(id) ON DELETE SET NULL,
  source TEXT NOT NULL,
  type_name TEXT,
  title TEXT,
  external_uuid TEXT,
  reason TEXT NOT NULL,
  raw JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
