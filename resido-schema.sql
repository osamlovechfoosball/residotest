-- Resido PostgreSQL schema for Render.
-- The current app keeps one JSONB application-state record so the existing
-- server behavior stays stable while Render gives you real persistent storage.

CREATE TABLE IF NOT EXISTS resido_app_state (
  key TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit table for admin/history tracking. The server creates and writes to it
-- when PostgreSQL is enabled, while also keeping recent audit entries in app state.
CREATE TABLE IF NOT EXISTS resido_audit_log (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id TEXT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  building_id TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS resido_audit_log_created_at_idx
  ON resido_audit_log (created_at DESC);
