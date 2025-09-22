-- Plugin key-value store
CREATE TABLE IF NOT EXISTS plugin_kv (
  id BIGSERIAL PRIMARY KEY,
  plugin TEXT NOT NULL,
  scope TEXT NOT NULL,              -- e.g., 'doc' | 'user' | 'global'
  scope_id UUID NULL,               -- NULL for global scope
  key TEXT NOT NULL,
  value JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(plugin, scope, scope_id, key)
);

CREATE INDEX IF NOT EXISTS idx_plugin_kv_lookup ON plugin_kv(plugin, scope, scope_id, key);

-- Generic plugin records (timeline-style data, etc.)
CREATE TABLE IF NOT EXISTS plugin_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  plugin TEXT NOT NULL,
  scope TEXT NOT NULL,              -- e.g., 'doc' | 'user'
  scope_id UUID NOT NULL,
  kind TEXT NOT NULL,               -- e.g., 'post' | 'comment'
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_plugin_records_lookup ON plugin_records(plugin, scope, scope_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_plugin_records_kind ON plugin_records(plugin, kind);
CREATE INDEX IF NOT EXISTS idx_plugin_records_scope ON plugin_records(scope, scope_id);

