CREATE TABLE IF NOT EXISTS plugin_installations (
  user_id UUID NOT NULL,
  plugin_id TEXT NOT NULL,
  version TEXT NOT NULL,
  scope TEXT NOT NULL,
  origin_url TEXT NULL,
  status TEXT NOT NULL DEFAULT 'enabled',
  installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_plugin_installations_plugin
  ON plugin_installations(plugin_id);

