CREATE TABLE IF NOT EXISTS api_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  token_digest TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
