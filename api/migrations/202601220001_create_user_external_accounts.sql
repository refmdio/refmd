CREATE TABLE IF NOT EXISTS user_external_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_user_external_accounts_user_id ON user_external_accounts(user_id);

INSERT INTO user_external_accounts (user_id, provider, subject)
SELECT id, 'google', google_subject
FROM users
WHERE google_subject IS NOT NULL;

ALTER TABLE users
  DROP COLUMN IF EXISTS google_subject;
