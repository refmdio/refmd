-- Allow password_hash to be nullable for external providers
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

-- Track Google accounts (one-to-one, optional)
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS google_subject TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_google_subject
    ON users(google_subject)
    WHERE google_subject IS NOT NULL;
