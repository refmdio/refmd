-- Track parent (origin) folder share for materialized document shares
ALTER TABLE shares
  ADD COLUMN IF NOT EXISTS parent_share_id uuid NULL REFERENCES shares(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_shares_parent_share ON shares(parent_share_id);

