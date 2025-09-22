-- Share exclusions: hide specific documents from a folder share
CREATE TABLE IF NOT EXISTS share_exclusions (
  share_id uuid NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  PRIMARY KEY (share_id, document_id)
);
CREATE INDEX IF NOT EXISTS idx_share_exclusions_share ON share_exclusions(share_id);

