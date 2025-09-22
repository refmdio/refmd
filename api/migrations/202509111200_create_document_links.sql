-- Document links graph for backlinks and outgoing links
CREATE TABLE IF NOT EXISTS document_links (
  source_document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  target_document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  link_type TEXT NOT NULL CHECK (link_type IN ('reference','embed','mention')),
  link_text TEXT NULL,
  position_start INT NOT NULL DEFAULT 0,
  position_end INT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (source_document_id, target_document_id, position_start)
);

CREATE INDEX IF NOT EXISTS idx_document_links_target ON document_links(target_document_id);
CREATE INDEX IF NOT EXISTS idx_document_links_source ON document_links(source_document_id);

