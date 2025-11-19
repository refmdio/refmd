-- Pre-workspace cleanup for doc_events so that migration 202601010001 can set
-- workspace_id to NOT NULL without hitting existing null rows.

ALTER TABLE doc_events
    ADD COLUMN IF NOT EXISTS workspace_id UUID;

UPDATE doc_events AS de
SET workspace_id = d.workspace_id
FROM documents AS d
WHERE de.doc_id = d.id
  AND de.workspace_id IS NULL;

DELETE FROM doc_events
WHERE doc_id IS NULL;

DELETE FROM doc_events AS de
WHERE de.workspace_id IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM documents AS d
    WHERE d.id = de.doc_id
  );
