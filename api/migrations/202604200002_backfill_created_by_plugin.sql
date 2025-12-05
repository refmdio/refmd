-- Backfill created_by_plugin for existing documents using plugin KV/records activity
WITH candidates AS (
  SELECT scope_id AS doc_id, plugin, MIN(created_at) AS first_seen
  FROM (
    SELECT scope_id, plugin, created_at
    FROM plugin_kv
    WHERE scope = 'doc' AND scope_id IS NOT NULL AND plugin IS NOT NULL AND plugin <> ''
    UNION ALL
    SELECT scope_id, plugin, created_at
    FROM plugin_records
    WHERE scope = 'doc' AND plugin IS NOT NULL AND plugin <> ''
  ) s
  GROUP BY scope_id, plugin
),
chosen AS (
  SELECT doc_id, plugin
  FROM (
    SELECT doc_id,
           plugin,
           first_seen,
           ROW_NUMBER() OVER (PARTITION BY doc_id ORDER BY first_seen) AS rn
    FROM candidates
  ) t
  WHERE rn = 1
)
UPDATE documents d
SET created_by_plugin = c.plugin
FROM chosen c
WHERE d.id = c.doc_id
  AND d.created_by_plugin IS NULL;
