ALTER TABLE documents
    ADD COLUMN slug TEXT,
    ADD COLUMN desired_path TEXT,
    ADD COLUMN path_digest BYTEA;

-- Generate unique, sanitized slugs for every document.
DO $$
DECLARE
    rec RECORD;
    base_slug TEXT;
    final_slug TEXT;
    counter INTEGER;
    nil_uuid CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    FOR rec IN
        SELECT id, title, owner_id, parent_id
        FROM documents
        ORDER BY created_at, id
    LOOP
        base_slug := lower(regexp_replace(regexp_replace(coalesce(rec.title, ''), '[^a-zA-Z0-9]+', '-', 'g'), '(^-|-$)', '', 'g'));
        IF base_slug = '' THEN
            base_slug := 'untitled';
        END IF;
        IF length(base_slug) > 100 THEN
            base_slug := left(base_slug, 100);
        END IF;
        final_slug := base_slug;
        counter := 1;
        WHILE EXISTS (
            SELECT 1
            FROM documents
            WHERE id <> rec.id
              AND owner_id = rec.owner_id
              AND coalesce(parent_id, nil_uuid) = coalesce(rec.parent_id, nil_uuid)
              AND slug = final_slug
        ) LOOP
            counter := counter + 1;
            final_slug := base_slug || '-' || counter::text;
        END LOOP;
        UPDATE documents SET slug = final_slug WHERE id = rec.id;
    END LOOP;
END$$;

-- Derive desired_path hierarchically using the generated slugs.
WITH RECURSIVE doc_tree AS (
    SELECT
        id,
        parent_id,
        type,
        slug,
        CASE
            WHEN parent_id IS NULL AND type = 'folder' THEN slug
            WHEN parent_id IS NULL THEN slug || '.md'
        END AS desired_path
    FROM documents
    WHERE parent_id IS NULL
      AND archived_parent_id IS NULL
    UNION ALL
    SELECT
        d.id,
        d.parent_id,
        d.type,
        d.slug,
        CASE
            WHEN d.type = 'folder' THEN doc_tree.desired_path || '/' || d.slug
            ELSE doc_tree.desired_path || '/' || d.slug || '.md'
        END AS desired_path
    FROM documents d
    JOIN doc_tree ON COALESCE(d.parent_id, d.archived_parent_id) = doc_tree.id
)
UPDATE documents
SET desired_path = doc_tree.desired_path
FROM doc_tree
WHERE documents.id = doc_tree.id;

-- Fallback for documents that failed to join the recursive tree (e.g. detached nodes).
UPDATE documents
SET desired_path = slug || CASE WHEN type = 'folder' THEN '' ELSE '.md' END
WHERE desired_path IS NULL;

UPDATE documents
SET path_digest = digest(desired_path, 'sha256');

ALTER TABLE documents
    ALTER COLUMN slug SET NOT NULL,
    ALTER COLUMN desired_path SET NOT NULL,
    ALTER COLUMN path_digest SET NOT NULL;

CREATE UNIQUE INDEX idx_documents_owner_parent_slug
    ON documents (owner_id, coalesce(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), slug);

CREATE UNIQUE INDEX idx_documents_owner_desired_path
    ON documents (owner_id, desired_path);

CREATE UNIQUE INDEX idx_documents_owner_path_digest
    ON documents (owner_id, path_digest);
