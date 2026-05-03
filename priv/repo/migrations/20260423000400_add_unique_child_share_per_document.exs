defmodule RefMD.Repo.Migrations.AddUniqueChildSharePerDocument do
  use Ecto.Migration

  def up do
    execute(duplicate_child_share_check_sql())
    execute(unreachable_child_share_check_sql())

    create unique_index(:shares, [:parent_share_id, :document_id],
             name: :shares_parent_share_document_id_index,
             where: "parent_share_id IS NOT NULL"
           )
  end

  def down do
    drop index(:shares, [:parent_share_id, :document_id],
           name: :shares_parent_share_document_id_index
         )
  end

  @spec duplicate_child_share_check_sql() :: String.t()
  def duplicate_child_share_check_sql do
    """
    DO $$
    DECLARE
      duplicate_keys text;
    BEGIN
      SELECT string_agg(parent_share_id::text || '/' || document_id::text, ', ')
      INTO duplicate_keys
      FROM (
        SELECT parent_share_id, document_id
        FROM shares
        WHERE parent_share_id IS NOT NULL
        GROUP BY parent_share_id, document_id
        HAVING COUNT(*) > 1
        ORDER BY parent_share_id, document_id
      ) duplicates;

      IF duplicate_keys IS NOT NULL THEN
        RAISE EXCEPTION 'duplicate child shares must be resolved before creating shares_parent_share_document_id_index: %', duplicate_keys;
      END IF;
    END
    $$;
    """
  end

  @spec unreachable_child_share_check_sql() :: String.t()
  def unreachable_child_share_check_sql do
    """
    DO $$
    DECLARE
      unreachable_keys text;
    BEGIN
      WITH RECURSIVE child_paths AS (
        SELECT
          child.parent_share_id AS root_share_id,
          root.document_id AS root_folder_id,
          child.document_id AS child_document_id,
          document.parent_id AS ancestor_id
        FROM shares child
        INNER JOIN shares root ON root.id = child.parent_share_id
        INNER JOIN documents document ON document.id = child.document_id
        WHERE child.parent_share_id IS NOT NULL AND root.scope = 'folder'

        UNION ALL

        SELECT
          child_paths.root_share_id,
          child_paths.root_folder_id,
          child_paths.child_document_id,
          ancestor.parent_id AS ancestor_id
        FROM child_paths
        INNER JOIN documents ancestor ON ancestor.id = child_paths.ancestor_id
        WHERE child_paths.ancestor_id IS NOT NULL
          AND child_paths.ancestor_id <> child_paths.root_folder_id
      ),
      unreachable AS (
        SELECT root_share_id, child_document_id, ancestor_id
        FROM child_paths
        WHERE ancestor_id IS NOT NULL
          AND ancestor_id <> root_folder_id
          AND NOT EXISTS (
            SELECT 1
            FROM shares ancestor_share
            WHERE ancestor_share.parent_share_id = child_paths.root_share_id
              AND ancestor_share.document_id = child_paths.ancestor_id
          )
      ),
      off_subtree AS (
        SELECT root_share_id, child_document_id, NULL::uuid AS ancestor_id
        FROM child_paths
        GROUP BY root_share_id, root_folder_id, child_document_id
        HAVING bool_or(ancestor_id = root_folder_id) IS NOT TRUE
      ),
      child_lineage AS (
        SELECT root_share_id, root_folder_id, child_document_id, child_document_id AS ancestor_id
        FROM child_paths
        UNION
        SELECT root_share_id, root_folder_id, child_document_id, ancestor_id
        FROM child_paths
        WHERE ancestor_id IS NOT NULL
      ),
      invalid_parent_scope AS (
        SELECT
          child.parent_share_id AS root_share_id,
          child.document_id AS child_document_id,
          NULL::uuid AS ancestor_id
        FROM shares child
        INNER JOIN shares root ON root.id = child.parent_share_id
        WHERE child.parent_share_id IS NOT NULL AND root.scope <> 'folder'
      ),
      invalid_child_scope AS (
        SELECT
          child.parent_share_id AS root_share_id,
          child.document_id AS child_document_id,
          NULL::uuid AS ancestor_id
        FROM shares child
        INNER JOIN documents document ON document.id = child.document_id
        WHERE child.parent_share_id IS NOT NULL AND child.scope <> document.doc_type
      ),
      invalid_exclusion AS (
        SELECT
          child_lineage.root_share_id,
          child_lineage.child_document_id,
          child_lineage.ancestor_id
        FROM child_lineage
        INNER JOIN share_exclusions exclusion
          ON exclusion.share_id = child_lineage.root_share_id
          AND exclusion.document_id = child_lineage.ancestor_id
      ),
      invalid_material AS (
        SELECT
          child.parent_share_id AS root_share_id,
          child.document_id AS child_document_id,
          NULL::uuid AS ancestor_id
        FROM shares child
        INNER JOIN documents document ON document.id = child.document_id
        LEFT JOIN share_keys share_key ON share_key.share_id = child.id
        LEFT JOIN shared_document_tokens document_token
          ON document_token.share_id = child.id
          AND document_token.document_id = child.document_id
        LEFT JOIN shared_folder_tokens folder_token
          ON folder_token.share_id = child.id
          AND folder_token.document_id = child.document_id
        WHERE child.parent_share_id IS NOT NULL
          AND (
            share_key.share_id IS NULL
            OR (document.doc_type = 'document' AND document_token.share_id IS NULL)
            OR (document.doc_type = 'folder' AND folder_token.share_id IS NULL)
          )
      ),
      invalid_paths AS (
        SELECT root_share_id, child_document_id, ancestor_id FROM unreachable
        UNION ALL
        SELECT root_share_id, child_document_id, ancestor_id FROM off_subtree
        UNION ALL
        SELECT root_share_id, child_document_id, ancestor_id FROM invalid_parent_scope
        UNION ALL
        SELECT root_share_id, child_document_id, ancestor_id FROM invalid_child_scope
        UNION ALL
        SELECT root_share_id, child_document_id, ancestor_id FROM invalid_exclusion
        UNION ALL
        SELECT root_share_id, child_document_id, ancestor_id FROM invalid_material
      )
      SELECT string_agg(
        root_share_id::text || '/' ||
          child_document_id::text || '/' ||
          COALESCE(ancestor_id::text, 'outside-root'),
        ', '
      )
      INTO unreachable_keys
      FROM invalid_paths;

      IF unreachable_keys IS NOT NULL THEN
        RAISE EXCEPTION 'unreachable folder share children must be resolved before creating shares_parent_share_document_id_index: %', unreachable_keys;
      END IF;
    END
    $$;
    """
  end
end
