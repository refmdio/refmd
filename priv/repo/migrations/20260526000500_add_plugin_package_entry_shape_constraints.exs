defmodule RefMD.Repo.Migrations.AddPluginPackageEntryShapeConstraints do
  use Ecto.Migration

  def change do
    execute(
      """
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'plugin_package_entries_kind_path_check'
        ) THEN
          ALTER TABLE plugin_package_entries
          ADD CONSTRAINT plugin_package_entries_kind_path_check
          CHECK (
            (entry_kind = 'manifest' AND logical_path = 'manifest.json' AND resource_kind IS NULL)
            OR (entry_kind = 'main_js' AND logical_path = 'main.js' AND resource_kind IS NULL)
            OR (entry_kind = 'styles_css' AND logical_path = 'styles.css' AND resource_kind IS NULL)
            OR (
              entry_kind = 'resource'
              AND logical_path LIKE 'resources/%'
              AND length(logical_path) > length('resources/')
              AND resource_kind IS NOT NULL
            )
          );
        END IF;
      END $$;
      """,
      "ALTER TABLE plugin_package_entries DROP CONSTRAINT IF EXISTS plugin_package_entries_kind_path_check"
    )

    create_if_not_exists unique_index(
                           :plugin_package_entries,
                           [:candidate_id, :entry_kind],
                           name: :plugin_package_entries_candidate_singleton_kind_index,
                           where:
                             "candidate_id IS NOT NULL AND entry_kind IN ('manifest', 'main_js', 'styles_css')"
                         )

    create_if_not_exists unique_index(
                           :plugin_package_entries,
                           [:bundle_id, :entry_kind],
                           name: :plugin_package_entries_bundle_singleton_kind_index,
                           where:
                             "bundle_id IS NOT NULL AND entry_kind IN ('manifest', 'main_js', 'styles_css')"
                         )
  end
end
