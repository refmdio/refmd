defmodule RefMD.Repo.Migrations.AddPluginPackageEntryStoragePathConstraint do
  use Ecto.Migration

  def change do
    execute(
      """
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'plugin_package_entries_storage_path_id_check'
        ) THEN
          ALTER TABLE plugin_package_entries
          ADD CONSTRAINT plugin_package_entries_storage_path_id_check
          CHECK (storage_path = 'plugin-packages/' || id::text);
        END IF;
      END $$;
      """,
      "ALTER TABLE plugin_package_entries DROP CONSTRAINT IF EXISTS plugin_package_entries_storage_path_id_check"
    )
  end
end
