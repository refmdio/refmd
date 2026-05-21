defmodule RefMD.Repo.Migrations.RelaxDocumentDeviceForeignKeys do
  use Ecto.Migration

  def up do
    execute(
      "ALTER TABLE document_snapshots DROP CONSTRAINT IF EXISTS document_snapshots_device_id_fkey"
    )

    execute(
      "ALTER TABLE document_updates DROP CONSTRAINT IF EXISTS document_updates_device_id_fkey"
    )
  end

  def down do
    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'document_snapshots' AND column_name = 'device_id'
      ) OR NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'document_updates' AND column_name = 'device_id'
      ) THEN
        RETURN;
      END IF;

      IF EXISTS (
        SELECT 1
        FROM document_snapshots ds
        LEFT JOIN devices d ON d.id = ds.device_id
        WHERE ds.device_id IS NOT NULL AND d.id IS NULL
      ) OR EXISTS (
        SELECT 1
        FROM document_updates du
        LEFT JOIN devices d ON d.id = du.device_id
        WHERE du.device_id IS NOT NULL AND d.id IS NULL
      ) THEN
        RAISE EXCEPTION
          'Cannot restore document device foreign keys while share participant device IDs remain in document snapshots or updates';
      END IF;

      ALTER TABLE document_snapshots
      ADD CONSTRAINT document_snapshots_device_id_fkey
      FOREIGN KEY (device_id) REFERENCES devices(id);

      ALTER TABLE document_updates
      ADD CONSTRAINT document_updates_device_id_fkey
      FOREIGN KEY (device_id) REFERENCES devices(id);
    END
    $$;
    """)
  end
end
