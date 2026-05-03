defmodule RefMD.Repo.Migrations.SyncDocumentUpdateShareColumns do
  use Ecto.Migration

  def up do
    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'document_updates' AND column_name = 'mac'
      ) THEN
        ALTER TABLE document_updates ADD COLUMN mac bytea;
        COMMENT ON COLUMN document_updates.mac IS 'added_by_20260421000300';
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'document_updates' AND column_name = 'share_id'
      ) THEN
        ALTER TABLE document_updates ADD COLUMN share_id uuid;
        COMMENT ON COLUMN document_updates.share_id IS 'added_by_20260421000300';
      END IF;
    END
    $$;
    """)

    execute("ALTER TABLE document_updates DROP CONSTRAINT IF EXISTS document_updates_auth_check")

    execute("""
    ALTER TABLE document_updates
    ADD CONSTRAINT document_updates_auth_check
    CHECK (
      signature IS NOT NULL AND
      mac IS NULL AND
      clock IS NOT NULL AND
      device_signing_pub_key IS NOT NULL AND
      device_id IS NOT NULL AND
      share_id IS NULL
    )
    """)
  end

  def down do
    execute("ALTER TABLE document_updates DROP CONSTRAINT IF EXISTS document_updates_auth_check")

    execute("""
    DO $$
    DECLARE
      mac_added boolean := EXISTS (
        SELECT 1
        FROM pg_catalog.pg_description d
        JOIN pg_catalog.pg_class c ON c.oid = d.objoid
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.objsubid
        WHERE c.relname = 'document_updates'
          AND a.attname = 'mac'
          AND d.description = 'added_by_20260421000300'
      );
      share_id_added boolean := EXISTS (
        SELECT 1
        FROM pg_catalog.pg_description d
        JOIN pg_catalog.pg_class c ON c.oid = d.objoid
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.objsubid
        WHERE c.relname = 'document_updates'
          AND a.attname = 'share_id'
          AND d.description = 'added_by_20260421000300'
      );
    BEGIN
      IF mac_added THEN
        ALTER TABLE document_updates DROP COLUMN mac;
      END IF;

      IF share_id_added THEN
        ALTER TABLE document_updates DROP COLUMN share_id;
      END IF;

      IF NOT mac_added AND NOT share_id_added THEN
        ALTER TABLE document_updates
        ADD CONSTRAINT document_updates_auth_check
        CHECK (
          signature IS NOT NULL AND
          mac IS NULL AND
          clock IS NOT NULL AND
          device_signing_pub_key IS NOT NULL AND
          device_id IS NOT NULL AND
          share_id IS NULL
        );
      ELSE
        ALTER TABLE document_updates
        ADD CONSTRAINT document_updates_auth_check
        CHECK (
          signature IS NOT NULL AND
          clock IS NOT NULL AND
          device_signing_pub_key IS NOT NULL AND
          device_id IS NOT NULL
        );
      END IF;
    END
    $$;
    """)
  end
end
