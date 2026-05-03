defmodule RefMD.Repo.Migrations.RefineDocumentSignerKeyContext do
  use Ecto.Migration

  def up do
    execute("""
    ALTER TABLE document_signer_keys
    ADD COLUMN IF NOT EXISTS context_key text
    """)

    execute("""
    UPDATE document_signer_keys
    SET context_key = concat_ws(
      ':',
      signer_kind,
      COALESCE(share_id::text, '-'),
      COALESCE(principal_id::text, '-'),
      COALESCE(user_id::text, '-'),
      device_id::text
    )
    WHERE context_key IS NULL
    """)

    execute("""
    ALTER TABLE document_signer_keys
    ALTER COLUMN context_key SET NOT NULL
    """)

    drop_if_exists index(:document_signer_keys, [:document_id, :signing_public_key])

    create_if_not_exists unique_index(
                           :document_signer_keys,
                           [:document_id, :signing_public_key, :context_key],
                           name: :document_signer_keys_context_unique_index
                         )
  end

  def down do
    drop_if_exists index(
                     :document_signer_keys,
                     [:document_id, :signing_public_key, :context_key],
                     name: :document_signer_keys_context_unique_index
                   )

    create_if_not_exists unique_index(:document_signer_keys, [:document_id, :signing_public_key])

    alter table(:document_signer_keys) do
      remove :context_key
    end
  end
end
