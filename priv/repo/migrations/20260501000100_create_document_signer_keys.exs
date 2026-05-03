defmodule RefMD.Repo.Migrations.CreateDocumentSignerKeys do
  use Ecto.Migration

  def change do
    create table(:document_signer_keys, primary_key: false) do
      add :id, :bigserial, primary_key: true

      add :document_id, references(:documents, type: :binary_id, on_delete: :delete_all),
        null: false

      add :signer_kind, :text, null: false
      add :share_id, :binary_id
      add :principal_id, :binary_id
      add :user_id, :binary_id
      add :device_id, :binary_id, null: false
      add :context_key, :text, null: false
      add :signing_public_key, :binary, null: false
      add :encryption_public_key, :binary, null: false
      add :first_seen_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
      add :last_seen_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
    end

    create unique_index(
             :document_signer_keys,
             [:document_id, :signing_public_key, :context_key],
             name: :document_signer_keys_context_unique_index
           )

    create index(:document_signer_keys, [:document_id, :signer_kind])
    create index(:document_signer_keys, [:document_id, :share_id])

    execute(
      "ALTER TABLE document_signer_keys ADD CONSTRAINT document_signer_keys_kind_check CHECK (signer_kind IN ('workspace', 'share_participant', 'mounted_share'))",
      "ALTER TABLE document_signer_keys DROP CONSTRAINT document_signer_keys_kind_check"
    )

    execute(
      "ALTER TABLE document_signer_keys ADD CONSTRAINT document_signer_keys_signing_key_size CHECK (octet_length(signing_public_key) = 32)",
      "ALTER TABLE document_signer_keys DROP CONSTRAINT document_signer_keys_signing_key_size"
    )

    execute(
      "ALTER TABLE document_signer_keys ADD CONSTRAINT document_signer_keys_encryption_key_size CHECK (octet_length(encryption_public_key) = 32)",
      "ALTER TABLE document_signer_keys DROP CONSTRAINT document_signer_keys_encryption_key_size"
    )
  end
end
