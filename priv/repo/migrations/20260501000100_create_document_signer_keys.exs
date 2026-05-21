defmodule RefMD.Repo.Migrations.CreateDocumentSignerKeys do
  use Ecto.Migration

  def change do
    create table(:document_signer_keys, primary_key: false) do
      add :id, :bigserial, primary_key: true

      add :document_id, references(:documents, type: :binary_id, on_delete: :delete_all),
        null: false

      add :authority_kind, :text, null: false
      add :authority_id, :text, null: false
      add :authority_context_key, :text, null: false
      add :authority_scope_id, :text, null: false
      add :authority_permission_version, :integer, null: false
      add :key_checkpoint_sequence, :bigint, null: false
      add :key_checkpoint_hash, :text, null: false
      add :owner_kind, :text, null: false
      add :owner_id, :text, null: false
      add :hybrid_signing_public_key_material, :map, null: false
      add :signing_key_id, :text, null: false
      add :first_seen_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
      add :last_seen_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
    end

    create unique_index(
             :document_signer_keys,
             [
               :document_id,
               :signing_key_id,
               :authority_context_key,
               :key_checkpoint_hash
             ],
             name: :document_signer_keys_authority_checkpoint_unique_index
           )

    create index(
             :document_signer_keys,
             [
               :document_id,
               :authority_kind,
               :authority_id,
               :authority_context_key,
               :signing_key_id
             ],
             name: :document_signer_keys_authority_lookup_index
           )

    execute(
      "ALTER TABLE document_signer_keys ADD CONSTRAINT document_signer_keys_authority_kind_check CHECK (authority_kind IN ('workspace_device', 'share_participant_device'))",
      "ALTER TABLE document_signer_keys DROP CONSTRAINT document_signer_keys_authority_kind_check"
    )
  end
end
