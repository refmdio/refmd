defmodule RefMD.Repo.Migrations.CreateEncryptionWorkspace do
  use Ecto.Migration

  def change do
    create table(:workspace_encrypted_keys, primary_key: false) do
      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :user_id,
          references(:users, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :device_id,
          references(:devices, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :key_version, :integer, primary_key: true

      add :sender_device_id,
          references(:devices, type: :binary_id, on_delete: :delete_all),
          null: false

      add :wrap_protocol, :text, null: false
      add :wrap_version, :integer, null: false
      add :suite_id, :text, null: false
      add :suite_rank, :integer, null: false
      add :purpose, :text, null: false
      add :resource, :map, null: false
      add :sender, :map, null: false
      add :recipient, :map, null: false
      add :event_scope, :map, null: false
      add :wrap_event_sequence, :bigint, null: false
      add :wrap_event_hash, :binary, null: false
      add :wrap_event_body_hash, :binary, null: false
      add :operation_checkpoint_sequence, :bigint, null: false
      add :operation_checkpoint_hash, :binary, null: false
      add :operation_checkpoint_covered_head_sequence, :bigint, null: false
      add :operation_checkpoint_covered_head_hash, :binary, null: false
      add :wrap_body_hash, :binary, null: false
      add :recipient_key_id, :binary, null: false
      add :sender_signing_key_id, :binary, null: false
      add :hpke_enc, :binary, null: false
      add :hpke_ciphertext, :binary, null: false
      add :signature_protocol, :text, null: false
      add :signature_version, :integer, null: false
      add :signature_suite_id, :text, null: false
      add :signature_suite_rank, :integer, null: false
      add :transcript_hash, :binary, null: false
      add :ed25519_signature, :binary, null: false
      add :mldsa65_signature, :binary, null: false
      add :is_active, :boolean, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:workspace_encrypted_keys, [:suite_id])
    create index(:workspace_encrypted_keys, [:sender_signing_key_id])
    create index(:workspace_encrypted_keys, [:recipient_key_id])

    create table(:workspace_tag_index_keys, primary_key: false) do
      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :encrypted_key, :binary, null: false
      add :nonce, :binary, null: false
      add :kek_version, :integer, null: false
      add :created_at, :utc_datetime_usec, null: false
    end
  end
end
