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

      add :encrypted_kek, :binary, null: false
      add :nonce, :binary, null: false
      add :is_active, :boolean, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    execute(
      "ALTER TABLE workspace_encrypted_keys ADD CONSTRAINT kek_nonce_size CHECK (octet_length(nonce) = 24)",
      "ALTER TABLE workspace_encrypted_keys DROP CONSTRAINT kek_nonce_size"
    )

    execute(
      "ALTER TABLE workspace_encrypted_keys ADD CONSTRAINT kek_ciphertext_size CHECK (octet_length(encrypted_kek) = 48)",
      "ALTER TABLE workspace_encrypted_keys DROP CONSTRAINT kek_ciphertext_size"
    )

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
