defmodule RefMD.Repo.Migrations.CreateEncryptionIdentity do
  use Ecto.Migration

  def change do
    create table(:user_identity_public_keys, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        primary_key: true

      add :ecdh_public_key, :binary, null: false
      add :signing_public_key, :binary, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create table(:user_encrypted_master_keys, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        primary_key: true

      add :auth_type, :text, null: false
      add :encrypted_umk, :binary
      add :umk_nonce, :binary
      add :salt, :binary
      add :kdf_type, :text
      add :kdf_params, :map
      add :auth_key_hash, :text
      add :recovery_encrypted_umk, :binary, null: false
      add :recovery_nonce, :binary, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create table(:user_encrypted_identity_keys, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        primary_key: true

      add :encrypted_ecdh_private, :binary, null: false
      add :encrypted_ecdh_private_nonce, :binary, null: false
      add :encrypted_signing_private, :binary, null: false
      add :encrypted_signing_private_nonce, :binary, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create table(:device_encrypted_umks, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :device_id, references(:devices, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :sender_device_id, :binary_id, null: false
      add :encrypted_umk, :binary, null: false
      add :nonce, :binary, null: false
      add :created_at, :utc_datetime_usec, null: false
    end
  end
end
