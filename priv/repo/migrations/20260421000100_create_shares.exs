defmodule RefMD.Repo.Migrations.CreateShares do
  use Ecto.Migration

  def up do
    create table(:shares, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          null: false

      add :parent_share_id, references(:shares, type: :binary_id, on_delete: :delete_all)
      add :scope, :string, null: false
      add :token_hash, :string, null: false
      add :token_prefix, :string, null: false
      add :slug_ciphertext, :binary, null: false
      add :slug_nonce, :binary, null: false
      add :slug_key_id, :string, null: false
      add :permission, :string, null: false
      add :password_protected, :boolean, null: false, default: false
      add :access_limit, :integer
      add :access_count, :integer, null: false, default: 0

      add :created_by,
          references(:users, type: :binary_id, on_delete: :delete_all),
          null: false

      add :expires_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: :updated_at)
    end

    create unique_index(:shares, [:token_hash])
    create index(:shares, [:document_id])
    create index(:shares, [:created_by])

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_scope_check CHECK (scope IN ('document', 'folder'))",
      "ALTER TABLE shares DROP CONSTRAINT shares_scope_check"
    )

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_permission_check CHECK (permission IN ('view', 'edit'))",
      "ALTER TABLE shares DROP CONSTRAINT shares_permission_check"
    )

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_access_count_non_negative CHECK (access_count >= 0)",
      "ALTER TABLE shares DROP CONSTRAINT shares_access_count_non_negative"
    )

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_slug_nonce_size CHECK (octet_length(slug_nonce) = 12)",
      "ALTER TABLE shares DROP CONSTRAINT shares_slug_nonce_size"
    )

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_access_limit_positive CHECK (access_limit IS NULL OR access_limit >= 0)",
      "ALTER TABLE shares DROP CONSTRAINT shares_access_limit_positive"
    )

    create table(:share_keys, primary_key: false) do
      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          null: false

      add :encrypted_dek, :binary, null: false
      add :nonce, :binary
      add :dek_server_nonce, :binary, null: false
      add :server_key_id, :string, null: false
      add :manage_token_hash, :string, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:share_keys, [:manage_token_hash])
    create index(:share_keys, [:document_id])

    execute(
      "ALTER TABLE share_keys ADD CONSTRAINT share_keys_nonce_size CHECK (nonce IS NULL OR octet_length(nonce) = 24)",
      "ALTER TABLE share_keys DROP CONSTRAINT share_keys_nonce_size"
    )

    execute(
      "ALTER TABLE share_keys ADD CONSTRAINT share_keys_dek_server_nonce_size CHECK (octet_length(dek_server_nonce) = 12)",
      "ALTER TABLE share_keys DROP CONSTRAINT share_keys_dek_server_nonce_size"
    )

    create table(:shared_document_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          null: false

      add :token, :string, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create unique_index(:shared_document_tokens, [:token])
    create unique_index(:shared_document_tokens, [:share_id, :document_id])
    create index(:shared_document_tokens, [:document_id])

    create table(:shared_folder_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          null: false

      add :token, :string, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create unique_index(:shared_folder_tokens, [:token])
    create unique_index(:shared_folder_tokens, [:share_id, :document_id])
    create index(:shared_folder_tokens, [:document_id])

    create table(:share_participant_principals, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :display_name, :string, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create index(:share_participant_principals, [:share_id])

    create table(:share_participant_devices, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :principal_id,
          references(:share_participant_principals, type: :binary_id, on_delete: :delete_all),
          null: false

      add :signing_public_key, :binary, null: false
      add :encryption_public_key, :binary, null: false
      add :last_seen_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:share_participant_devices, [:share_id, :signing_public_key])
    create index(:share_participant_devices, [:principal_id])

    execute(
      "ALTER TABLE share_participant_devices ADD CONSTRAINT share_participant_devices_signing_key_size CHECK (octet_length(signing_public_key) = 32)",
      "ALTER TABLE share_participant_devices DROP CONSTRAINT share_participant_devices_signing_key_size"
    )

    execute(
      "ALTER TABLE share_participant_devices ADD CONSTRAINT share_participant_devices_encryption_key_size CHECK (octet_length(encryption_public_key) = 32)",
      "ALTER TABLE share_participant_devices DROP CONSTRAINT share_participant_devices_encryption_key_size"
    )

    create table(:share_participant_sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :principal_id,
          references(:share_participant_principals, type: :binary_id, on_delete: :delete_all),
          null: false

      add :device_id,
          references(:share_participant_devices, type: :binary_id, on_delete: :delete_all),
          null: false

      add :token_hash, :string, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :last_seen_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:share_participant_sessions, [:token_hash])
    create index(:share_participant_sessions, [:share_id])
    create index(:share_participant_sessions, [:expires_at])

    create table(:share_participant_pop_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :device_id,
          references(:share_participant_devices, type: :binary_id, on_delete: :delete_all),
          null: false

      add :challenge_hash, :binary, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:share_participant_pop_challenges, [:share_id, :device_id])
    create index(:share_participant_pop_challenges, [:expires_at])
  end

  def down do
    drop table(:share_participant_pop_challenges)
    drop table(:share_participant_sessions)
    drop table(:share_participant_devices)
    drop table(:share_participant_principals)
    drop table(:shared_folder_tokens)
    drop table(:shared_document_tokens)
    drop table(:share_keys)
    drop table(:shares)
  end
end
