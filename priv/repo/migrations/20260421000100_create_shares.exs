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
      add :authorization_public_key_material, :map
      add :share_capability_secret_commitment, :string, null: false
      add :password_capability_secret_commitment, :string, null: false, default: "none"
      add :capability_context_hash, :string, null: false
      add :created_event_hash, :string, null: false
      add :latest_bootstrap_event_hash, :string, null: false
      add :authenticated_workspace_pin_bootstrap_hash, :text, null: false
      add :authenticated_workspace_pin_bootstrap_checkpoint, :map
      add :permission, :string, null: false
      add :permission_version, :integer, null: false, default: 1
      add :password_protected, :boolean, null: false, default: false
      add :max_views, :bigint, null: false
      add :view_count, :integer, null: false, default: 0
      add :expires_event_sequence, :bigint, null: false

      add :created_by,
          references(:users, type: :binary_id, on_delete: :delete_all),
          null: false

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
      "ALTER TABLE shares ADD CONSTRAINT shares_view_count_non_negative CHECK (view_count >= 0)",
      "ALTER TABLE shares DROP CONSTRAINT shares_view_count_non_negative"
    )

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_max_views_positive CHECK (max_views > 0)",
      "ALTER TABLE shares DROP CONSTRAINT shares_max_views_positive"
    )

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_expires_event_sequence_positive CHECK (expires_event_sequence > 0)",
      "ALTER TABLE shares DROP CONSTRAINT shares_expires_event_sequence_positive"
    )

    execute(
      "ALTER TABLE shares ADD CONSTRAINT shares_latest_bootstrap_event_hash_length CHECK (length(latest_bootstrap_event_hash) = 43)",
      "ALTER TABLE shares DROP CONSTRAINT shares_latest_bootstrap_event_hash_length"
    )

    execute(
      ~s|ALTER TABLE shares ADD CONSTRAINT shares_latest_bootstrap_event_hash_format CHECK (latest_bootstrap_event_hash ~ '^[A-Za-z0-9\\-_]{43}$')|,
      "ALTER TABLE shares DROP CONSTRAINT shares_latest_bootstrap_event_hash_format"
    )

    create constraint(:shares, :shares_authenticated_workspace_pin_bootstrap_hash_length,
             check: "length(authenticated_workspace_pin_bootstrap_hash) = 43"
           )

    create constraint(:shares, :shares_authenticated_workspace_pin_bootstrap_hash_format,
             check: "authenticated_workspace_pin_bootstrap_hash ~ '^[A-Za-z0-9\\-_]{43}$'"
           )

    create table(:share_keys, primary_key: false) do
      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          null: false

      add :encrypted_dek, :binary, null: false
      add :nonce, :binary, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create index(:share_keys, [:document_id])

    execute(
      "ALTER TABLE share_keys ADD CONSTRAINT share_keys_nonce_size CHECK (octet_length(nonce) = 24)",
      "ALTER TABLE share_keys DROP CONSTRAINT share_keys_nonce_size"
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

      add :hybrid_signing_public_key_material, :map, null: false
      add :signing_key_id, :text, null: false
      add :hybrid_encryption_public_key_material, :map, null: false
      add :encryption_key_id, :text, null: false
      add :revoked_at, :utc_datetime_usec
      add :last_seen_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:share_participant_devices, [:share_id, :signing_key_id])
    create unique_index(:share_participant_devices, [:share_id, :encryption_key_id])
    create index(:share_participant_devices, [:principal_id])

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

    create table(:share_participant_rrp_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :device_id,
          references(:share_participant_devices, type: :binary_id, on_delete: :delete_all),
          null: false

      add :challenge_hash, :binary, null: false
      add :session_id_hash, :string, null: false
      add :session_kind, :string, null: false
      add :subject_id, :binary_id, null: false
      add :share_participant_principal_id, :binary_id, null: false
      add :share_participant_device_id, :binary_id, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:share_participant_rrp_challenges, [:share_id, :device_id])
    create index(:share_participant_rrp_challenges, [:share_participant_principal_id])
    create index(:share_participant_rrp_challenges, [:share_participant_device_id])
    create index(:share_participant_rrp_challenges, [:session_id_hash])

    create index(
             :share_participant_rrp_challenges,
             [
               :challenge_hash,
               :session_kind,
               :subject_id,
               :share_id,
               :share_participant_principal_id,
               :share_participant_device_id,
               :session_id_hash
             ]
           )

    execute(
      "ALTER TABLE share_participant_rrp_challenges ADD CONSTRAINT share_participant_rrp_challenges_session_kind_check CHECK (session_kind = 'share_participant')",
      "ALTER TABLE share_participant_rrp_challenges DROP CONSTRAINT share_participant_rrp_challenges_session_kind_check"
    )

    create index(:share_participant_rrp_challenges, [:expires_at])

    create table(:share_link_secret_backup_wraps, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :share_id, references(:shares, type: :uuid, on_delete: :delete_all), null: false
      add :recipient_user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false

      add :recipient_device_id, references(:devices, type: :uuid, on_delete: :delete_all),
        null: false

      add :recipient_encryption_key_id, :text, null: false
      add :wrap, :map, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:share_link_secret_backup_wraps, [:recipient_user_id])

    create unique_index(:share_link_secret_backup_wraps, [:share_id, :recipient_device_id],
             name: :share_link_secret_backup_wraps_share_device_index
           )

    create table(:share_open_consumptions, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :consumer_kind, :string, null: false
      add :consumer_id, :binary_id, null: false
      add :consumed_at, :utc_datetime_usec, null: false
    end

    create unique_index(:share_open_consumptions, [:share_id, :consumer_kind, :consumer_id],
             name: :share_open_consumptions_share_consumer_index
           )

    create index(:share_open_consumptions, [:share_id])

    execute(
      "ALTER TABLE share_open_consumptions ADD CONSTRAINT share_open_consumptions_consumer_kind_check CHECK (consumer_kind IN ('share_participant_device', 'share_mount_user'))",
      "ALTER TABLE share_open_consumptions DROP CONSTRAINT share_open_consumptions_consumer_kind_check"
    )
  end

  def down do
    drop table(:share_open_consumptions)
    drop table(:share_link_secret_backup_wraps)
    drop table(:share_participant_rrp_challenges)
    drop table(:share_participant_sessions)
    drop table(:share_participant_devices)
    drop table(:share_participant_principals)
    drop table(:shared_folder_tokens)
    drop table(:shared_document_tokens)
    drop table(:share_keys)
    drop table(:shares)
  end
end
