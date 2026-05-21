defmodule RefMD.Repo.Migrations.CreateAccounts do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :email, :text, null: false
      add :name, :text, null: false
      add :encryption_setup_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:users, [:email])

    create table(:user_settings, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        primary_key: true

      add :theme, :text, null: false, default: "system"
      add :locale, :text, null: false, default: "en"
      add :editor_vim_mode, :boolean, null: false, default: false
      add :editor_font_size, :integer, null: false, default: 14

      add :updated_at, :utc_datetime_usec, null: false
    end

    create table(:user_external_accounts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :provider, :text, null: false
      add :provider_user_id, :text, null: false
      add :email, :text

      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:user_external_accounts, [:provider, :provider_user_id])
    create index(:user_external_accounts, [:user_id])

    create table(:user_shortcuts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :action, :text, null: false
      add :keys, :text, null: false

      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:user_shortcuts, [:user_id, :action])

    create table(:devices, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :name, :text, null: false
      add :device_type, :text, null: false
      add :hybrid_encryption_public_key_material, :map, null: false
      add :encryption_key_id, :text, null: false
      add :hybrid_signing_public_key_material, :map, null: false
      add :signing_key_id, :text, null: false
      add :approval_signature, :map, null: false
      add :approval_signature_surface, :text, null: false
      add :approval_proof, :map, null: false
      add :approval_delivery_commitments, :map
      add :approval_delivery_artifacts, :map
      add :key_checkpoint_sequence, :bigint, null: false
      add :key_checkpoint_hash, :text, null: false
      add :client_nonce, :binary, null: false
      add :last_seen_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
    end

    create index(:devices, [:user_id])
    create unique_index(:devices, [:encryption_key_id])
    create unique_index(:devices, [:signing_key_id])

    create table(:sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :device_id, references(:devices, type: :binary_id, on_delete: :nilify_all)
      add :token_hash, :text, null: false
      add :remember_me, :boolean, null: false
      add :is_recovery, :boolean, null: false, default: false
      add :ip_address, :text
      add :user_agent, :text
      add :expires_at, :utc_datetime_usec, null: false
      add :last_seen_at, :utc_datetime_usec, null: false
      add :last_verified_at, :utc_datetime_usec
      add :recovery_session_transcript_hash, :text
      add :recovery_capability_hash, :text
      add :pending_registration_binding_hash, :text
      add :candidate_user_checkpoint_sequence, :bigint
      add :candidate_user_checkpoint_hash, :text
      add :candidate_user_event_head_sequence, :bigint
      add :candidate_user_event_head_hash, :text
      add :recovered_identity_signing_key_id, :text
      add :target_key_checkpoint_sequence, :bigint
      add :target_key_checkpoint_hash, :text
      add :pending_registration_challenge_hash, :text
      add :pending_registration_challenge_expires_at, :utc_datetime_usec
      add :pending_registration_challenge_consumed_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:sessions, [:user_id])
    create unique_index(:sessions, [:token_hash])

    create table(:device_registrations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :name, :text, null: false
      add :device_type, :text, null: false
      add :hybrid_encryption_public_key_material, :map, null: false
      add :encryption_key_id, :text, null: false
      add :hybrid_signing_public_key_material, :map, null: false
      add :signing_key_id, :text, null: false
      add :ake_responder_prekeys, :map
      add :approval_signature, :map
      add :approval_signature_surface, :text
      add :approval_proof, :map
      add :approval_delivery_commitments, :map
      add :approval_delivery_artifacts, :map
      add :approval_key_directory, :map
      add :pending_registration_challenge_hash, :text, null: false
      add :client_nonce, :binary, null: false
      add :ip_address, :text
      add :created_at, :utc_datetime_usec, null: false
      add :expires_at, :utc_datetime_usec, null: false
    end

    create index(:device_registrations, [:user_id])
    create index(:device_registrations, [:encryption_key_id])
    create unique_index(:device_registrations, [:signing_key_id])

    create table(:initial_ake_prekeys, primary_key: false) do
      add :prekey_id, :string, primary_key: true
      add :operation_id, :string, null: false
      add :purpose, :string, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :device_registration_id,
          references(:device_registrations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :issued_at_event_sequence, :bigint, null: false
      add :expires_event_sequence, :bigint, null: false
      add :payload, :map, null: false
      add :consumed_at, :utc_datetime_usec
      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create index(:initial_ake_prekeys, [:user_id, :device_registration_id])
    create unique_index(:initial_ake_prekeys, [:purpose, :prekey_id, :operation_id])

    create table(:initial_ake_prekey_consumptions, primary_key: false) do
      add :prekey_id, :string, primary_key: true
      add :operation_id, :string, null: false
      add :purpose, :string, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :device_id, references(:devices, type: :binary_id, on_delete: :delete_all), null: false
      add :delivery_id, :string, null: false
      add :delivery_hash, :string, null: false
      timestamps(type: :utc_datetime_usec, inserted_at: :consumed_at, updated_at: false)
    end

    create index(:initial_ake_prekey_consumptions, [:user_id, :device_id])
    create unique_index(:initial_ake_prekey_consumptions, [:purpose, :prekey_id, :operation_id])
  end
end
