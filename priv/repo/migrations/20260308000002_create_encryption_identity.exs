defmodule RefMD.Repo.Migrations.CreateEncryptionIdentity do
  use Ecto.Migration

  def change do
    create table(:user_identity_public_keys, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        primary_key: true

      add :hybrid_encryption_public_key_material, :map, null: false
      add :encryption_key_id, :text, null: false
      add :hybrid_signing_public_key_material, :map, null: false
      add :signing_key_id, :text, null: false
      add :pending_registration_challenge_hash, :text, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(
             :user_identity_public_keys,
             [:signing_key_id],
             name: :user_identity_public_keys_signing_key_id_index
           )

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
      add :recovery_authorization_public_material, :map, null: false
      add :recovery_authorization_key_id, :text, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create table(:user_encrypted_identity_keys, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        primary_key: true

      add :encrypted_identity_hybrid_encryption_private_key_material, :binary, null: false
      add :identity_hybrid_encryption_private_key_material_nonce, :binary, null: false
      add :encryption_key_id, :text, null: false
      add :encrypted_identity_hybrid_signing_private_key_material, :binary, null: false
      add :identity_hybrid_signing_private_key_material_nonce, :binary, null: false
      add :signing_key_id, :text, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create constraint(
             :user_encrypted_identity_keys,
             :identity_hybrid_encryption_private_key_material_nonce_size,
             check: "octet_length(identity_hybrid_encryption_private_key_material_nonce) = 24"
           )

    create constraint(
             :user_encrypted_identity_keys,
             :identity_hybrid_signing_private_key_material_nonce_size,
             check: "octet_length(identity_hybrid_signing_private_key_material_nonce) = 24"
           )

    create table(:device_encrypted_umks, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :device_id, references(:devices, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :sender_device_id, :binary_id, null: false
      add :initial_ake, :map, null: false
      add :initial_key_delivery, :map, null: false
      add :initial_kek_deliveries, :map, null: false, default: %{}
      add :device_state_delivery, :map, null: false, default: %{}
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:device_encrypted_umks, [:sender_device_id])

    create table(:key_directory_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :scope_kind, :text, null: false
      add :scope_id, :binary_id, null: false
      add :sequence, :bigint, null: false
      add :event_type, :text, null: false
      add :event_hash, :text, null: false
      add :event_body_hash, :text, null: false
      add :previous_event_hash, :text
      add :payload, :map, null: false
      add :signatures, {:array, :map}, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:key_directory_events, [:scope_kind, :scope_id, :sequence])
    create unique_index(:key_directory_events, [:scope_kind, :scope_id, :event_hash])

    create unique_index(
             :key_directory_events,
             [:scope_kind, :scope_id, :sequence, :event_hash],
             name: :key_directory_events_scope_sequence_hash_index
           )

    create constraint(:key_directory_events, :key_directory_events_scope_kind_check,
             check: "scope_kind IN ('user', 'workspace')"
           )

    create constraint(:key_directory_events, :key_directory_events_sequence_positive,
             check: "sequence > 0 AND sequence <= 9007199254740991"
           )

    create constraint(:key_directory_events, :key_directory_events_signature_non_empty,
             check: "cardinality(signatures) > 0"
           )

    create constraint(:key_directory_events, :key_directory_events_previous_hash_shape,
             check:
               "(sequence = 1 AND previous_event_hash IS NULL) OR " <>
                 "(sequence > 1 AND previous_event_hash IS NOT NULL)"
           )

    create table(:key_directory_checkpoints, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :scope_kind, :text, null: false
      add :scope_id, :binary_id, null: false
      add :sequence, :bigint, null: false
      add :checkpoint_hash, :text, null: false
      add :previous_checkpoint_hash, :text
      add :covered_event_head_sequence, :bigint, null: false
      add :covered_event_head_hash, :text, null: false
      add :suite_policy_version, :integer, null: false
      add :min_suite_rank, :integer, null: false
      add :allowed_suite_ids_hash, :text, null: false
      add :payload, :map, null: false
      add :signatures, {:array, :map}, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:key_directory_checkpoints, [:scope_kind, :scope_id, :sequence])
    create unique_index(:key_directory_checkpoints, [:scope_kind, :scope_id, :checkpoint_hash])

    create unique_index(
             :key_directory_checkpoints,
             [:scope_kind, :scope_id, :sequence, :checkpoint_hash],
             name: :key_directory_checkpoints_scope_sequence_hash_index
           )

    create constraint(:key_directory_checkpoints, :key_directory_checkpoints_scope_kind_check,
             check: "scope_kind IN ('user', 'workspace')"
           )

    create constraint(:key_directory_checkpoints, :key_directory_checkpoints_sequence_positive,
             check: "sequence > 0 AND sequence <= 9007199254740991"
           )

    create constraint(:key_directory_checkpoints, :key_directory_checkpoints_event_head_positive,
             check:
               "covered_event_head_sequence > 0 AND covered_event_head_sequence <= 9007199254740991"
           )

    create constraint(:key_directory_checkpoints, :key_directory_checkpoints_signature_non_empty,
             check: "cardinality(signatures) > 0"
           )

    create constraint(:key_directory_checkpoints, :key_directory_checkpoints_previous_hash_shape,
             check:
               "(sequence = 1 AND previous_checkpoint_hash IS NULL) OR " <>
                 "(sequence > 1 AND previous_checkpoint_hash IS NOT NULL)"
           )

    execute(
      """
      ALTER TABLE key_directory_checkpoints
      ADD CONSTRAINT key_directory_checkpoints_covered_event_fk
      FOREIGN KEY (scope_kind, scope_id, covered_event_head_sequence, covered_event_head_hash)
      REFERENCES key_directory_events(scope_kind, scope_id, sequence, event_hash)
      ON DELETE RESTRICT
      """,
      """
      ALTER TABLE key_directory_checkpoints
      DROP CONSTRAINT key_directory_checkpoints_covered_event_fk
      """
    )
  end
end
