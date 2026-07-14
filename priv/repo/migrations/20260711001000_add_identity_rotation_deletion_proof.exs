defmodule RefMD.Repo.Migrations.AddIdentityRotationDeletionProof do
  use Ecto.Migration

  def change do
    alter table(:user_identity_public_keys) do
      add :private_key_deletion_proof_hash, :text
    end

    create constraint(
             :user_identity_public_keys,
             :user_identity_public_keys_deletion_proof_hash_shape,
             check:
               "private_key_deletion_proof_hash IS NULL OR " <>
                 "private_key_deletion_proof_hash ~ '^[A-Za-z0-9_-]{43}$'"
           )

    create table(:user_identity_rotation_deletion_evidences, primary_key: false) do
      add :old_key_deleted_event_hash, :string, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :rotation_kind, :string, null: false
      add :scope_kind, :string, null: false
      add :scope_id, :string, null: false
      add :old_key_version, :integer, null: false
      add :deletion_manifest, :map, null: false
      add :device_key_deletion_proofs, :map, null: false
      add :wipe_required_device_ids, {:array, :binary_id}, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create constraint(:user_identity_rotation_deletion_evidences, :rotation_kind_is_identity,
             check: "rotation_kind = 'identity'"
           )

    create constraint(:user_identity_rotation_deletion_evidences, :scope_kind_is_user,
             check: "scope_kind = 'user'"
           )

    create constraint(:user_identity_rotation_deletion_evidences, :scope_id_matches_user_id,
             check: "scope_id = user_id::text"
           )
  end
end
