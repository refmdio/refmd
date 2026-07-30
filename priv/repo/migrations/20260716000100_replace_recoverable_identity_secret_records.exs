defmodule RefMD.Repo.Migrations.ReplaceRecoverableIdentitySecretRecords do
  use Ecto.Migration

  def up do
    drop_if_exists index(:user_encrypted_identity_keys, [:user_id],
                     name: :user_encrypted_identity_keys_one_current_index
                   )

    drop_if_exists index(:user_encrypted_identity_keys, [:user_id],
                     name: :user_encrypted_identity_keys_one_pending_index
                   )

    execute("DELETE FROM user_encrypted_identity_keys")

    execute(
      "ALTER TABLE user_encrypted_identity_keys DROP CONSTRAINT user_encrypted_identity_keys_pkey"
    )

    alter table(:user_encrypted_identity_keys) do
      remove :key_version
      remove :lifecycle_state
      add :id, :uuid, primary_key: true, null: false
      add :identity_key_epoch, :bigint, null: false
      add :previous_record_hash, :text, null: false
      add :signing_material_aad_hash, :text, null: false
      add :encryption_material_aad_hash, :text, null: false
      add :record_hash, :text, null: false
      add :is_current, :boolean, null: false
    end

    create unique_index(:user_encrypted_identity_keys, [:user_id, :identity_key_epoch])
    create unique_index(:user_encrypted_identity_keys, [:user_id, :record_hash])

    create unique_index(:user_encrypted_identity_keys, [:user_id],
             where: "is_current = true",
             name: :user_encrypted_identity_keys_one_current_index
           )

    create constraint(:user_encrypted_identity_keys, :identity_key_epoch_positive,
             check: "identity_key_epoch > 0"
           )
  end

  def down do
    drop constraint(:user_encrypted_identity_keys, :identity_key_epoch_positive)

    drop index(:user_encrypted_identity_keys, [:user_id],
           name: :user_encrypted_identity_keys_one_current_index
         )

    drop index(:user_encrypted_identity_keys, [:user_id, :record_hash])
    drop index(:user_encrypted_identity_keys, [:user_id, :identity_key_epoch])

    execute("DELETE FROM user_encrypted_identity_keys")

    alter table(:user_encrypted_identity_keys) do
      remove :id
      remove :identity_key_epoch
      remove :previous_record_hash
      remove :signing_material_aad_hash
      remove :encryption_material_aad_hash
      remove :record_hash
      remove :is_current
      add :key_version, :integer, null: false, default: 1
      add :lifecycle_state, :text, null: false, default: "current"
    end

    execute("ALTER TABLE user_encrypted_identity_keys ADD PRIMARY KEY (user_id, key_version)")
  end
end
