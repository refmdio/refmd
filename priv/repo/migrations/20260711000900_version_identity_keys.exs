defmodule RefMD.Repo.Migrations.VersionIdentityKeys do
  use Ecto.Migration

  def up do
    alter table(:user_identity_public_keys) do
      add :key_version, :integer, null: false, default: 1
      add :lifecycle_state, :text, null: false, default: "current"
      add :rotation_due_at, :utc_datetime_usec
      add :needs_rotation, :boolean, null: false, default: false
      add :superseded_at, :utc_datetime_usec
    end

    execute "ALTER TABLE user_identity_public_keys DROP CONSTRAINT user_identity_public_keys_pkey"
    execute "ALTER TABLE user_identity_public_keys ADD PRIMARY KEY (user_id, key_version)"

    create constraint(:user_identity_public_keys, :user_identity_public_keys_version_positive,
             check: "key_version > 0"
           )

    create constraint(
             :user_identity_public_keys,
             :user_identity_public_keys_lifecycle_state_check,
             check: "lifecycle_state IN ('current', 'pending', 'historical')"
           )

    create constraint(
             :user_identity_public_keys,
             :user_identity_public_keys_active_deadline_required,
             check: "lifecycle_state = 'historical' OR rotation_due_at IS NOT NULL"
           )

    create unique_index(:user_identity_public_keys, [:user_id],
             where: "lifecycle_state = 'current'",
             name: :user_identity_public_keys_one_current_index
           )

    create unique_index(:user_identity_public_keys, [:user_id],
             where: "lifecycle_state = 'pending'",
             name: :user_identity_public_keys_one_pending_index
           )

    alter table(:user_encrypted_identity_keys) do
      add :key_version, :integer, null: false, default: 1
      add :lifecycle_state, :text, null: false, default: "current"
    end

    execute "ALTER TABLE user_encrypted_identity_keys DROP CONSTRAINT user_encrypted_identity_keys_pkey"
    execute "ALTER TABLE user_encrypted_identity_keys ADD PRIMARY KEY (user_id, key_version)"

    create constraint(
             :user_encrypted_identity_keys,
             :user_encrypted_identity_keys_version_positive,
             check: "key_version > 0"
           )

    create constraint(
             :user_encrypted_identity_keys,
             :user_encrypted_identity_keys_lifecycle_state_check,
             check: "lifecycle_state IN ('current', 'pending')"
           )

    create unique_index(:user_encrypted_identity_keys, [:user_id],
             where: "lifecycle_state = 'current'",
             name: :user_encrypted_identity_keys_one_current_index
           )

    create unique_index(:user_encrypted_identity_keys, [:user_id],
             where: "lifecycle_state = 'pending'",
             name: :user_encrypted_identity_keys_one_pending_index
           )
  end

  def down do
    drop index(:user_encrypted_identity_keys, [:user_id],
           name: :user_encrypted_identity_keys_one_pending_index
         )

    drop index(:user_encrypted_identity_keys, [:user_id],
           name: :user_encrypted_identity_keys_one_current_index
         )

    execute "DELETE FROM user_encrypted_identity_keys WHERE lifecycle_state != 'current'"

    execute "ALTER TABLE user_encrypted_identity_keys DROP CONSTRAINT user_encrypted_identity_keys_pkey"

    execute "ALTER TABLE user_encrypted_identity_keys ADD PRIMARY KEY (user_id)"

    alter table(:user_encrypted_identity_keys) do
      remove :lifecycle_state
      remove :key_version
    end

    drop index(:user_identity_public_keys, [:user_id],
           name: :user_identity_public_keys_one_pending_index
         )

    drop index(:user_identity_public_keys, [:user_id],
           name: :user_identity_public_keys_one_current_index
         )

    drop constraint(
           :user_identity_public_keys,
           :user_identity_public_keys_active_deadline_required
         )

    execute "DELETE FROM user_identity_public_keys WHERE lifecycle_state != 'current'"
    execute "ALTER TABLE user_identity_public_keys DROP CONSTRAINT user_identity_public_keys_pkey"
    execute "ALTER TABLE user_identity_public_keys ADD PRIMARY KEY (user_id)"

    alter table(:user_identity_public_keys) do
      remove :superseded_at
      remove :needs_rotation
      remove :rotation_due_at
      remove :lifecycle_state
      remove :key_version
    end
  end
end
