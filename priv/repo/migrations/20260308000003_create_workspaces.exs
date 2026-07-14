defmodule RefMD.Repo.Migrations.CreateWorkspaces do
  use Ecto.Migration

  def change do
    create table(:workspaces, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :text, null: false
      add :slug, :text, null: false
      add :description, :text
      add :icon, :text
      add :encrypted_name, :bytea
      add :encrypted_name_nonce, :bytea
      add :encrypted_name_key_version, :integer
      add :encrypted_description, :bytea
      add :encrypted_description_nonce, :bytea
      add :encrypted_description_key_version, :integer
      add :encrypted_icon, :bytea
      add :encrypted_icon_nonce, :bytea
      add :encrypted_icon_key_version, :integer
      add :owner_id, references(:users, type: :binary_id), null: false
      add :share_links_enabled, :boolean, null: false, default: true
      add :public_publishing_enabled, :boolean, null: false, default: false
      add :current_kek_version, :integer, null: false, default: 0
      add :min_kek_version, :integer, null: false, default: 0
      add :needs_kek_rotation, :boolean, null: false, default: false
      add :kek_rotation_initiator_user_id, :binary_id

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:workspaces, [:slug])

    create table(:workspace_roles, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :name, :text, null: false
      add :base_role, :text, null: false
      add :is_default, :boolean, null: false, default: false
      add :catalog_version, :integer
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:workspace_roles, [:workspace_id, :id], name: :workspace_roles_composite)

    create unique_index(:workspace_roles, [:workspace_id],
             where: "is_default = true",
             name: :workspace_roles_one_default_per_workspace
           )

    create table(:workspace_members, primary_key: false) do
      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :user_id,
          references(:users, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :role_id, :binary_id, null: false
      add :permission_version, :integer, null: false, default: 1
      add :is_default, :boolean, null: false, default: false
      add :joined_at, :utc_datetime_usec, null: false
    end

    create index(:workspace_members, [:user_id])

    # Composite FK: (workspace_id, role_id) → workspace_roles(workspace_id, id)
    execute(
      """
      ALTER TABLE workspace_members
      ADD CONSTRAINT workspace_members_role_fk
      FOREIGN KEY (workspace_id, role_id)
      REFERENCES workspace_roles (workspace_id, id)
      """,
      """
      ALTER TABLE workspace_members
      DROP CONSTRAINT workspace_members_role_fk
      """
    )

    create table(:workspace_role_permissions, primary_key: false) do
      add :role_id,
          references(:workspace_roles, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :permission, :text, primary_key: true
      add :granted, :boolean, null: false
    end

    create table(:workspace_kek_rotation_deletion_evidences, primary_key: false) do
      add :old_key_deleted_event_hash, :string, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :rotation_kind, :string, null: false
      add :scope_kind, :string, null: false
      add :scope_id, :string, null: false
      add :old_key_version, :integer, null: false
      add :deletion_manifest, :map, null: false
      add :device_key_deletion_proofs, :map, null: false
      add :wipe_required_device_ids, {:array, :binary_id}, null: false, default: []

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create constraint(:workspace_kek_rotation_deletion_evidences, :rotation_kind_is_kek,
             check: "rotation_kind = 'kek'"
           )

    create constraint(:workspace_kek_rotation_deletion_evidences, :scope_kind_is_workspace,
             check: "scope_kind = 'workspace'"
           )

    create constraint(
             :workspace_kek_rotation_deletion_evidences,
             :scope_id_matches_workspace_id,
             check: "scope_id = workspace_id::text"
           )

    create index(:workspace_kek_rotation_deletion_evidences, [:workspace_id])

    create table(:workspace_device_wipe_requirements, primary_key: false) do
      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :device_id, references(:devices, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :required_kek_version, :integer, null: false, primary_key: true
      add :reason, :text, null: false, default: "kek_rotation_deletion_proof_missing"
      add :required_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:workspace_device_wipe_requirements, [:device_id])
  end
end
