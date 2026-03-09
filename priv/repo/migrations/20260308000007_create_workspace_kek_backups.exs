defmodule RefMD.Repo.Migrations.CreateWorkspaceKekBackups do
  use Ecto.Migration

  def change do
    create table(:workspace_kek_backups, primary_key: false) do
      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :user_id,
          references(:users, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :key_version, :integer, primary_key: true
      add :encrypted_kek, :binary, null: false
      add :nonce, :binary, null: false
      add :is_active, :boolean, null: false, default: true
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:workspace_kek_backups, [:workspace_id, :user_id],
             where: "is_active = true",
             name: :workspace_kek_backups_one_active_per_user
           )

    execute(
      "ALTER TABLE workspace_kek_backups ADD CONSTRAINT workspace_kek_backups_key_version_positive CHECK (key_version > 0)",
      "ALTER TABLE workspace_kek_backups DROP CONSTRAINT workspace_kek_backups_key_version_positive"
    )

    execute(
      "ALTER TABLE workspace_kek_backups ADD CONSTRAINT workspace_kek_backups_nonce_length CHECK (length(nonce) = 24)",
      "ALTER TABLE workspace_kek_backups DROP CONSTRAINT workspace_kek_backups_nonce_length"
    )
  end
end
