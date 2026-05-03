defmodule RefMD.Repo.Migrations.CreateShareMounts do
  use Ecto.Migration

  def change do
    create table(:share_mounts, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          null: false

      add :target_document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          null: false

      add :target_kind, :string, null: false

      add :user_id,
          references(:users, type: :binary_id, on_delete: :delete_all),
          null: false

      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          null: false

      add :parent_id, references(:documents, type: :binary_id, on_delete: :nilify_all)
      add :position, :integer, null: false, default: 0

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create unique_index(:share_mounts, [:share_id, :target_document_id, :user_id],
             name: :share_mounts_share_target_user_index
           )

    create index(:share_mounts, [:user_id, :workspace_id])
    create index(:share_mounts, [:workspace_id, :parent_id])
    create index(:share_mounts, [:share_id])
    create index(:share_mounts, [:target_document_id])

    create constraint(:share_mounts, :share_mounts_target_kind_check,
             check: "target_kind IN ('document', 'folder')"
           )

    create constraint(:share_mounts, :share_mounts_position_non_negative, check: "position >= 0")
  end
end
