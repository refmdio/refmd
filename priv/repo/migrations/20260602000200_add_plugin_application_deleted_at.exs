defmodule RefMD.Repo.Migrations.AddPluginApplicationDeletedAt do
  use Ecto.Migration

  def up do
    alter table(:plugin_applications) do
      add :deleted_at, :utc_datetime_usec
    end

    create index(:plugin_applications, [:workspace_id, :deleted_at],
             name: :plugin_applications_workspace_deleted_at_index
           )
  end

  def down do
    drop_if_exists index(:plugin_applications, [:workspace_id, :deleted_at],
                     name: :plugin_applications_workspace_deleted_at_index
                   )

    alter table(:plugin_applications) do
      remove :deleted_at
    end
  end
end
