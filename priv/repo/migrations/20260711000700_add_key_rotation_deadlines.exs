defmodule RefMD.Repo.Migrations.AddKeyRotationDeadlines do
  use Ecto.Migration

  def up do
    alter table(:workspaces) do
      add :kek_rotation_due_at, :utc_datetime_usec
    end

    alter table(:documents) do
      add :dek_rotation_due_at, :utc_datetime_usec
    end

    create index(:workspaces, [:kek_rotation_due_at],
             where: "current_kek_version > 0 AND needs_kek_rotation = false"
           )

    create index(:documents, [:dek_rotation_due_at],
             where: "archived_at IS NULL AND needs_dek_rotation = false"
           )
  end

  def down do
    drop_if_exists index(:documents, [:dek_rotation_due_at])
    drop_if_exists index(:workspaces, [:kek_rotation_due_at])

    alter table(:documents) do
      remove :dek_rotation_due_at
    end

    alter table(:workspaces) do
      remove :kek_rotation_due_at
    end
  end
end
