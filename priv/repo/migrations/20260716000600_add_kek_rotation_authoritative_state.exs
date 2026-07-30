defmodule RefMD.Repo.Migrations.AddKekRotationAuthoritativeState do
  use Ecto.Migration

  def change do
    alter table(:workspaces) do
      add :current_kek_rotation_id, :binary_id
      add :pending_kek_version, :integer
      add :kek_rotation_completed_event_hash, :string
    end

    create unique_index(:workspaces, [:current_kek_rotation_id],
             where: "current_kek_rotation_id IS NOT NULL"
           )
  end
end
